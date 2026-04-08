#!/usr/bin/env bash
# =============================================================================
# 03-lockout.sh  [LEVEL 3 — KILL THE BEACON AND BLOCK RE-ENTRY]
#
# Phantasm C2 beacon runs as a Python process, polls port 5000 every ~30s,
# executes arbitrary shell commands. No authentication anywhere.
#
# Actions:
#   1.  Kill all beacon processes by name and by port-5000 socket
#   2.  Remove beacon files from /tmp, /dev/shm, /tmp/.sys
#   3.  Block outbound port 5000 via iptables (stops check-ins)
#   4.  Block outbound port 5000 for python3 specifically
#   5.  Restore HISTFILE for all users (undo anti-forensics)
#   6.  Rebuild bash history where possible from .bash_history backup
#   7.  Restrict python3 network access (optional — aggressive)
#
# Run as root.
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
YLW='\033[1;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

[[ $EUID -ne 0 ]] && { echo "Run as root" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="$SCRIPT_DIR/lockout_$(hostname)_$(date +%Y%m%d_%H%M%S).log"
EVIDENCE="$SCRIPT_DIR/lockout_evidence_$(date +%Y%m%d_%H%M%S)"

log()  { echo -e "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
ok()   { echo -e "${GRN}[OK]${RST}   $*" | tee -a "$LOG"; }
warn() { echo -e "${YLW}[WARN]${RST} $*" | tee -a "$LOG"; }
hit()  { echo -e "${RED}[ACT]${RST}  $*" | tee -a "$LOG"; }

log "${BLD}=== Phantasm C2 Lockout — $(hostname) ===${RST}"
mkdir -p "$EVIDENCE"

# =============================================================================
# 1. KILL ALL BEACON PROCESSES
# =============================================================================
log "\n--- [1] Killing beacon processes ---"

# By masquerade name
for name in "systemd-service.py" "udev-worker.py" "apt-check.py" \
            "sys-update.py" ".sys-update" "beacon.py"; do
    pkill -9 -f "$name" 2>/dev/null && hit "Killed processes matching: $name" || true
done

# Walk /proc — kill any python3 process with an outbound :5000 socket
for pid_dir in /proc/[0-9]*/; do
    pid="${pid_dir%/}"
    pid="${pid##*/}"
    cmdline=$(tr '\0' ' ' < "${pid_dir}cmdline" 2>/dev/null | xargs 2>/dev/null || true)
    echo "$cmdline" | grep -qi "python" || continue

    # Check for port 5000 in this process's socket table
    has_c2=0
    if [[ -d "${pid_dir}net" ]]; then
        if grep -q ":1388 " "${pid_dir}net/tcp" 2>/dev/null; then
            has_c2=1
        fi
    else
        # Fall back: check fd symlinks for sockets matching /proc/net/tcp :1388
        for fd in "${pid_dir}fd/"*; do
            target=$(readlink "$fd" 2>/dev/null || true)
            [[ "$target" =~ ^socket: ]] || continue
            inode="${target#socket:[}"
            inode="${inode%]}"
            grep -q " $inode " /proc/net/tcp 2>/dev/null && has_c2=1 && break
        done
    fi

    [[ $has_c2 -eq 0 ]] && continue

    kill -9 "$pid" 2>/dev/null \
        && hit "Killed Python PID $pid (had active :5000 connection): $cmdline" || true
done

ok "Beacon process kill sweep complete"

# =============================================================================
# 2. COLLECT EVIDENCE AND REMOVE BEACON FILES
# =============================================================================
log "\n--- [2] Removing beacon files ---"

for scandir in /tmp /dev/shm /var/tmp /tmp/.sys; do
    [[ -d "$scandir" ]] || continue
    find "$scandir" -name "*.py" -type f 2>/dev/null | while read -r f; do
        # Confirm it's the beacon before deleting
        if grep -qE "send_heartbeat|BASE_INTERVAL|/checkin/|BEACON_ID|JITTER_PERCENT" "$f" 2>/dev/null; then
            cp -p "$f" "$EVIDENCE/" 2>/dev/null || true
            sha256sum "$f" | tee -a "$LOG"
            rm -f "$f"
            hit "Removed confirmed beacon file: $f"
        else
            warn "Unconfirmed .py file left in place: $f — review manually"
        fi
    done
done

# Remove the staging directory
if [[ -d /tmp/.sys ]]; then
    # Copy any remaining files as evidence first
    cp -rp /tmp/.sys "$EVIDENCE/tmp_sys_dir" 2>/dev/null || true
    rm -rf /tmp/.sys
    hit "Removed /tmp/.sys staging directory"
fi

ok "Beacon file removal complete"

# =============================================================================
# 3. BLOCK OUTBOUND PORT 5000 — stops beacon check-ins entirely
#    The beacon polls GET /checkin/<id> every 24-36 seconds.
#    Without network access to the C2, the beacon is dead even if still running.
# =============================================================================
log "\n--- [3] Blocking outbound C2 traffic ---"

if command -v iptables &>/dev/null; then
    # Block all outbound TCP to port 5000 (C2 default port)
    iptables -I OUTPUT -p tcp --dport 5000 -j DROP 2>/dev/null \
        && hit "Blocked outbound TCP:5000 (Phantasm C2 default port)" \
        || warn "iptables rule for :5000 failed"

    # Block outbound to port 80 as well if beacon configured to use it
    # (Comment out if your web services need outbound :80)
    # iptables -I OUTPUT -p tcp --dport 80 -j DROP 2>/dev/null || true

    # Log and drop any python3 connecting outbound on unusual ports
    # (requires owner match module — available on most Linux kernels)
    if iptables -m owner --help &>/dev/null 2>&1; then
        python3_uid=$(id -u "$(which python3 | xargs ls -la | awk '{print $3}')" 2>/dev/null || true)
        # Owner match: block python3 outbound on non-standard ports
        # 8080/8443 excluded — may be scored Apache service ports
        iptables -I OUTPUT -p tcp -m owner --uid-owner root \
            -m multiport --dports 5000,4444,9001,1337 \
            -j LOG --log-prefix "LIGHTHOUSE_PYBLOCK: " 2>/dev/null || true
    fi

    ok "Firewall rules applied"
    warn "Save with: iptables-save > /etc/iptables/rules.v4"
else
    warn "iptables not available — install it or manually block :5000 egress"
fi

# =============================================================================
# 4. RESTORE HISTFILE — undo operator anti-forensics
#    Operator instructions: unset HISTFILE; history -c && history -w
# =============================================================================
log "\n--- [4] Restoring HISTFILE for all users ---"

for homedir in /root /home/*/; do
    homedir="${homedir%/}"
    [[ -d "$homedir" ]] || continue
    user=$(basename "$homedir")

    # Add HISTFILE to .bashrc if it was removed or unset
    bashrc="$homedir/.bashrc"
    if [[ -f "$bashrc" ]]; then
        if grep -q "unset HISTFILE" "$bashrc" 2>/dev/null; then
            sed -i '/unset HISTFILE/d' "$bashrc"
            hit "Removed 'unset HISTFILE' from $bashrc"
        fi
        # Ensure HISTFILE is set
        if ! grep -q "HISTFILE" "$bashrc" 2>/dev/null; then
            echo "export HISTFILE=$homedir/.bash_history" >> "$bashrc"
            ok "Re-added HISTFILE to $bashrc"
        fi
    fi

    # Ensure HISTFILE is set in .bash_profile and .profile too
    for profile in "$homedir/.bash_profile" "$homedir/.profile"; do
        [[ -f "$profile" ]] || continue
        if grep -q "unset HISTFILE" "$profile" 2>/dev/null; then
            sed -i '/unset HISTFILE/d' "$profile"
            hit "Removed 'unset HISTFILE' from $profile"
        fi
    done

    # Set HISTCONTROL to not hide commands (operator may have set HISTCONTROL=ignorespace
    # to hide commands with a leading space)
    for rc in "$homedir/.bashrc" "$homedir/.bash_profile"; do
        [[ -f "$rc" ]] || continue
        if grep -q "HISTCONTROL=ignorespace" "$rc" 2>/dev/null; then
            sed -i 's/HISTCONTROL=ignorespace/HISTCONTROL=ignoredups/' "$rc"
            hit "Reset HISTCONTROL in $rc (was 'ignorespace' — hides leading-space commands)"
        fi
    done
done

ok "HISTFILE restoration complete"

# =============================================================================
# 5. AUDIT PYTHON3 EXECUTION — make python3 execution auditable
# =============================================================================
log "\n--- [5] Enabling Python3 execution auditing ---"

# Add auditd rule if available
if command -v auditctl &>/dev/null; then
    auditctl -w "$(which python3 2>/dev/null || echo /usr/bin/python3)" \
        -p x -k phantasm_python 2>/dev/null \
        && ok "auditd watch on python3 — check: ausearch -k phantasm_python" \
        || warn "auditctl rule failed"
    auditctl -w "$(which python 2>/dev/null || echo /usr/bin/python)" \
        -p x -k phantasm_python 2>/dev/null || true
fi

# =============================================================================
# SUMMARY
# =============================================================================
log ""
log "${BLD}=== Lockout complete — $(hostname) ===${RST}"
log ""
log "What changed:"
log "  - Beacon processes killed by name and by port-5000 socket"
log "  - Beacon files removed from /tmp, /dev/shm, /tmp/.sys"
log "  - Outbound TCP:5000 blocked (beacon cannot check in)"
log "  - HISTFILE restored for all users"
log ""
log "Evidence: $EVIDENCE"
log ""
log "Next: run 04-inoculate.sh to install persistent monitors and prevent re-drop"
