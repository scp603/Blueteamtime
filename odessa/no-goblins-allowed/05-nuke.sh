#!/usr/bin/env bash
# =============================================================================
# 05-nuke.sh  [LEVEL 5 — SCORCHED EARTH]
# Full post-infection cleanup. Assumes the worm has already run on this host.
#
# Actions:
#   1.  Kill all worm processes (by name + by /tmp-origin detection)
#   2.  Remove all worm binary instances
#   3.  Attempt filesystem restoration from baseline (renames dirs/files back)
#   4.  Purge injected cron jobs and systemd timers
#   5.  Restore DNS (/etc/hosts, /etc/resolv.conf)
#   6.  Restore file corruption victims from package manager
#   7.  Clear proof file and any attacker artifacts
#   8.  Run full lockout + inoculate automatically
#   9.  Lock everything immutable
#
# Run as root. Keep a second session open.
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
LOG="$SCRIPT_DIR/nuke_$(hostname)_$(date +%Y%m%d_%H%M%S).log"
EVIDENCE="$SCRIPT_DIR/nuke_evidence_$(date +%Y%m%d_%H%M%S)"

log()  { echo -e "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
ok()   { echo -e "${GRN}[OK]${RST}   $*" | tee -a "$LOG"; }
warn() { echo -e "${YLW}[WARN]${RST} $*" | tee -a "$LOG"; }
hit()  { echo -e "${RED}[NUKE]${RST} $*" | tee -a "$LOG"; }

log "${BLD}=== Goblin-Wagon Scorched Earth — $(hostname) ===${RST}"
log "Evidence dir: $EVIDENCE"
mkdir -p "$EVIDENCE"

# =============================================================================
# 1. KILL ALL WORM PROCESSES — by name, by /tmp origin, by sudo -n pattern
# =============================================================================
log "\n--- [1/9] Killing worm processes ---"

# By known binary names (covers renamed copies too via cmdline)
for name in goblin-wagon wagon systemd-update dbus-helper; do
    pkill -9 -f "$name" 2>/dev/null && hit "Killed processes matching: $name" || true
done

# Walk /proc — kill anything whose exe resolves into /tmp or /var/tmp
for pid_dir in /proc/[0-9]*/; do
    pid="${pid_dir%/}"
    pid="${pid##*/}"
    exe=$(readlink "${pid_dir}exe" 2>/dev/null || true)
    [[ "$exe" =~ ^/tmp|^/var/tmp ]] || continue
    kill -9 "$pid" 2>/dev/null \
        && hit "Killed PID $pid (exe in temp dir: $exe)" || true
done

# Kill wagon goroutine workers — look for bash -c sudo -n
pkill -9 -f "sudo -n bash" 2>/dev/null && hit "Killed 'sudo -n bash' processes" || true

ok "Process kill sweep complete"

# =============================================================================
# 2. REMOVE WORM BINARIES AND STAGING AREA
# =============================================================================
log "\n--- [2/9] Removing worm binaries ---"

# Unfreeze /tmp/.cache if we locked it in 04-inoculate.sh
chattr -i /tmp/.cache 2>/dev/null || true

find /tmp /var/tmp -type f 2>/dev/null | while read -r f; do
    head -c 4 "$f" 2>/dev/null | grep -qP '^\x7fELF' || continue
    cp -p "$f" "$EVIDENCE/" 2>/dev/null || true
    rm -f "$f"
    hit "Removed ELF binary from temp: $f"
done

# Named drop paths
for path in /tmp/.cache/systemd-update /tmp/.cache/dbus-helper \
            /tmp/.cache/wagon /tmp/.cache/goblin-wagon \
            /tmp/systemd-update /tmp/dbus-helper \
            /var/tmp/systemd-update /var/tmp/dbus-helper; do
    if [[ -f "$path" ]]; then
        cp -p "$path" "$EVIDENCE/" 2>/dev/null || true
        rm -f "$path"
        hit "Removed: $path"
    fi
done

# Remove the proof file
if [[ -f /etc/redteam_was_here.txt ]]; then
    cp /etc/redteam_was_here.txt "$EVIDENCE/"
    rm -f /etc/redteam_was_here.txt
    hit "Removed /etc/redteam_was_here.txt"
fi

# =============================================================================
# 3. FILESYSTEM RESTORATION — disorder_file_sys.sh renames everything in:
#    /opt /srv /var/www /home /var/log
#
#    There is no automatic undo of random renames — we can't know what
#    "right" looked like. Strategy: reinstall packages that own files in
#    these dirs, and restore from git/backup where available.
# =============================================================================
log "\n--- [3/9] Filesystem recovery ---"

# Reinstall packages whose files live in target dirs (restores /opt, /srv, etc.)
if command -v dpkg &>/dev/null; then
    log "Checking for packages with files in scrambled dirs..."
    # Find packages that have files under the target dirs
    for target in /opt /srv /var/www; do
        pkgs=$(dpkg -S "$target" 2>/dev/null | awk -F: '{print $1}' | sort -u) || true
        for pkg in $pkgs; do
            log "  Reinstalling: $pkg"
            apt-get install --reinstall -y "$pkg" 2>&1 | tee -a "$LOG" || true
        done
    done
    ok "Package reinstall sweep done"
elif command -v rpm &>/dev/null; then
    for target in /opt /srv /var/www; do
        pkgs=$(rpm -qf "$target" 2>/dev/null | grep -v "not owned" | sort -u) || true
        for pkg in $pkgs; do
            log "  Reinstalling: $pkg"
            dnf reinstall -y "$pkg" 2>&1 | tee -a "$LOG" || true
        done
    done
    ok "Package reinstall sweep done"
fi

# Restore /var/log structure — reinstall rsyslog, systemd
if command -v apt-get &>/dev/null; then
    apt-get install --reinstall -y rsyslog logrotate 2>&1 | tee -a "$LOG" || true
elif command -v dnf &>/dev/null; then
    dnf reinstall -y rsyslog logrotate 2>&1 | tee -a "$LOG" || true
fi

# Check if a baseline exists from 04-inoculate.sh and verify
LATEST_BASELINE=$(ls -t "$SCRIPT_DIR"/fs_baseline_*.sha256 2>/dev/null | head -1) || true
if [[ -n "$LATEST_BASELINE" ]]; then
    log "Checking against baseline: $LATEST_BASELINE"
    sha256sum -c "$LATEST_BASELINE" 2>&1 | grep FAILED | tee -a "$LOG" \
        | while read -r line; do warn "Corrupted/missing: $line"; done || true
else
    warn "No baseline file found — run 04-inoculate.sh on a clean host first"
fi

# =============================================================================
# 4. PURGE INJECTED CRON JOBS AND SYSTEMD TIMERS
# =============================================================================
log "\n--- [4/9] Purging injected cron and timers ---"

# Unfreeze cron dirs first
chattr -i /etc/cron.d 2>/dev/null || true
find /etc/cron.d/ /var/spool/cron/crontabs/ -type f \
    -exec chattr -i {} \; 2>/dev/null || true

# Look for cron entries added after the baseline date or referencing /tmp
for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
    [[ -f "$f" ]] || continue
    if grep -qE '/tmp/|/var/tmp/|[a-zA-Z0-9]{12}' "$f" 2>/dev/null; then
        cp "$f" "$EVIDENCE/"
        # Remove suspicious lines
        sed -i -E '/\/tmp\/|\/var\/tmp\/|[a-zA-Z0-9]{12}/d' "$f"
        hit "Cleaned suspicious cron entries from $f"
    fi
done

# Disable non-distro systemd timers
systemctl list-units --type=timer --no-legend 2>/dev/null | awk '{print $1}' | while read -r unit; do
    unit_file=$(systemctl show "$unit" --property=FragmentPath 2>/dev/null | cut -d= -f2)
    [[ -z "$unit_file" ]] && continue

    is_owned=0
    dpkg -S "$unit_file" &>/dev/null 2>&1 && is_owned=1 || true
    rpm -qf "$unit_file" &>/dev/null 2>&1 && is_owned=1 || true

    if [[ $is_owned -eq 0 && "$unit_file" != "" ]]; then
        systemctl stop "$unit" 2>/dev/null && hit "Stopped non-distro timer: $unit" || true
        systemctl disable "$unit" 2>/dev/null || true
        cp "$unit_file" "$EVIDENCE/" 2>/dev/null || true
        rm -f "$unit_file"
        hit "Removed: $unit_file"
    fi
done

systemctl daemon-reload

# =============================================================================
# 5. RESTORE DNS
# =============================================================================
log "\n--- [5/9] Restoring DNS files ---"

chattr -i /etc/hosts /etc/resolv.conf 2>/dev/null || true

if [[ -f /etc/hosts.goblin_backup ]]; then
    cp /etc/hosts.goblin_backup /etc/hosts
    ok "/etc/hosts restored from backup"
else
    warn "No /etc/hosts backup — verify hosts file manually"
    cat /etc/hosts | tee -a "$LOG"
fi

if [[ -f /etc/resolv.conf.goblin_backup ]]; then
    cp /etc/resolv.conf.goblin_backup /etc/resolv.conf
    ok "/etc/resolv.conf restored from backup"
else
    warn "No /etc/resolv.conf backup — verify resolv.conf manually"
fi

# Re-lock
chattr +i /etc/hosts /etc/resolv.conf 2>/dev/null || true
ok "DNS files re-locked immutable"

# =============================================================================
# 6. ROTATE CREDENTIALS AND HARDEN (call 03 + 04 non-interactively)
# =============================================================================
log "\n--- [6/9] Running lockout and inoculation ---"

if [[ -f "$SCRIPT_DIR/03-lockout.sh" ]]; then
    bash "$SCRIPT_DIR/03-lockout.sh" 2>&1 | tee -a "$LOG"
    ok "03-lockout.sh completed"
else
    warn "03-lockout.sh not found — run it manually"
fi

if [[ -f "$SCRIPT_DIR/04-inoculate.sh" ]]; then
    bash "$SCRIPT_DIR/04-inoculate.sh" 2>&1 | tee -a "$LOG"
    ok "04-inoculate.sh completed"
else
    warn "04-inoculate.sh not found — run it manually"
fi

# =============================================================================
# 7. RESTART CORE SERVICES — ensure scrambling/corruption didn't break them
# =============================================================================
log "\n--- [7/9] Restarting core services ---"

for svc in rsyslog cron ssh sshd auditd; do
    systemctl restart "$svc" 2>/dev/null && ok "Restarted: $svc" || true
done

# =============================================================================
# 8. VERIFY CONNECTIVITY
# =============================================================================
log "\n--- [8/9] Post-nuke connectivity check ---"

if systemctl is-active ssh &>/dev/null || systemctl is-active sshd &>/dev/null; then
    ok "SSH service is running — verify login from a second terminal NOW"
else
    warn "SSH is NOT running — fix before closing this session"
fi

# =============================================================================
# 9. FINAL LOCK
# =============================================================================
log "\n--- [9/9] Final immutable lock ---"

for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow \
         /etc/sudoers /etc/ssh/sshd_config \
         /etc/hosts /etc/resolv.conf; do
    [[ -f "$f" ]] || continue
    chattr +i "$f" 2>/dev/null && ok "chattr +i $f" || warn "chattr failed: $f"
done

# =============================================================================
# FINAL REPORT
# =============================================================================
log ""
log "${BLD}=== Nuke complete — $(hostname) ===${RST}"
log "Evidence: $EVIDENCE"
log ""
log "Verify auth from a second terminal before closing this session:"
log "  ${CYN}ssh -o ConnectTimeout=5 $(hostname -I | awk '{print $1}') 'echo auth ok'${RST}"
log ""
log "Monitor for reinfection:"
log "  ${CYN}journalctl -kf | grep -E 'GOBLIN'${RST}"
log "  ${CYN}tail -F /var/log/goblin_fs_alerts.log /var/log/goblin_etc_alerts.log${RST}"
log ""
log "Worm cannot spread if hardcoded creds are rotated on all hosts."
log "Run 03-lockout.sh on every host in 10.10.10.1-199 to stop the spread."
