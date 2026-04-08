#!/usr/bin/env bash
# =============================================================================
# 05-nuke.sh  [LEVEL 5 — SCORCHED EARTH]
# Full post-infection cleanup for Phantasm C2 (CDT-RedTeam-HTTPBeaconTool).
#
# Actions:
#   1.  Attempt remote beacon recall via zero-auth C2 API (cleanest kill)
#   2.  Kill all beacon processes by every method available
#   3.  Remove all beacon files and staging directories
#   4.  Restore bash history for all users
#   5.  Audit and clean all cron jobs (possible persistence vector)
#   6.  Permanent egress block on :5000 (and common C2 ports)
#   7.  Run lockout + inoculate
#   8.  Install persistent monitoring
#   9.  Lock critical files immutable
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

log "${BLD}=== Phantasm C2 Scorched Earth — $(hostname) ===${RST}"
log "Evidence dir: $EVIDENCE"
mkdir -p "$EVIDENCE"

# =============================================================================
# 1. ATTEMPT REMOTE BEACON RECALL FIRST (cleanest — beacon exits gracefully)
#    Phantasm C2 server has ZERO authentication.
#    If we can reach the C2 IP, we can issue exit to all known beacon IDs.
# =============================================================================
log "\n--- [1/9] Remote beacon recall via C2 API ---"

declare -A C2_SERVERS=()
BEACON_IDS=("GRV-01" "SRC-01")

# Extract C2 IPs from current and recent connections
while read -r sl local_addr rem_addr st rest; do
    [[ "$sl" == "sl" ]] && continue
    [[ "$st" == "01" || "$st" == "02" || "$st" == "06" || "$st" == "08" ]] || continue

    rem_ip_hex="${rem_addr%:*}"
    rem_port_hex="${rem_addr##*:}"
    rem_port=$(printf '%d' "0x$rem_port_hex" 2>/dev/null || true)
    [[ "$rem_port" -eq 5000 ]] || continue

    rem_ip=$(printf '%d.%d.%d.%d' \
        "0x${rem_ip_hex:6:2}" "0x${rem_ip_hex:4:2}" \
        "0x${rem_ip_hex:2:2}" "0x${rem_ip_hex:0:2}")
    C2_SERVERS["$rem_ip"]=1
done < /proc/net/tcp 2>/dev/null || true

if [[ ${#C2_SERVERS[@]} -gt 0 ]] && command -v curl &>/dev/null; then
    for c2_ip in "${!C2_SERVERS[@]}"; do
        log "  C2 server identified: $c2_ip — attempting remote recall"
        for beacon_id in "${BEACON_IDS[@]}"; do
            result=$(curl -s -m 5 -X POST "http://$c2_ip:5000/issue" \
                -H "Content-Type: application/json" \
                -d "{\"id\":\"$beacon_id\",\"cmd\":\"exit\"}" 2>/dev/null || echo "no response")
            hit "Recall sent: $beacon_id → $c2_ip:5000 (response: $result)"
        done
    done
    log "  Waiting 10s for beacons to check in and process exit command..."
    sleep 10
else
    warn "No C2 server identified from network state — skipping remote recall"
    warn "If you identify the C2 IP later, recall with:"
    log "  ${CYN}curl -X POST http://<C2_IP>:5000/issue -H 'Content-Type: application/json' -d '{\"id\":\"GRV-01\",\"cmd\":\"exit\"}'${RST}"
fi

# =============================================================================
# 2. KILL ALL BEACON PROCESSES
# =============================================================================
log "\n--- [2/9] Killing beacon processes ---"

# By masquerade name
for name in "systemd-service.py" "udev-worker.py" "apt-check.py" \
            "sys-update.py" ".sys-update" "beacon.py" "phantasm"; do
    pkill -9 -f "$name" 2>/dev/null && hit "Killed: $name" || true
done

# All Python processes with :5000 socket
for pid_dir in /proc/[0-9]*/; do
    pid="${pid_dir%/}"
    pid="${pid##*/}"
    cmdline=$(tr '\0' ' ' < "${pid_dir}cmdline" 2>/dev/null | xargs 2>/dev/null || true)
    echo "$cmdline" | grep -qi "python" || continue

    has_c2=0
    [[ -d "${pid_dir}net" ]] && grep -q ":1388 " "${pid_dir}net/tcp" 2>/dev/null && has_c2=1

    [[ $has_c2 -eq 0 ]] && continue
    kill -9 "$pid" 2>/dev/null && hit "Killed Python PID $pid (active :5000): $cmdline" || true
done

ok "Beacon kill sweep complete"

# =============================================================================
# 3. COLLECT EVIDENCE AND REMOVE ALL BEACON FILES
# =============================================================================
log "\n--- [3/9] Collecting evidence and removing files ---"

for scandir in /tmp /dev/shm /var/tmp /tmp/.sys; do
    [[ -d "$scandir" ]] || continue
    find "$scandir" -name "*.py" -o -name ".*" -type f 2>/dev/null | while read -r f; do
        [[ -f "$f" ]] || continue
        if grep -qE "send_heartbeat|BASE_INTERVAL|/checkin/|BEACON_ID" "$f" 2>/dev/null; then
            cp -p "$f" "$EVIDENCE/" 2>/dev/null || true
            sha256sum "$f" | tee -a "$LOG"
            rm -f "$f"
            hit "Removed beacon file: $f"
        fi
    done
done

# Remove staging directory
if [[ -d /tmp/.sys ]]; then
    cp -rp /tmp/.sys "$EVIDENCE/tmp_sys/" 2>/dev/null || true
    rm -rf /tmp/.sys
    hit "Removed /tmp/.sys"
fi

# Wipe /dev/shm .py files regardless of content (nothing legitimate runs from here)
find /dev/shm -name "*.py" -type f 2>/dev/null | while read -r f; do
    cp -p "$f" "$EVIDENCE/" 2>/dev/null || true
    rm -f "$f"
    hit "Removed .py file from /dev/shm: $f"
done

ok "File cleanup complete"

# =============================================================================
# 4. RESTORE BASH HISTORY FOR ALL USERS
#    Operator anti-forensics: unset HISTFILE; history -c && history -w
# =============================================================================
log "\n--- [4/9] Restoring bash history ---"

for homedir in /root /home/*/; do
    homedir="${homedir%/}"
    [[ -d "$homedir" ]] || continue

    for rc in "$homedir/.bashrc" "$homedir/.bash_profile" "$homedir/.profile"; do
        [[ -f "$rc" ]] || continue
        if grep -qE "unset HISTFILE|HISTFILE=/dev/null" "$rc" 2>/dev/null; then
            cp "$rc" "$EVIDENCE/$(basename $homedir)_$(basename $rc).bak"
            sed -i -E '/unset HISTFILE|HISTFILE=\/dev\/null/d' "$rc"
            hit "Removed HISTFILE evasion from $rc"
        fi
        if grep -q "HISTCONTROL=ignorespace" "$rc" 2>/dev/null; then
            sed -i 's/HISTCONTROL=ignorespace/HISTCONTROL=ignoredups/' "$rc"
            hit "Fixed HISTCONTROL in $rc"
        fi
    done
done

ok "Bash history restoration complete"

# =============================================================================
# 5. AUDIT AND CLEAN CRON JOBS
#    No automated cron is created by Phantasm, but operators may have added one.
# =============================================================================
log "\n--- [5/9] Auditing cron jobs ---"

for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
    [[ -f "$f" ]] || continue
    # Look for python, /tmp, /dev/shm in cron jobs
    if grep -qE "python|/tmp/|/dev/shm|\.py" "$f" 2>/dev/null; then
        hit "Suspicious cron entry in $f:"
        grep -E "python|/tmp/|/dev/shm|\.py" "$f" | tee -a "$LOG"
        cp "$f" "$EVIDENCE/$(basename $f).cron.bak"
        warn "  Review manually — these lines were NOT auto-removed"
    fi
done

# Root crontab
if crontab -l 2>/dev/null | grep -qE "python|/tmp/|/dev/shm|\.py"; then
    hit "Suspicious entries in root crontab:"
    crontab -l 2>/dev/null | grep -E "python|/tmp/|/dev/shm|\.py" | tee -a "$LOG"
    crontab -l 2>/dev/null | tee "$EVIDENCE/root_crontab.bak" > /dev/null
    warn "  Review manually — entries NOT auto-removed"
fi

ok "Cron audit complete"

# =============================================================================
# 6. BLOCK ALL COMMON C2 EGRESS PORTS
# =============================================================================
log "\n--- [6/9] Applying egress firewall rules ---"

if command -v iptables &>/dev/null; then
    # 8080/8443 excluded — may be scored Apache service ports
    for port in 5000 4444 9001 1337; do
        if ! iptables -C OUTPUT -p tcp --dport $port -j DROP 2>/dev/null; then
            iptables -I OUTPUT -p tcp --dport $port -j DROP 2>/dev/null \
                && hit "Blocked outbound TCP:$port" || true
        else
            ok "TCP:$port egress already blocked"
        fi
    done

    if command -v iptables-save &>/dev/null; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
        ok "Firewall rules persisted to /etc/iptables/rules.v4"
    fi
else
    warn "iptables not available"
fi

# =============================================================================
# 7. RUN LOCKOUT AND INOCULATE
# =============================================================================
log "\n--- [7/9] Running lockout and inoculation ---"

if [[ -f "$SCRIPT_DIR/03-lockout.sh" ]]; then
    bash "$SCRIPT_DIR/03-lockout.sh" 2>&1 | tee -a "$LOG"
    ok "03-lockout.sh completed"
else
    warn "03-lockout.sh not found — run manually"
fi

if [[ -f "$SCRIPT_DIR/04-inoculate.sh" ]]; then
    bash "$SCRIPT_DIR/04-inoculate.sh" 2>&1 | tee -a "$LOG"
    ok "04-inoculate.sh completed"
else
    warn "04-inoculate.sh not found — run manually"
fi

# =============================================================================
# 8. VERIFY SSH IS STILL UP
# =============================================================================
log "\n--- [8/9] Verifying SSH connectivity ---"

if systemctl is-active ssh &>/dev/null || systemctl is-active sshd &>/dev/null; then
    ok "SSH service is running — verify login from a second terminal NOW"
else
    warn "SSH is NOT running — fix before closing this session"
fi

# =============================================================================
# 9. FINAL LOCK
# =============================================================================
log "\n--- [9/9] Final immutable lock on critical files ---"

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
log "Verify auth from a second terminal:"
log "  ${CYN}ssh -o ConnectTimeout=5 $(hostname -I | awk '{print $1}') 'echo auth ok'${RST}"
log ""
log "Monitor for re-deployment:"
log "  ${CYN}journalctl -kf | grep -E 'LIGHTHOUSE'${RST}"
log "  ${CYN}tail -F /var/log/lighthouse_alerts.log${RST}"
log "  ${CYN}tail -F /var/log/lighthouse_proc_alerts.log${RST}"
log ""
log "Key defensive fact: Phantasm C2 has zero authentication on its Flask API."
log "If the red team re-deploys beacons, catch the C2 IP from:"
log "  ${CYN}watch -n5 \"grep ':1388' /proc/net/tcp\"${RST}"
log "Then recall all beacons with:"
log "  ${CYN}for id in GRV-01 SRC-01; do${RST}"
log "  ${CYN}  curl -X POST http://<C2_IP>:5000/issue \\${RST}"
log "  ${CYN}    -H 'Content-Type: application/json' \\${RST}"
log "  ${CYN}    -d \"{\\\"id\\\":\\\"\\$id\\\",\\\"cmd\\\":\\\"exit\\\"}\"${RST}"
log "  ${CYN}done${RST}"
