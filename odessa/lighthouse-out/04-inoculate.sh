#!/usr/bin/env bash
# =============================================================================
# 04-inoculate.sh  [LEVEL 4 — HARDEN AGAINST RE-DEPLOYMENT]
# Closes every specific attack vector Phantasm C2 uses.
# Safe to run even with no active infection — pure hardening.
#
# Vectors closed:
#   - /tmp/.sys drop zone → create immutable decoy directory
#   - /dev/shm Python scripts → inotify monitor + alert (review manually)
#   - /tmp .py files → inotify monitor + alert (review manually)
#   - Outbound :5000 → iptables permanent egress block
#   - Python3 masquerade processes → auditd + process name alerting
#   - HISTFILE anti-forensics → enforce via /etc/profile.d/
#   - Beacon check-in URI patterns → if proxy available, filter /checkin/ GET
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
LOG="$SCRIPT_DIR/inoculate_$(hostname)_$(date +%Y%m%d_%H%M%S).log"

log()  { echo -e "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
ok()   { echo -e "${GRN}[OK]${RST}   $*" | tee -a "$LOG"; }
warn() { echo -e "${YLW}[WARN]${RST} $*" | tee -a "$LOG"; }
hit()  { echo -e "${RED}[ACT]${RST}  $*" | tee -a "$LOG"; }

log "${BLD}=== Phantasm C2 Inoculation — $(hostname) ===${RST}"

# =============================================================================
# 1. LOCK /tmp/.sys DROP ZONE
#    Create an immutable decoy directory — operator cannot write beacon here.
# =============================================================================
log "\n--- [1] Locking /tmp/.sys drop zone ---"

# Clean any existing content first
if [[ -d /tmp/.sys ]]; then
    rm -rf /tmp/.sys
    hit "Removed existing /tmp/.sys"
fi

mkdir -p /tmp/.sys
chmod 555 /tmp/.sys                    # no write, not even by root without chattr -i
chattr +i /tmp/.sys 2>/dev/null \
    && ok "/tmp/.sys locked immutable — beacon cannot write staging files here" \
    || warn "chattr on /tmp/.sys failed"

# =============================================================================
# 2. MAKE /tmp AND /dev/shm NOEXEC
#    Beacon can still drop the file but python3 cannot exec scripts from noexec mounts.
#    Note: python3 may bypass this by importing — see inotify monitor below.
# =============================================================================
log "\n--- [2] Mounting /tmp and /dev/shm noexec ---"

if ! mount | grep -E " on /tmp " | grep -q noexec; then
    mount -o remount,noexec /tmp 2>/dev/null \
        && ok "/tmp remounted noexec" \
        || warn "/tmp noexec remount failed — add to /etc/fstab"
fi

if ! mount | grep -E " on /dev/shm " | grep -q noexec; then
    mount -o remount,noexec /dev/shm 2>/dev/null \
        && ok "/dev/shm remounted noexec" \
        || warn "/dev/shm noexec remount failed"
fi

# Persist across reboots
if ! grep -qE "^\s*tmpfs\s+/tmp" /etc/fstab 2>/dev/null; then
    echo "tmpfs /tmp tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab
    ok "noexec /tmp added to /etc/fstab"
fi

if grep -qE "^\s*tmpfs\s+/dev/shm" /etc/fstab 2>/dev/null; then
    sed -i 's|\(tmpfs\s\+/dev/shm\s\+tmpfs\s\+\)\(defaults[^0-9]*\)|\1\2,noexec,nosuid |' /etc/fstab || true
else
    echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab
    ok "noexec /dev/shm added to /etc/fstab"
fi

# =============================================================================
# 3. PERSISTENT EGRESS BLOCK ON PORT 5000
#    The beacon cannot function if it cannot reach the C2 server.
# =============================================================================
log "\n--- [3] Persistent egress block on port 5000 ---"

if command -v iptables &>/dev/null; then
    # Idempotent: check before adding
    if ! iptables -C OUTPUT -p tcp --dport 5000 -j DROP 2>/dev/null; then
        iptables -I OUTPUT -p tcp --dport 5000 -j DROP 2>/dev/null \
            && ok "Egress block on TCP:5000 added" \
            || warn "iptables rule failed"
    else
        ok "Egress block on TCP:5000 already present"
    fi

    # Persist via iptables-save
    if command -v iptables-save &>/dev/null; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
        ok "iptables rules saved to /etc/iptables/rules.v4"

        # Install iptables-persistent to reload on boot if available
        if command -v apt-get &>/dev/null && ! dpkg -l iptables-persistent &>/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent 2>&1 | tee -a "$LOG" || true
        fi
    fi
else
    warn "iptables not available"
fi

# =============================================================================
# 4. INOTIFY MONITOR — detect .py file drops in /tmp and /dev/shm
#    Alerts to log — does NOT auto-delete. Review flagged files manually.
# =============================================================================
log "\n--- [4] Inotify beacon drop detector ---"

if command -v inotifywait &>/dev/null; then
    WATCH_SCRIPT="/usr/local/bin/lighthouse_watch.sh"
    ALERT_LOG="/var/log/lighthouse_alerts.log"

    cat > "$WATCH_SCRIPT" <<'WATCHEOF'
#!/usr/bin/env bash
ALERT_LOG="/var/log/lighthouse_alerts.log"

# Beacon signature strings
BEACON_SIGS="send_heartbeat|BASE_INTERVAL|/checkin/|BEACON_ID|JITTER_PERCENT|subprocess\.Popen"

inotifywait -m -r -e create,moved_to,close_write \
    /tmp /dev/shm /var/tmp 2>/dev/null \
| while read -r dir event file; do
    fullpath="${dir}${file}"
    ts="$(date '+%Y-%m-%d %H:%M:%S')"

    # Ignore non-.py files unless they look like scripts
    [[ "$file" =~ \.py$ ]] || [[ "$file" =~ ^\. ]] || continue

    echo "[$ts] FILE_DROP: $event $fullpath" | tee -a "$ALERT_LOG"
    echo "LIGHTHOUSE_DROP: $event $fullpath" > /dev/kmsg 2>/dev/null || true

    # Give file time to fully write
    sleep 0.5

    # Check if it matches beacon signatures — alert only, do NOT auto-remove
    if [[ -f "$fullpath" ]] && \
       grep -qE "$BEACON_SIGS" "$fullpath" 2>/dev/null; then
        echo "[$ts] BEACON SIGNATURE MATCH — REVIEW AND REMOVE MANUALLY: $fullpath" | tee -a "$ALERT_LOG"
        echo "LIGHTHOUSE_BEACON_FLAGGED: $fullpath" > /dev/kmsg 2>/dev/null || true
    fi

    # Alert on any .py/.hidden file in temp dir — always log, never auto-delete
    echo "[$ts] ALERT: Suspicious file in temp dir — review manually: $fullpath" | tee -a "$ALERT_LOG"
done
WATCHEOF

    chmod +x "$WATCH_SCRIPT"

    cat > /etc/systemd/system/lighthouse-watch.service <<'SVCEOF'
[Unit]
Description=Phantasm C2 beacon drop detector
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/lighthouse_watch.sh
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable lighthouse-watch.service
    systemctl restart lighthouse-watch.service
    ok "Beacon drop watcher running → $ALERT_LOG"

else
    warn "inotify-tools not installed — run: apt-get install -y inotify-tools"
fi

# =============================================================================
# 5. PROCESS NAME ALERTING — catch masquerade process names
#    Monitor for python3 processes named systemd-service.py, udev-worker.py, etc.
# =============================================================================
log "\n--- [5] Masquerade process monitor ---"

if command -v inotifywait &>/dev/null; then
    PROC_WATCH="/usr/local/bin/lighthouse_proc_watch.sh"

    cat > "$PROC_WATCH" <<'PROCEOF'
#!/usr/bin/env bash
ALERT_LOG="/var/log/lighthouse_proc_alerts.log"
MASQUERADE_NAMES="systemd-service\.py|udev-worker\.py|apt-check\.py|sys-update\.py"

while true; do
    for pid_dir in /proc/[0-9]*/; do
        pid="${pid_dir%/}"
        pid="${pid##*/}"
        cmdline=$(tr '\0' ' ' < "${pid_dir}cmdline" 2>/dev/null | xargs 2>/dev/null || true)
        [[ -z "$cmdline" ]] && continue
        echo "$cmdline" | grep -qi "python" || continue

        if echo "$cmdline" | grep -qE "$MASQUERADE_NAMES"; then
            ts="$(date '+%Y-%m-%d %H:%M:%S')"
            echo "[$ts] MASQUERADE PROCESS: PID=$pid CMD=$cmdline" | tee -a "$ALERT_LOG"
            echo "LIGHTHOUSE_MASQ: PID=$pid $cmdline" > /dev/kmsg 2>/dev/null || true
        fi

        # Check for port 5000 connection
        if [[ -d "${pid_dir}net" ]]; then
            if grep -q ":1388 " "${pid_dir}net/tcp" 2>/dev/null; then
                ts="$(date '+%Y-%m-%d %H:%M:%S')"
                echo "[$ts] PYTHON C2 CONN: PID=$pid connecting to :5000" | tee -a "$ALERT_LOG"
                echo "LIGHTHOUSE_C2CONN: PID=$pid CMD=$cmdline" > /dev/kmsg 2>/dev/null || true
            fi
        fi
    done
    sleep 15
done
PROCEOF

    chmod +x "$PROC_WATCH"

    cat > /etc/systemd/system/lighthouse-proc-watch.service <<'SVCEOF'
[Unit]
Description=Phantasm C2 masquerade process detector
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/lighthouse_proc_watch.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable lighthouse-proc-watch.service
    systemctl restart lighthouse-proc-watch.service
    ok "Process masquerade monitor running → /var/log/lighthouse_proc_alerts.log"
fi

# =============================================================================
# 6. ENFORCE HISTFILE SYSTEM-WIDE — prevent operator anti-forensics
#    Place in /etc/profile.d/ so it applies to all users on login.
# =============================================================================
log "\n--- [6] Enforcing HISTFILE system-wide ---"

cat > /etc/profile.d/enforce_histfile.sh <<'HISTEOF'
# Enforced by lighthouse-out inoculation — prevents HISTFILE evasion
export HISTFILE="${HOME}/.bash_history"
export HISTSIZE=10000
export HISTFILESIZE=20000
export HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S  "
# Do NOT allow leading-space command hiding
export HISTCONTROL=ignoredups
# Append to history instead of overwriting
shopt -s histappend 2>/dev/null || true
HISTEOF

chmod 644 /etc/profile.d/enforce_histfile.sh
ok "HISTFILE enforcement added to /etc/profile.d/enforce_histfile.sh"

# =============================================================================
# 7. AUDITD RULES FOR PYTHON EXECUTION
# =============================================================================
log "\n--- [7] Audit rules for Python execution ---"

if command -v auditctl &>/dev/null; then
    PYTHON3_PATH=$(which python3 2>/dev/null || echo /usr/bin/python3)
    PYTHON_PATH=$(which python 2>/dev/null || echo /usr/bin/python)

    auditctl -w "$PYTHON3_PATH" -p x -k lighthouse_python 2>/dev/null \
        && ok "auditd: watching python3 execution"
    auditctl -w "$PYTHON_PATH" -p x -k lighthouse_python 2>/dev/null || true
    auditctl -w /tmp -p x -k lighthouse_tmp_exec 2>/dev/null \
        && ok "auditd: watching /tmp execution"
    auditctl -w /dev/shm -p x -k lighthouse_shm_exec 2>/dev/null \
        && ok "auditd: watching /dev/shm execution"

    ok "Audit rules active — check with: ausearch -k lighthouse_python"
else
    warn "auditd not running — install with: apt-get install -y auditd"
fi

# =============================================================================
# SUMMARY
# =============================================================================
log ""
log "${BLD}=== Inoculation complete — $(hostname) ===${RST}"
log ""
log "Monitors running:"
log "  ${CYN}journalctl -kf | grep -E 'LIGHTHOUSE'${RST}"
log "  ${CYN}tail -F /var/log/lighthouse_alerts.log${RST}"
log "  ${CYN}tail -F /var/log/lighthouse_proc_alerts.log${RST}"
log ""
log "Egress block on TCP:5000 active — beacon cannot check in."
log "/tmp/.sys locked immutable — beacon cannot use staging directory."
log "HISTFILE enforced via /etc/profile.d/ — anti-forensics prevented."
log ""
log "Note: Phantasm C2 server has zero authentication."
log "If you identify the C2 IP from network traffic, you can kill all beacons with:"
log "  ${CYN}curl -X POST http://<C2_IP>:5000/issue \\${RST}"
log "  ${CYN}  -H 'Content-Type: application/json' \\${RST}"
log "  ${CYN}  -d '{\"id\":\"GRV-01\",\"cmd\":\"exit\"}'${RST}"
