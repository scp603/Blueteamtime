#!/usr/bin/env bash
# =============================================================================
# 02-expose.sh  [LEVEL 2 — TURN THEIR STEALTH TOOL INTO A SPOTLIGHT]
# Enables PAM_DEBUG=1 globally so pam_error_mod logs every bypass attempt,
# every hardcoded-credential use, and every auth event to its own log.
# The red team thinks their backdoor is quiet. Now it isn't.
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
LOG="$SCRIPT_DIR/expose_$(hostname)_$(date +%Y%m%d_%H%M%S).log"

log()  { echo -e "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
hit()  { echo -e "${RED}[HIT]${RST} $*" | tee -a "$LOG"; }
ok()   { echo -e "${GRN}[OK]${RST}  $*" | tee -a "$LOG"; }

log "${BLD}=== Exposing pam_error_mod debug logging ===${RST}"

# =============================================================================
# 1. Inject PAM_DEBUG=1 into the module's argument list in every PAM config
#    that loads it — module reads PAM_DEBUG from env, so also set it globally
# =============================================================================
log "--- Setting PAM_DEBUG=1 in /etc/environment ---"

if grep -q "^PAM_DEBUG=" /etc/environment 2>/dev/null; then
    sed -i 's/^PAM_DEBUG=.*/PAM_DEBUG=1/' /etc/environment
else
    echo "PAM_DEBUG=1" >> /etc/environment
fi
ok "PAM_DEBUG=1 written to /etc/environment (picked up by PAM sessions)"

# =============================================================================
# 2. Set up inotifywait to tail the backdoor log file in real time.
#    Any time the module writes to its log, we capture it.
# =============================================================================
WATCH_SCRIPT="/usr/local/bin/pam_backdoor_watch.sh"
ALERT_LOG="/var/log/pam_backdoor_alerts.log"

cat > "$WATCH_SCRIPT" <<'WATCHEOF'
#!/usr/bin/env bash
# Real-time monitor for pam_error_mod log activity
LOG_FILE="/etc/logcheck/pam_auth.log"
ALERT_LOG="/var/log/pam_backdoor_alerts.log"

mkdir -p /etc/logcheck
touch "$LOG_FILE"

tail -F "$LOG_FILE" 2>/dev/null | while IFS= read -r line; do
    ts="$(date '+%Y-%m-%d %H:%M:%S')"

    # Alert on bypass or hardcoded-cred events
    if echo "$line" | grep -qE "bypass triggered|Hardcoded password|SETAUTH|PAM_SETAUTH"; then
        echo "[$ts] BACKDOOR USE DETECTED: $line" | tee -a "$ALERT_LOG"
        # Write to kernel log too (shows in dmesg / journalctl -k)
        echo "PAM_BACKDOOR: $line" > /dev/kmsg 2>/dev/null || true
    else
        echo "[$ts] $line" >> "$ALERT_LOG"
    fi
done
WATCHEOF

chmod +x "$WATCH_SCRIPT"
ok "Watch script written to $WATCH_SCRIPT"

# =============================================================================
# 3. Install watch script as a systemd one-shot service so it survives reboots
# =============================================================================
cat > /etc/systemd/system/pam-backdoor-watch.service <<'SVCEOF'
[Unit]
Description=PAM backdoor activity monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/pam_backdoor_watch.sh
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable pam-backdoor-watch.service
systemctl restart pam-backdoor-watch.service
ok "pam-backdoor-watch.service running — alerts → $ALERT_LOG"

# =============================================================================
# 4. One-liner to watch for bypass attempts in real time (print to terminal)
# =============================================================================
log ""
log "${BLD}=== Real-time monitoring commands ===${RST}"
log "  Watch all module activity:"
log "  ${CYN}tail -F /etc/logcheck/pam_auth.log${RST}"
log ""
log "  Watch only backdoor events (bypass / hardcoded creds):"
log "  ${CYN}tail -F /var/log/pam_backdoor_alerts.log | grep 'DETECTED'${RST}"
log ""
log "  Or via journalctl (kernel log alerts):"
log "  ${CYN}journalctl -kf | grep PAM_BACKDOOR${RST}"
log ""
log "When you see 'bypass triggered' or 'Hardcoded password' — that's the red team"
log "using the backdoor. Their session PID will be in the TRACE lines above it."
log "Cross-reference with: ss -tnp sport = :22 or the ssh-kill.sh script"
