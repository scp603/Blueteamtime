#!/usr/bin/env bash
# =============================================================================
# 04-inoculate.sh  [LEVEL 4 — HARDEN AGAINST REINFECTION]
# Closes every specific attack vector Party Rocket uses.
# Safe to run even if no active infection is found — pure hardening.
#
# Vectors closed:
#   - PAM pam_exec.so hook re-injection → lock /etc/pam.d immutable
#   - Beacon binary re-drop → lock /usr/local/bin/ssh-auth-check path
#   - Cron self-healing (System-Svc-Monitor) → lock cron dirs immutable
#   - Bashrc PROMPT_COMMAND hijack → snapshot bashrc files + inotify watch
#   - SSH PasswordAuthentication re-enable → lock sshd_config immutable
#   - Credential log re-creation → inotify canary on /var/lib/systemd/
#   - Ansible re-deployment → host_key_checking and sshpass removal
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

log "${BLD}=== Party Rocket Inoculation — $(hostname) ===${RST}"

# =============================================================================
# 1. LOCK PAM CONFIGURATION IMMUTABLE
#    Party Rocket's self-healing cron re-inserts the hook into /etc/pam.d/common-auth.
#    Making PAM configs immutable prevents any re-injection.
# =============================================================================
log "\n--- [1] Locking PAM configuration ---"

# First ensure the hook is actually clean before locking
if grep -q "ssh-auth-check" /etc/pam.d/common-auth 2>/dev/null; then
    warn "PAM hook still present! Run 02-evict.sh first before inoculating"
    sed -i '/ssh-auth-check/d' /etc/pam.d/common-auth
    hit "Emergency: removed PAM hook from /etc/pam.d/common-auth"
fi

# Remove any pam_exec hooks pointing at /usr/local/bin scripts
for f in /etc/pam.d/*; do
    [[ -f "$f" ]] || continue
    if grep -qE "pam_exec\.so.*expose_authtok.*/usr/local/bin/" "$f" 2>/dev/null; then
        sed -i -E '/pam_exec\.so.*expose_authtok.*\/usr\/local\/bin\//d' "$f"
        hit "Cleaned pam_exec hook from $f"
    fi
    chattr +i "$f" 2>/dev/null && ok "Locked: $f" || warn "chattr failed: $f"
done

ok "PAM configs locked immutable — re-injection will fail"
warn "To make legitimate PAM changes: chattr -i /etc/pam.d/<file>"

# =============================================================================
# 2. LOCK BEACON BINARY PATH
#    Create a decoy immutable placeholder at /usr/local/bin/ssh-auth-check
#    so the attacker's script can't overwrite it.
# =============================================================================
log "\n--- [2] Locking beacon binary path ---"

BEACON="/usr/local/bin/ssh-auth-check"

# If binary still exists, it's been missed — remove it
if [[ -f "$BEACON" ]]; then
    chattr -i "$BEACON" 2>/dev/null || true
    rm -f "$BEACON"
    hit "Removed leftover beacon binary"
fi

# Create an immutable decoy file — attacker's deploy will fail on overwrite
cat > "$BEACON" <<'EOF'
#!/usr/bin/env bash
# This file is a security decoy. The original malicious script has been removed.
# This placeholder is locked immutable to prevent re-installation.
exit 0
EOF
chmod 444 "$BEACON"
chattr +i "$BEACON" 2>/dev/null \
    && ok "$BEACON locked immutable — attacker cannot install beacon" \
    || warn "chattr on $BEACON failed"

# =============================================================================
# 3. LOCK CRON DIRS — prevents self-healing cron re-installation
# =============================================================================
log "\n--- [3] Locking cron directories ---"

# Ensure malicious cron is gone before locking
for f in /var/spool/cron/crontabs/*; do
    [[ -f "$f" ]] || continue
    if grep -qE "ssh-auth-check|System-Svc-Monitor" "$f" 2>/dev/null; then
        sed -i -E '/ssh-auth-check|System-Svc-Monitor/d' "$f"
        hit "Cleaned cron spool: $f"
    fi
    chattr +i "$f" 2>/dev/null || true
done
chattr +i /var/spool/cron/crontabs 2>/dev/null \
    && ok "/var/spool/cron/crontabs locked" \
    || warn "Could not lock cron spool"

for f in /etc/cron.d/*; do
    [[ -f "$f" ]] || continue
    chattr +i "$f" 2>/dev/null || true
done
chattr +i /etc/cron.d 2>/dev/null && ok "/etc/cron.d locked" || true

if [[ -f /etc/crontab ]]; then
    chattr +i /etc/crontab 2>/dev/null && ok "/etc/crontab locked" || true
fi

ok "Cron dirs locked — System-Svc-Monitor cannot re-inject"
warn "To add legitimate cron entries: chattr -i /etc/cron.d first"

# =============================================================================
# 4. LOCK SSH CONFIGURATION IMMUTABLE
#    Party Rocket forces PasswordAuthentication yes — lock it down
# =============================================================================
log "\n--- [4] Locking SSH configuration ---"

# SCORING SAFETY: SCP-OPENSSH-01 (10.10.10.103) MUST keep PasswordAuthentication yes
# for scp073/scp343. DO NOT run this script on 10.10.10.103 — use fix-ssh.sh instead.
THIS_IP="$(hostname -I | awk '{print $1}')"
SSHD_CONFIG="/etc/ssh/sshd_config"
chattr -i "$SSHD_CONFIG" 2>/dev/null || true

if [[ "$THIS_IP" == "10.10.10.103" ]]; then
    warn "SCP-OPENSSH-01 detected — locking sshd_config WITHOUT disabling PasswordAuth (required for scoring)"
    chattr +i "$SSHD_CONFIG" 2>/dev/null && ok "sshd_config locked (PasswordAuthentication preserved)" || warn "chattr failed"
else
    # Verify the config is clean before locking
    if grep -q "^PasswordAuthentication yes" "$SSHD_CONFIG" 2>/dev/null; then
        warn "PasswordAuthentication still YES — fixing before lock"
        sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' "$SSHD_CONFIG"
        hit "Corrected PasswordAuthentication to no"
    fi

    chattr +i "$SSHD_CONFIG" 2>/dev/null \
        && ok "sshd_config locked immutable — attacker cannot re-enable password auth" \
        || warn "chattr on sshd_config failed"
fi

# =============================================================================
# 5. SNAPSHOT BASHRC FILES
#    Detect future PROMPT_COMMAND injection by checksumming current .bashrc files
# =============================================================================
log "\n--- [5] Bashrc baseline snapshot ---"

BASELINE="$SCRIPT_DIR/bashrc_baseline_$(hostname)_$(date +%Y%m%d).sha256"
> "$BASELINE"

for homedir in /root /home/*/; do
    homedir="${homedir%/}"
    [[ -d "$homedir" ]] || continue
    bashrc="$homedir/.bashrc"
    [[ -f "$bashrc" ]] || continue

    # Verify clean before snapshotting
    if grep -qE "hidden_log|system_data_cache" "$bashrc" 2>/dev/null; then
        warn "Bashrc still contains hijack — cleaning before snapshot"
        sed -i -E '/hidden_log|system_data_cache/d' "$bashrc"
        hit "Cleaned $bashrc"
    fi

    sha256sum "$bashrc" >> "$BASELINE"
    ok "Baselined: $bashrc"
done

ok "Bashrc baseline written: $BASELINE"
log "  To check for tampering later: sha256sum -c $BASELINE 2>&1 | grep FAILED"

# =============================================================================
# 6. INOTIFY MONITOR — watch for re-injection attempts
# =============================================================================
log "\n--- [6] Installing re-injection monitors ---"

if command -v inotifywait &>/dev/null; then
    # Monitor 1: PAM and SSH config changes
    PAM_WATCH="/usr/local/bin/rocket_pam_watch.sh"
    cat > "$PAM_WATCH" <<'WATCHEOF'
#!/usr/bin/env bash
ALERT_LOG="/var/log/rocket_pam_alerts.log"
inotifywait -m -e modify,create,attrib \
    /etc/pam.d/ /etc/ssh/sshd_config /usr/local/bin/ /var/lib/systemd/ 2>/dev/null \
| while read -r dir event file; do
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    msg="[$ts] ROCKET_WATCH: event=$event path=${dir}${file}"
    echo "$msg" | tee -a "$ALERT_LOG"
    echo "ROCKET_REINJECT: $event ${dir}${file}" > /dev/kmsg 2>/dev/null || true

    # Auto-remove beacon if it reappears
    if [[ "${dir}${file}" == "/usr/local/bin/ssh-auth-check" && "$event" != "ATTRIB" ]]; then
        echo "[$ts] BEACON REAPPEARED — auto-removing" | tee -a "$ALERT_LOG"
        chattr -i "/usr/local/bin/ssh-auth-check" 2>/dev/null || true
        rm -f "/usr/local/bin/ssh-auth-check"
    fi

    # Alert if credential log reappears
    if [[ "${dir}${file}" == "/var/lib/systemd/ssh-service.log" ]]; then
        echo "[$ts] CREDENTIAL LOG REAPPEARED — host may be reinfected!" | tee -a "$ALERT_LOG"
        echo "ROCKET_CREDLOG: ssh-service.log recreated" > /dev/kmsg 2>/dev/null || true
    fi
done
WATCHEOF
    chmod +x "$PAM_WATCH"

    cat > /etc/systemd/system/rocket-pam-watch.service <<'SVCEOF'
[Unit]
Description=Party Rocket PAM re-injection detector
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rocket_pam_watch.sh
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable rocket-pam-watch.service
    systemctl restart rocket-pam-watch.service
    ok "PAM/SSH watch running → /var/log/rocket_pam_alerts.log"

    # Monitor 2: .bashrc files for PROMPT_COMMAND injection
    BASHRC_WATCH="/usr/local/bin/rocket_bashrc_watch.sh"
    cat > "$BASHRC_WATCH" <<'BWATCHEOF'
#!/usr/bin/env bash
ALERT_LOG="/var/log/rocket_bashrc_alerts.log"
WATCH_DIRS=""
for homedir in /root /home/*/; do
    homedir="${homedir%/}"
    [[ -d "$homedir" ]] && WATCH_DIRS="$WATCH_DIRS $homedir"
done

inotifywait -m -r -e modify,create $WATCH_DIRS 2>/dev/null \
| while read -r dir event file; do
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    [[ "$file" == ".bashrc" || "$file" == ".bash_profile" || "$file" == ".profile" ]] || continue

    fullpath="${dir}${file}"
    if grep -qE "hidden_log|system_data_cache" "$fullpath" 2>/dev/null; then
        echo "[$ts] BASHRC HIJACKED: $fullpath — auto-cleaning" | tee -a "$ALERT_LOG"
        echo "ROCKET_BASHRC: hijack detected in $fullpath" > /dev/kmsg 2>/dev/null || true
        sed -i -E '/hidden_log|system_data_cache/d' "$fullpath"
    else
        echo "[$ts] BASHRC_MODIFY: $fullpath (event=$event)" >> "$ALERT_LOG"
    fi
done
BWATCHEOF
    chmod +x "$BASHRC_WATCH"

    cat > /etc/systemd/system/rocket-bashrc-watch.service <<'SVCEOF'
[Unit]
Description=Party Rocket bashrc hijack detector
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rocket_bashrc_watch.sh
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable rocket-bashrc-watch.service
    systemctl restart rocket-bashrc-watch.service
    ok "Bashrc watch running → /var/log/rocket_bashrc_alerts.log"

else
    warn "inotify-tools not installed — run: apt-get install -y inotify-tools"
    warn "Skipping real-time monitors"
fi

# =============================================================================
# 7. LOCK CRITICAL FILES IMMUTABLE
# =============================================================================
log "\n--- [7] Locking critical files immutable ---"

for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow \
         /etc/sudoers /etc/hosts /etc/resolv.conf; do
    [[ -f "$f" ]] || continue
    chattr +i "$f" 2>/dev/null && ok "chattr +i $f" || warn "chattr failed: $f"
done

# =============================================================================
# SUMMARY
# =============================================================================
log ""
log "${BLD}=== Inoculation complete — $(hostname) ===${RST}"
log ""
log "Monitors running:"
log "  ${CYN}journalctl -kf | grep -E 'ROCKET'${RST}"
log "  ${CYN}tail -F /var/log/rocket_pam_alerts.log${RST}"
log "  ${CYN}tail -F /var/log/rocket_bashrc_alerts.log${RST}"
log ""
log "To verify bashrc integrity:"
log "  ${CYN}sha256sum -c $BASELINE 2>&1 | grep FAILED${RST}"
log ""
log "Unlock before legitimate changes:"
log "  PAM:  ${CYN}chattr -i /etc/pam.d/<file>${RST}"
log "  Cron: ${CYN}chattr -i /etc/cron.d${RST}"
log "  SSH:  ${CYN}chattr -i /etc/ssh/sshd_config${RST}"
