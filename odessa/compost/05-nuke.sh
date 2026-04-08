#!/usr/bin/env bash
# =============================================================================
# 05-nuke.sh  [LEVEL 5 — SCORCHED EARTH]
# Full post-infection cleanup. Assumes Party Rocket has already run on this host.
#
# Actions:
#   1.  Kill all beacon processes
#   2.  Remove all artifacts (beacon binary, credential log, hidden logs)
#   3.  Purge and restore PAM configuration from package manager
#   4.  Purge injected cron jobs
#   5.  Clean all bashrc files for all users
#   6.  Restore SSH configuration to secure baseline
#   7.  Run full lockout + inoculate automatically
#   8.  Install persistent PAM integrity monitor
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

log "${BLD}=== Party Rocket Scorched Earth — $(hostname) ===${RST}"
log "Evidence dir: $EVIDENCE"
mkdir -p "$EVIDENCE"

# =============================================================================
# 1. KILL ALL BEACON PROCESSES
# =============================================================================
log "\n--- [1/9] Killing beacon processes ---"

pkill -9 -f "ssh-auth-check" 2>/dev/null && hit "Killed ssh-auth-check processes" || true

# Walk /proc for any beacon by content (catches renamed copies)
for pid_dir in /proc/[0-9]*/; do
    pid="${pid_dir%/}"
    pid="${pid##*/}"
    exe=$(readlink "${pid_dir}exe" 2>/dev/null || true)
    [[ -z "$exe" ]] && continue

    # Check if the exe reads PAM auth tokens
    if cat "${pid_dir}cmdline" 2>/dev/null | tr '\0' ' ' | grep -qi "ssh-auth-check"; then
        kill -9 "$pid" 2>/dev/null && hit "Killed PID $pid ($exe)" || true
    fi
done

ok "Process kill sweep complete"

# =============================================================================
# 2. COLLECT EVIDENCE AND REMOVE ALL ARTIFACTS
# =============================================================================
log "\n--- [2/9] Collecting evidence and removing artifacts ---"

# Credential log
CREDLOG="/var/lib/systemd/ssh-service.log"
if [[ -f "$CREDLOG" ]]; then
    cp -p "$CREDLOG" "$EVIDENCE/"
    chmod 600 "$EVIDENCE/$(basename $CREDLOG)"
    chattr -i "$CREDLOG" 2>/dev/null || true
    shred -u "$CREDLOG" 2>/dev/null || rm -f "$CREDLOG"
    hit "Removed credential log: $CREDLOG"
    hit "Evidence saved — PASSWORDS IN THIS FILE ARE COMPROMISED"
fi

# Beacon binary
BEACON="/usr/local/bin/ssh-auth-check"
if [[ -f "$BEACON" ]]; then
    cp -p "$BEACON" "$EVIDENCE/"
    chattr -i "$BEACON" 2>/dev/null || true
    rm -f "$BEACON"
    hit "Removed beacon binary: $BEACON"
fi

# Hidden command logs for all users
for homedir in /root /home/*/; do
    homedir="${homedir%/}"
    [[ -d "$homedir" ]] || continue
    for hidden in ".local/share/.hidden_log" ".local/share/.system_data_cache"; do
        f="$homedir/$hidden"
        [[ -f "$f" ]] || continue
        cp "$f" "$EVIDENCE/$(basename $homedir)_$(basename $f).evidence" 2>/dev/null || true
        rm -f "$f"
        hit "Removed hidden log: $f"
    done
done

ok "Artifact collection and removal complete"

# =============================================================================
# 3. PAM RESTORATION — reinstall PAM packages for clean baseline
#    This guarantees /etc/pam.d/common-auth is from the official package,
#    not the attacker-modified version.
# =============================================================================
log "\n--- [3/9] Restoring PAM configuration ---"

# Unfreeze all PAM files
for f in /etc/pam.d/*; do
    chattr -i "$f" 2>/dev/null || true
done

if command -v apt-get &>/dev/null; then
    log "Reinstalling PAM packages via apt..."
    apt-get install --reinstall -y \
        libpam-runtime libpam-modules libpam-modules-bin \
        openssh-server 2>&1 | tee -a "$LOG" || true
    # pam-auth-update regenerates /etc/pam.d/common-* files from package profiles
    pam-auth-update --force 2>&1 | tee -a "$LOG" || true
    ok "PAM packages reinstalled and auth config regenerated"
elif command -v dnf &>/dev/null; then
    log "Reinstalling PAM packages via dnf..."
    dnf reinstall -y pam openssh-server 2>&1 | tee -a "$LOG" || true
    authselect apply-changes 2>&1 | tee -a "$LOG" || true
    ok "PAM packages reinstalled"
fi

# Final check — make sure the hook is gone after reinstall
if grep -q "ssh-auth-check" /etc/pam.d/common-auth 2>/dev/null; then
    warn "PAM hook survived reinstall — removing manually"
    sed -i '/ssh-auth-check/d' /etc/pam.d/common-auth
    hit "Manually removed PAM hook post-reinstall"
fi

ok "PAM configuration restored to clean state"

# =============================================================================
# 4. PURGE ALL INJECTED CRON JOBS
# =============================================================================
log "\n--- [4/9] Purging injected cron jobs ---"

# Unfreeze
chattr -i /etc/cron.d 2>/dev/null || true
find /etc/cron.d/ /var/spool/cron/crontabs/ -type f \
    -exec chattr -i {} \; 2>/dev/null || true

# Clean all cron locations
for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
    [[ -f "$f" ]] || continue
    if grep -qE "ssh-auth-check|System-Svc-Monitor" "$f" 2>/dev/null; then
        cp "$f" "$EVIDENCE/$(basename $f).cron.bak"
        sed -i -E '/ssh-auth-check|System-Svc-Monitor/d' "$f"
        hit "Cleaned malicious cron from $f"
    fi
done

# Root crontab via crontab command
if crontab -l 2>/dev/null | grep -qE "ssh-auth-check|System-Svc-Monitor"; then
    crontab -l 2>/dev/null | tee "$EVIDENCE/root_crontab.bak" > /dev/null
    crontab -l 2>/dev/null \
        | grep -vE "ssh-auth-check|System-Svc-Monitor" \
        | crontab -
    hit "Removed malicious entries from root crontab"
fi

ok "Cron purge complete"

# =============================================================================
# 5. CLEAN ALL BASHRC FILES
# =============================================================================
log "\n--- [5/9] Cleaning bashrc injections ---"

for homedir in /root /home/*/; do
    homedir="${homedir%/}"
    [[ -d "$homedir" ]] || continue
    bashrc="$homedir/.bashrc"
    [[ -f "$bashrc" ]] || continue

    if grep -qE "hidden_log|system_data_cache|PROMPT_COMMAND.*hidden" "$bashrc" 2>/dev/null; then
        cp "$bashrc" "$EVIDENCE/$(basename $homedir)_bashrc.bak"
        sed -i -E '/hidden_log|system_data_cache/d' "$bashrc"
        hit "Cleaned bashrc: $bashrc"
    else
        ok "$bashrc clean"
    fi
done

ok "Bashrc cleanup complete"

# =============================================================================
# 6. RESTORE SSH CONFIGURATION TO SECURE BASELINE
# =============================================================================
log "\n--- [6/9] Restoring SSH configuration ---"

SSHD_CONFIG="/etc/ssh/sshd_config"
chattr -i "$SSHD_CONFIG" 2>/dev/null || true
cp "$SSHD_CONFIG" "$EVIDENCE/sshd_config.bak"

# Disable password auth if keys exist
if [[ -f /root/.ssh/authorized_keys ]] || ls /home/*/.ssh/authorized_keys 2>/dev/null | head -1 &>/dev/null; then
    sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' "$SSHD_CONFIG"
    grep -q "^PasswordAuthentication" "$SSHD_CONFIG" \
        || echo "PasswordAuthentication no" >> "$SSHD_CONFIG"
    hit "PasswordAuthentication set to no"
else
    warn "No authorized_keys — leaving password auth enabled to avoid lockout"
fi

sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 2/' "$SSHD_CONFIG"
grep -q "^MaxAuthTries" "$SSHD_CONFIG" || echo "MaxAuthTries 2" >> "$SSHD_CONFIG"

sed -i 's/^#*LogLevel.*/LogLevel VERBOSE/' "$SSHD_CONFIG"
grep -q "^LogLevel" "$SSHD_CONFIG" || echo "LogLevel VERBOSE" >> "$SSHD_CONFIG"

systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
ok "SSH configuration restored and restarted"

# =============================================================================
# 7. RUN LOCKOUT AND INOCULATION
# =============================================================================
log "\n--- [7/9] Running credential lockout and inoculation ---"

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
# 8. INSTALL PERSISTENT PAM INTEGRITY MONITOR
#    Watches PAM config dir and /usr/local/bin for any write events.
#    Alerts to kernel log and file — visible in: journalctl -kf | grep ROCKET
# =============================================================================
log "\n--- [8/9] Installing persistent PAM integrity monitor ---"

if command -v inotifywait &>/dev/null; then
    CANARY="/usr/local/bin/rocket_canary.sh"

    # Don't overwrite if 04-inoculate already installed it
    if [[ ! -f "$CANARY" ]]; then
        cat > "$CANARY" <<'CANEOF'
#!/usr/bin/env bash
ALERT_LOG="/var/log/rocket_canary.log"
inotifywait -m -e modify,create,attrib \
    /etc/pam.d/ /etc/ssh/ /usr/local/bin/ /var/lib/systemd/ 2>/dev/null \
| while read -r dir event file; do
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[$ts] CANARY: $event ${dir}${file}" | tee -a "$ALERT_LOG"
    echo "ROCKET_CANARY: $event ${dir}${file}" > /dev/kmsg 2>/dev/null || true

    # Auto-clean beacon re-drop
    if [[ "$file" == "ssh-auth-check" && "$event" == "CREATE" ]]; then
        echo "[$ts] BEACON REDEPLOYED — auto-removing" | tee -a "$ALERT_LOG"
        sleep 0.5
        chattr -i "${dir}${file}" 2>/dev/null || true
        rm -f "${dir}${file}"
    fi

    # Alert on credential log re-creation
    if [[ "$file" == "ssh-service.log" && "$event" == "CREATE" ]]; then
        echo "[$ts] CREDENTIAL LOG RECREATED — ACTIVE REINFECTION" | tee -a "$ALERT_LOG"
        echo "ROCKET_REINFECT: ssh-service.log recreated on $(hostname)" > /dev/kmsg 2>/dev/null || true
    fi

    # Alert on PAM modification
    if [[ "$dir" == "/etc/pam.d/" && "$event" == "MODIFY" ]]; then
        echo "[$ts] PAM CONFIG MODIFIED: $file" | tee -a "$ALERT_LOG"
        if grep -q "ssh-auth-check" "/etc/pam.d/$file" 2>/dev/null; then
            echo "[$ts] PAM HOOK REINJECTED in $file — auto-removing" | tee -a "$ALERT_LOG"
            sed -i '/ssh-auth-check/d' "/etc/pam.d/$file"
        fi
    fi
done
CANEOF
        chmod +x "$CANARY"

        cat > /etc/systemd/system/rocket-canary.service <<'SVCEOF'
[Unit]
Description=Party Rocket reinfection canary
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rocket_canary.sh
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
SVCEOF

        systemctl daemon-reload
        systemctl enable rocket-canary.service
        systemctl restart rocket-canary.service
        ok "Canary service running → /var/log/rocket_canary.log"
    else
        ok "Canary already installed (from 04-inoculate.sh)"
    fi
else
    warn "inotify-tools not installed: apt-get install -y inotify-tools"
fi

# =============================================================================
# 9. FINAL IMMUTABLE LOCK
# =============================================================================
log "\n--- [9/9] Final immutable lock ---"

for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow \
         /etc/sudoers /etc/ssh/sshd_config \
         /etc/hosts /etc/resolv.conf; do
    [[ -f "$f" ]] || continue
    chattr +i "$f" 2>/dev/null && ok "chattr +i $f" || warn "chattr failed: $f"
done

# =============================================================================
# VERIFY SSH IS STILL UP
# =============================================================================
if systemctl is-active ssh &>/dev/null || systemctl is-active sshd &>/dev/null; then
    ok "SSH service is running — verify login from a second terminal NOW"
else
    warn "SSH is NOT running — fix before closing this session"
fi

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
log "  ${CYN}journalctl -kf | grep -E 'ROCKET'${RST}"
log "  ${CYN}tail -F /var/log/rocket_canary.log${RST}"
log "  ${CYN}tail -F /var/log/rocket_pam_alerts.log${RST}"
log ""
log "${RED}${BLD}CRITICAL: Review captured credentials in $EVIDENCE/${RST}"
log "Every password that was used to authenticate during infection is compromised."
log "Rotate all account passwords on this host and any shared-credential systems."
log ""
log "The attacker used one universal password: ${RED}Cyberrange123!${RST}"
log "Rotate it on every host in the lab — run 03-lockout.sh on all 10.10.10.1-199"
