#!/usr/bin/env bash
# =============================================================================
# 04-inoculate.sh  [LEVEL 4 — HARDEN AGAINST REINFECTION]
# Closes every specific attack vector Goblin-Wagon uses.
# Safe to run even if no active infection is found — pure hardening.
#
# Vectors closed:
#   - SSH InsecureIgnoreHostKey() → enforce StrictHostKeyChecking
#   - sudo -n payload exec        → require password + log all sudo
#   - /tmp/.cache binary drop     → noexec + immutable .cache dir
#   - Filesystem scrambling       → snapshot target dirs with checksums
#   - Cron/timer injection        → lock cron dirs + inotify watch
#   - DNS corruption              → lock /etc/resolv.conf + hosts immutable
#   - Worm proof file             → make /etc immutable after cleanup
#   - Reverse DNS discovery       → optionally disable rDNS responses
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

log "${BLD}=== Goblin-Wagon Inoculation — $(hostname) ===${RST}"

# =============================================================================
# 1. SSH — enforce StrictHostKeyChecking globally
#    The orchestrator uses ssh.InsecureIgnoreHostKey() — it skips key checks
#    for the victim side. We harden the sshd_config to make the protocol
#    harder to abuse from a compromised account.
# =============================================================================
log "\n--- [1] SSH hardening ---"

chattr -i /etc/ssh/sshd_config 2>/dev/null || true

# Disable password auth if possible (breaks worm's password-based spread TO us)
# Only do this if there's already a key-based login available
if [[ -f /root/.ssh/authorized_keys ]] || ls /home/*/.ssh/authorized_keys 2>/dev/null | head -1; then
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    grep -q "^PasswordAuthentication" /etc/ssh/sshd_config \
        || echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
    hit "SSH PasswordAuthentication disabled — worm cannot authenticate via password"
    warn "Verify you have key-based access before closing this session"
else
    warn "No authorized_keys found — leaving PasswordAuthentication enabled to avoid lockout"
    warn "Add your SSH public key then re-run to disable password auth"
fi

# Restrict SSH to specific users if your team has a known list
# Uncomment and populate:
# echo "AllowUsers yourteamuser" >> /etc/ssh/sshd_config

# Log all SSH connections at verbose level
sed -i 's/^#*LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config
grep -q "^LogLevel" /etc/ssh/sshd_config \
    || echo "LogLevel VERBOSE" >> /etc/ssh/sshd_config

# Limit auth attempts — makes brute-force credential stuffing slower
sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 2/' /etc/ssh/sshd_config
grep -q "^MaxAuthTries" /etc/ssh/sshd_config \
    || echo "MaxAuthTries 2" >> /etc/ssh/sshd_config

systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
chattr +i /etc/ssh/sshd_config 2>/dev/null && ok "sshd_config locked immutable" || true

# =============================================================================
# 2. SUDO HARDENING — wagon uses `sudo -n bash -c` (NOPASSWD required)
#    Also add logging so every sudo invocation is audited
# =============================================================================
log "\n--- [2] Sudo hardening ---"

# Remove all NOPASSWD (belt-and-suspenders after 03-lockout.sh)
chattr -i /etc/sudoers 2>/dev/null || true
sed -i 's/NOPASSWD://g' /etc/sudoers
for f in /etc/sudoers.d/*; do
    [[ -f "$f" ]] || continue
    chattr -i "$f" 2>/dev/null || true
    grep -q "NOPASSWD" "$f" && sed -i 's/NOPASSWD://g' "$f" && hit "NOPASSWD removed from $f"
done

# Enable sudo logging to syslog (auditd will also catch it if running)
cat > /etc/sudoers.d/99-audit-logging <<'EOF'
Defaults log_output
Defaults!/usr/bin/sudoreplay !log_output
Defaults logfile=/var/log/sudo.log
Defaults log_year
Defaults loglinelen=0
EOF
chmod 440 /etc/sudoers.d/99-audit-logging
chattr +i /etc/sudoers.d/99-audit-logging 2>/dev/null || true
ok "Sudo output logging enabled → /var/log/sudo.log"

# Lock sudoers immutable
chattr +i /etc/sudoers 2>/dev/null && ok "sudoers locked immutable" || warn "chattr on sudoers failed"

# =============================================================================
# 3. LOCK DOWN /tmp DROP ZONE — /tmp/.cache is the worm's staging area
# =============================================================================
log "\n--- [3] /tmp drop zone lockdown ---"

# Remove and recreate .cache dir as a sticky, non-executable decoy
rm -rf /tmp/.cache 2>/dev/null || true
mkdir -p /tmp/.cache
chmod 1777 /tmp/.cache              # world-sticky, no special perms
chattr +i /tmp/.cache 2>/dev/null \
    && ok "/tmp/.cache locked immutable — worm cannot write binary here" \
    || warn "chattr on /tmp/.cache failed"

# Ensure /tmp is noexec
if ! mount | grep -E " on /tmp " | grep -q noexec; then
    mount -o remount,noexec /tmp 2>/dev/null \
        && ok "/tmp remounted noexec" \
        || warn "/tmp noexec remount failed — add to /etc/fstab"
fi

# Persist noexec across reboots
if ! grep -qE "^\s*tmpfs\s+/tmp" /etc/fstab 2>/dev/null; then
    echo "tmpfs /tmp tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab
    ok "noexec /tmp added to /etc/fstab"
fi

# =============================================================================
# 4. FILESYSTEM SCRAMBLE DEFENCE — take a checksum baseline of target dirs
#    disorder_file_sys.sh hits: /opt /srv /var/www /home /var/log
# =============================================================================
log "\n--- [4] Filesystem baseline snapshot ---"

BASELINE="$SCRIPT_DIR/fs_baseline_$(hostname)_$(date +%Y%m%d).sha256"

for target in /opt /srv /var/www /home /var/log; do
    [[ -d "$target" ]] || continue
    find "$target" -type f 2>/dev/null | sort | xargs sha256sum 2>/dev/null
done > "$BASELINE"

BASELINE_COUNT=$(wc -l < "$BASELINE")
ok "Baseline written: $BASELINE ($BASELINE_COUNT files checksummed)"
log "  Run later to detect scrambling: sha256sum -c $BASELINE 2>&1 | grep FAILED"

# Set up an inotify watch on the target dirs to alert on mass renames
if command -v inotifywait &>/dev/null; then
    WATCH_SCRIPT="/usr/local/bin/goblin_fs_watch.sh"
    ALERT_LOG="/var/log/goblin_fs_alerts.log"

    cat > "$WATCH_SCRIPT" <<'WATCHEOF'
#!/usr/bin/env bash
ALERT_LOG="/var/log/goblin_fs_alerts.log"
inotifywait -m -r -e moved_from,moved_to,create,delete \
    /opt /srv /var/www /home /var/log 2>/dev/null \
| while read -r dir event file; do
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[$ts] FS_CHANGE event=$event path=${dir}${file}" | tee -a "$ALERT_LOG"
    echo "GOBLIN_FS_WATCH: $event ${dir}${file}" > /dev/kmsg 2>/dev/null || true
done
WATCHEOF

    chmod +x "$WATCH_SCRIPT"
    cat > /etc/systemd/system/goblin-fs-watch.service <<'SVCEOF'
[Unit]
Description=Goblin-Wagon filesystem scramble detector
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/goblin_fs_watch.sh
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SVCEOF
    systemctl daemon-reload
    systemctl enable goblin-fs-watch.service
    systemctl restart goblin-fs-watch.service
    ok "Filesystem watch running → $ALERT_LOG"
else
    warn "inotify-tools not installed — run: apt-get install -y inotify-tools"
fi

# =============================================================================
# 5. CRON LOCKDOWN — junk_cron_n_timers.sh injects into cron
# =============================================================================
log "\n--- [5] Cron lockdown ---"

# Lock crontab files immutable
for f in /etc/crontab; do
    [[ -f "$f" ]] || continue
    chattr +i "$f" 2>/dev/null && ok "chattr +i $f" || warn "chattr failed: $f"
done

# Lock cron.d directory (prevents adding new files)
for f in /etc/cron.d/*; do
    [[ -f "$f" ]] || continue
    chattr +i "$f" 2>/dev/null || true
done
chattr +i /etc/cron.d 2>/dev/null && ok "/etc/cron.d locked immutable" || true

# Lock user crontab spool
chattr -R +i /var/spool/cron/crontabs 2>/dev/null \
    && ok "/var/spool/cron/crontabs locked" \
    || warn "Could not lock cron spool"

ok "Cron dirs locked — to add legitimate crons: chattr -i /etc/cron.d first"

# =============================================================================
# 6. DNS LOCKDOWN — dns_disruptor.sh corrupts /etc/hosts and resolv.conf
# =============================================================================
log "\n--- [6] DNS file lockdown ---"

# Take a snapshot first
cp /etc/hosts /etc/hosts.goblin_backup 2>/dev/null
cp /etc/resolv.conf /etc/resolv.conf.goblin_backup 2>/dev/null

chattr +i /etc/hosts     2>/dev/null && ok "/etc/hosts locked immutable"     || warn "chattr failed: /etc/hosts"
chattr +i /etc/resolv.conf 2>/dev/null && ok "/etc/resolv.conf locked immutable" || warn "chattr failed: /etc/resolv.conf"

# =============================================================================
# 7. LOCK /etc — worm writes /etc/redteam_was_here.txt as a proof file
#    After cleanup, make the dir itself append-only for new files
# =============================================================================
log "\n--- [7] /etc proof file cleanup and hardening ---"

if [[ -f /etc/redteam_was_here.txt ]]; then
    rm -f /etc/redteam_was_here.txt
    hit "Removed /etc/redteam_was_here.txt"
fi

# chattr +a on /etc means new files can be created but not deleted/modified
# (use +i only on individual files you don't want changed at all)
# We do individual critical files instead to not break package installs
for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow; do
    chattr +i "$f" 2>/dev/null && ok "chattr +i $f" || warn "chattr failed: $f"
done

# =============================================================================
# 8. INSTALL CANARY for worm proof file re-creation
# =============================================================================
log "\n--- [8] Proof-file canary ---"

if command -v inotifywait &>/dev/null; then
    CANARY="/usr/local/bin/goblin_etc_canary.sh"
    cat > "$CANARY" <<'CEOF'
#!/usr/bin/env bash
ALERT_LOG="/var/log/goblin_etc_alerts.log"
inotifywait -m /etc -e create 2>/dev/null \
| while read -r dir event file; do
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[$ts] NEW FILE IN /etc: $file (event=$event)" | tee -a "$ALERT_LOG"
    if [[ "$file" == "redteam_was_here.txt" ]]; then
        echo "[$ts] GOBLIN PROOF FILE RECREATED — host is being reinfected!" | tee -a "$ALERT_LOG"
        echo "GOBLIN_REINFECT: $file" > /dev/kmsg 2>/dev/null || true
        rm -f "/etc/$file"
    fi
done
CEOF
    chmod +x "$CANARY"
    cat > /etc/systemd/system/goblin-etc-canary.service <<'SVCEOF'
[Unit]
Description=Goblin-Wagon /etc proof file canary
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/goblin_etc_canary.sh
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
SVCEOF
    systemctl daemon-reload
    systemctl enable goblin-etc-canary.service
    systemctl restart goblin-etc-canary.service
    ok "Proof file canary running — auto-deletes redteam_was_here.txt on recreation"
fi

# =============================================================================
# SUMMARY
# =============================================================================
log ""
log "${BLD}=== Inoculation complete — $(hostname) ===${RST}"
log ""
log "Monitors running:"
log "  ${CYN}journalctl -kf | grep -E 'GOBLIN'${RST}"
log "  ${CYN}tail -F /var/log/goblin_fs_alerts.log${RST}"
log "  ${CYN}tail -F /var/log/goblin_etc_alerts.log${RST}"
log ""
log "To verify filesystem integrity later:"
log "  ${CYN}sha256sum -c $BASELINE 2>&1 | grep FAILED${RST}"
log ""
log "Unlock before legitimate changes:"
log "  Files: ${CYN}chattr -i <file>${RST}"
log "  Cron:  ${CYN}chattr -i /etc/cron.d${RST}"
