#!/usr/bin/env bash
# =============================================================================
# 01-detect.sh  [LEVEL 1 — FORENSIC SCAN]
# Detects signs of Party Rocket infection on this host.
#
# Party Rocket attack vectors detected:
#   - PAM pam_exec.so hook pointing to /usr/local/bin/ssh-auth-check
#   - Credential log at /var/lib/systemd/ssh-service.log (plaintext passwords)
#   - Immutable beacon binary (chattr +i)
#   - Self-healing cron "System-Svc-Monitor" re-inserting PAM line every minute
#   - .bashrc PROMPT_COMMAND hijack logging commands to hidden dotfiles
#   - SSH config forced to PasswordAuthentication yes + UsePAM yes
#   - Timestamp-manipulated config files (anti-forensics)
#   - Hidden command logs: ~/.local/share/.hidden_log, .system_data_cache
#
# Does NOT use ps/who/w.
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
OUT="$SCRIPT_DIR/detect_$(hostname)_$(date +%Y%m%d_%H%M%S).txt"

log()  { echo -e "$*" | tee -a "$OUT"; }
hit()  { echo -e "${RED}[HIT]${RST}  $*" | tee -a "$OUT"; }
ok()   { echo -e "${GRN}[OK]${RST}   $*" | tee -a "$OUT"; }
info() { echo -e "${CYN}[INFO]${RST} $*" | tee -a "$OUT"; }
warn() { echo -e "${YLW}[WARN]${RST} $*" | tee -a "$OUT"; }

log "\n${BLD}=== Party Rocket Detection — $(hostname) — $(date) ===${RST}\n"

TOTAL_HITS=0
hit_count() { TOTAL_HITS=$((TOTAL_HITS + 1)); }

# =============================================================================
# 1. PAM HOOK — pam_exec.so wired to ssh-auth-check
#    The beacon inserts this at line 1 of /etc/pam.d/common-auth:
#    auth optional pam_exec.so quiet expose_authtok /usr/local/bin/ssh-auth-check
# =============================================================================
log "${BLD}--- 1. PAM hook injection (/etc/pam.d/common-auth) ---${RST}"

if [[ -f /etc/pam.d/common-auth ]]; then
    if grep -q "ssh-auth-check" /etc/pam.d/common-auth; then
        hit "PAM hook ACTIVE — ssh-auth-check is in /etc/pam.d/common-auth"
        grep "ssh-auth-check" /etc/pam.d/common-auth | tee -a "$OUT"
        hit_count
    else
        ok "No ssh-auth-check hook in /etc/pam.d/common-auth"
    fi

    # Check any pam_exec.so entry (the tool uses pam_exec to run the script)
    if grep -q "pam_exec.so" /etc/pam.d/common-auth; then
        warn "pam_exec.so present in /etc/pam.d/common-auth — verify it's legitimate:"
        grep "pam_exec.so" /etc/pam.d/common-auth | tee -a "$OUT"
    fi
else
    warn "/etc/pam.d/common-auth not found"
fi

# Check all PAM configs for the hook
log ""
info "Scanning all /etc/pam.d/* files for ssh-auth-check..."
grep -rl "ssh-auth-check" /etc/pam.d/ 2>/dev/null | while read -r f; do
    hit "ssh-auth-check hook found in PAM config: $f"
    grep "ssh-auth-check" "$f" | tee -a "$OUT"
    hit_count
done || true

# =============================================================================
# 2. BEACON BINARY — /usr/local/bin/ssh-auth-check
#    Script reads auth tokens, logs plaintext passwords with PAM env vars
# =============================================================================
log "\n${BLD}--- 2. Beacon binary ---${RST}"

BEACON="/usr/local/bin/ssh-auth-check"
if [[ -f "$BEACON" ]]; then
    hit "Beacon binary EXISTS: $BEACON"
    ls -la "$BEACON" | tee -a "$OUT"

    # Check if immutable (chattr +i)
    attrs=$(lsattr "$BEACON" 2>/dev/null || echo "lsattr failed")
    echo "  Attributes: $attrs" | tee -a "$OUT"
    if echo "$attrs" | grep -q -- "-i-"; then
        hit "Binary is IMMUTABLE (chattr +i) — must run chattr -i before removal"
    fi

    # Show content
    log "  Content:"
    cat "$BEACON" | tee -a "$OUT"
    hit_count
else
    ok "$BEACON not found"
fi

# Check for any other scripts logging PAM variables
info "Scanning /usr/local/bin/ for PAM variable references..."
grep -rl "PAM_USER\|PAM_RHOST\|expose_authtok" /usr/local/bin/ 2>/dev/null | while read -r f; do
    hit "PAM credential logger candidate: $f"
    hit_count
done || true

# =============================================================================
# 3. CREDENTIAL LOG — /var/lib/systemd/ssh-service.log
#    Plaintext password log, world-readable (chmod 666)
# =============================================================================
log "\n${BLD}--- 3. Credential harvest log ---${RST}"

CREDLOG="/var/lib/systemd/ssh-service.log"
if [[ -f "$CREDLOG" ]]; then
    hit "CREDENTIAL LOG EXISTS: $CREDLOG"
    ls -la "$CREDLOG" | tee -a "$OUT"
    log "  Line count: $(wc -l < "$CREDLOG")"
    log "  Last 5 entries (CONTAINS PLAINTEXT PASSWORDS):"
    tail -5 "$CREDLOG" | sed 's/^/    /' | tee -a "$OUT"
    hit_count
else
    ok "$CREDLOG not present"
fi

# Broader sweep for suspicious logs in /var/lib/systemd/
info "Scanning /var/lib/systemd/ for non-standard files..."
find /var/lib/systemd/ -maxdepth 2 -type f 2>/dev/null | while read -r f; do
    # Skip known systemd files
    case "$f" in
        */coredump/*|*/catalog/*|*/journal/*|*/random-seed|*/credential.secret|*/timesync/clock) continue ;;
    esac
    warn "Non-standard file in /var/lib/systemd/: $f"
    ls -la "$f" | tee -a "$OUT"
done || true

# =============================================================================
# 4. SELF-HEALING CRON — "System-Svc-Monitor"
#    Runs every minute, re-inserts PAM hook if removed
# =============================================================================
log "\n${BLD}--- 4. Self-healing cron job ---${RST}"

cron_found=0

# Check root crontab
if crontab -l 2>/dev/null | grep -q "ssh-auth-check\|System-Svc-Monitor"; then
    hit "Malicious cron in ROOT crontab:"
    crontab -l 2>/dev/null | grep -E "ssh-auth-check|System-Svc-Monitor" | tee -a "$OUT"
    cron_found=1
    hit_count
fi

# Check all user crontabs in spool
for f in /var/spool/cron/crontabs/*; do
    [[ -f "$f" ]] || continue
    if grep -qE "ssh-auth-check|System-Svc-Monitor" "$f" 2>/dev/null; then
        hit "Malicious cron in $f:"
        grep -E "ssh-auth-check|System-Svc-Monitor" "$f" | tee -a "$OUT"
        cron_found=1
        hit_count
    fi
done

# Check /etc/cron.d/
for f in /etc/cron.d/*; do
    [[ -f "$f" ]] || continue
    if grep -qE "ssh-auth-check|System-Svc-Monitor" "$f" 2>/dev/null; then
        hit "Malicious cron in $f:"
        grep -E "ssh-auth-check|System-Svc-Monitor" "$f" | tee -a "$OUT"
        cron_found=1
        hit_count
    fi
done

# Check /etc/crontab
if grep -qE "ssh-auth-check|System-Svc-Monitor" /etc/crontab 2>/dev/null; then
    hit "Malicious entry in /etc/crontab"
    grep -E "ssh-auth-check|System-Svc-Monitor" /etc/crontab | tee -a "$OUT"
    cron_found=1
    hit_count
fi

[[ $cron_found -eq 0 ]] && ok "No ssh-auth-check or System-Svc-Monitor cron entries found"

# =============================================================================
# 5. BASHRC HIJACK — PROMPT_COMMAND redirected to hidden log files
#    Logs every command with timestamp to ~/.local/share/.hidden_log
#    and ~/.local/share/.system_data_cache
# =============================================================================
log "\n${BLD}--- 5. Bash command history exfiltration ---${RST}"

bashrc_hits=0

# Check all user home dirs
for homedir in /root /home/*/; do
    bashrc="$homedir/.bashrc"
    [[ -f "$bashrc" ]] || continue

    if grep -qE "PROMPT_COMMAND.*hidden_log|PROMPT_COMMAND.*system_data_cache|hidden_log|system_data_cache" "$bashrc" 2>/dev/null; then
        hit "BASHRC HIJACKED: $bashrc"
        grep -E "PROMPT_COMMAND|hidden_log|system_data_cache" "$bashrc" | tee -a "$OUT"
        bashrc_hits=1
        hit_count
    fi

    # Check hidden log files
    for hidden in "$homedir/.local/share/.hidden_log" "$homedir/.local/share/.system_data_cache"; do
        if [[ -f "$hidden" ]]; then
            hit "Hidden command log exists: $hidden"
            ls -la "$hidden" | tee -a "$OUT"
            log "  Line count: $(wc -l < "$hidden")"
            log "  Last 3 entries:"
            tail -3 "$hidden" | sed 's/^/    /' | tee -a "$OUT"
            hit_count
        fi
    done
done

[[ $bashrc_hits -eq 0 ]] && ok "No PROMPT_COMMAND hijack detected in .bashrc files"

# =============================================================================
# 6. SSH CONFIG TAMPERING
#    Party Rocket forces PasswordAuthentication yes and UsePAM yes
#    to ensure cred-based logins remain available even after partial hardening
# =============================================================================
log "\n${BLD}--- 6. SSH configuration tampering ---${RST}"

SSHD_CONFIG="/etc/ssh/sshd_config"
if [[ -f "$SSHD_CONFIG" ]]; then
    pw_auth=$(grep -E "^PasswordAuthentication" "$SSHD_CONFIG" 2>/dev/null | tail -1 || echo "not set")
    use_pam=$(grep -E "^UsePAM" "$SSHD_CONFIG" 2>/dev/null | tail -1 || echo "not set")

    if echo "$pw_auth" | grep -qi "yes"; then
        hit "PasswordAuthentication is YES in sshd_config — attacker may have forced this"
        echo "  $pw_auth" | tee -a "$OUT"
        hit_count
    else
        ok "PasswordAuthentication: $pw_auth"
    fi

    if echo "$use_pam" | grep -qi "yes"; then
        warn "UsePAM is YES — required for PAM hook to intercept passwords"
        echo "  $use_pam" | tee -a "$OUT"
    fi

    # Check for anti-forensics timestamp manipulation
    # Party Rocket runs: touch -r /etc/hostname /etc/ssh/sshd_config
    hostname_ts=$(stat -c %Y /etc/hostname 2>/dev/null || echo "0")
    sshd_ts=$(stat -c %Y "$SSHD_CONFIG" 2>/dev/null || echo "0")
    pam_ts=$(stat -c %Y /etc/pam.d/common-auth 2>/dev/null || echo "0")

    if [[ "$sshd_ts" == "$hostname_ts" ]]; then
        hit "ANTI-FORENSICS: sshd_config timestamp matches /etc/hostname (touch -r applied)"
        hit_count
    fi
    if [[ "$pam_ts" == "$hostname_ts" ]]; then
        hit "ANTI-FORENSICS: /etc/pam.d/common-auth timestamp matches /etc/hostname (touch -r applied)"
        hit_count
    fi
else
    warn "sshd_config not found"
fi

# =============================================================================
# 7. HARDCODED CREDENTIAL ACCOUNTS
#    Inventory files show: cyberrange:Cyberrange123! and ubuntu:Cyberrange123!
# =============================================================================
log "\n${BLD}--- 7. Hardcoded credential accounts ---${RST}"

for user in cyberrange ubuntu; do
    if id "$user" &>/dev/null; then
        warn "Account '$user' exists (used in Party Rocket inventory files with known password)"
        id "$user" | tee -a "$OUT"
    else
        ok "Account '$user' not present"
    fi
done

# =============================================================================
# 8. LOOT COLLECTION ARTIFACTS
#    flagfinder searches /etc /var/www /home /tmp /root for FLAG{...}
#    harvester searches /var/www /etc/mysql /etc/apache2 /etc/sssd /etc/ldap /etc/samba
# =============================================================================
log "\n${BLD}--- 8. Evidence of active reconnaissance ---${RST}"

# Check if recent access times on sensitive dirs suggest enumeration
for target in /etc/mysql /etc/sssd /etc/ldap /etc/samba /var/www/html/wp-config.php; do
    [[ -e "$target" ]] || continue
    atime=$(stat -c %X "$target" 2>/dev/null || echo "0")
    now=$(date +%s)
    age=$((now - atime))
    if [[ $age -lt 3600 ]]; then
        warn "Recently accessed (<1h ago): $target — may indicate enumeration"
        stat -c "  Last access: %x" "$target" | tee -a "$OUT"
    fi
done

# Check for running processes executing the beacon (via /proc)
log ""
info "Scanning /proc for beacon execution patterns..."
for pid_dir in /proc/[0-9]*/; do
    pid="${pid_dir%/}"
    pid="${pid##*/}"
    cmdline=$(tr '\0' ' ' < "${pid_dir}cmdline" 2>/dev/null | xargs 2>/dev/null || true)
    [[ -z "$cmdline" ]] && continue
    if echo "$cmdline" | grep -qi "ssh-auth-check"; then
        hit "Beacon process running: PID $pid — $cmdline"
        hit_count
    fi
done

# =============================================================================
# SUMMARY
# =============================================================================
log ""
log "${BLD}=== Detection complete — $(hostname) ===${RST}"
log "Report saved: $OUT"
log ""
if [[ $TOTAL_HITS -gt 0 ]]; then
    log "${RED}${BLD}INFECTED — $TOTAL_HITS indicators found.${RST}"
    log ""
    log "Response playbook:"
    log "  02-evict.sh   — remove beacon, PAM hook, cron, bashrc injection"
    log "  03-lockout.sh — rotate credentials, harden SSH, block attacker access"
    log "  04-inoculate.sh — lock files, monitor for re-injection"
    log "  05-nuke.sh    — full scorched-earth cleanup"
else
    log "${GRN}No Party Rocket indicators found.${RST}"
    log "Run 04-inoculate.sh to harden this host proactively."
fi
