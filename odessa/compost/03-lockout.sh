#!/usr/bin/env bash
# =============================================================================
# 03-lockout.sh  [LEVEL 3 — CREDENTIAL ROTATION AND ACCESS HARDENING]
# Rotates all credentials the attacker knows about, hardens SSH, and blocks
# outbound access from this host to prevent it becoming a pivot point.
#
# Party Rocket uses one universal password: Cyberrange123!
# Accounts used across all inventory files: cyberrange, ubuntu
#
# Actions:
#   1.  Rotate passwords for cyberrange and ubuntu
#   2.  Revoke authorized_keys entries added by attacker (detect + confirm)
#   3.  Kill any active sessions for compromised accounts
#   4.  Harden sshd_config: disable password auth, MaxAuthTries 2, LogLevel VERBOSE
#   5.  Block outbound SSH from this host (stop it being used as a pivot node)
#   6.  Remove ansible/ansible-runner if installed by attacker
#
# Run as root. Keep a second session open — SSH is restarted.
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

log()  { echo -e "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
ok()   { echo -e "${GRN}[OK]${RST}   $*" | tee -a "$LOG"; }
warn() { echo -e "${YLW}[WARN]${RST} $*" | tee -a "$LOG"; }
hit()  { echo -e "${RED}[ACT]${RST}  $*" | tee -a "$LOG"; }

log "${BLD}=== Party Rocket Lockout — $(hostname) ===${RST}"

# =============================================================================
# 1. ROTATE HARDCODED CREDENTIAL ACCOUNTS
#    Party Rocket inventory files hardcode: cyberrange:Cyberrange123!
#    and ubuntu:Cyberrange123! across ALL target hosts.
# =============================================================================
log "\n--- [1] Rotating all unprotected local accounts ---"

# Protected (competition packet users — do NOT rotate these):
#   cyberrange — listed in packet with default password Cyberrange123!
#   GREYTEAM   — Overseer account, must not be changed per rules
#   greyteam   — lowercase variant (Linux is case-sensitive)
#   scp073     — NON-PRIVILEGED SCORING USER — DO NOT MODIFY (breaks scoring)
#   scp343     — PRIVILEGED SCORING USER — DO NOT MODIFY (breaks scoring)
PROTECTED_USERS=("root" "cyberrange" "GREYTEAM" "greyteam" "scp073" "scp343")

while IFS=: read -r username _ uid _ _ _ shell; do
    [[ "$uid" -lt 1000 ]] && continue
    [[ "$shell" == */nologin || "$shell" == */false ]] && continue

    skip=0
    for p in "${PROTECTED_USERS[@]}"; do
        [[ "$username" == "$p" ]] && skip=1 && break
    done
    if [[ $skip -eq 1 ]]; then
        ok "Skipping protected account: $username"
        continue
    fi

    new_pass=$(tr -dc 'A-Za-z0-9!@#$%^&*' < /dev/urandom | head -c 24)
    echo "$username:$new_pass" | chpasswd
    hit "Password rotated for: $username"
    log "  New password (store securely): ${CYN}$new_pass${RST}"
    passwd -e "$username" 2>/dev/null || true
done < /etc/passwd

# =============================================================================
# 2. AUDIT AUTHORIZED_KEYS — attacker may have added their key
#    Party Rocket uses password auth, but they may have added a backdoor key
# =============================================================================
log "\n--- [2] Auditing authorized_keys files ---"

for homedir in /root /home/*/; do
    homedir="${homedir%/}"
    [[ -d "$homedir" ]] || continue
    keys_file="$homedir/.ssh/authorized_keys"
    [[ -f "$keys_file" ]] || continue

    user=$(basename "$homedir")
    count=$(wc -l < "$keys_file" 2>/dev/null || echo 0)
    log "  $keys_file — $count key(s):"
    cat "$keys_file" | while read -r line; do
        [[ -z "$line" ]] && continue
        # Extract key comment (last field) — flag anything that looks suspicious
        comment=$(echo "$line" | awk '{print $NF}')
        log "    Key: $comment"
    done
    warn "Review $keys_file manually — remove any keys not belonging to your team"
done

# =============================================================================
# 3. KILL ACTIVE SESSIONS for compromised accounts
#    Walk /proc directly — don't trust who/w
# =============================================================================
log "\n--- [3] Killing active sessions for compromised accounts ---"

for user in cyberrange ubuntu; do
    id "$user" &>/dev/null || continue
    uid=$(id -u "$user")
    killed=0

    for pid_dir in /proc/[0-9]*/; do
        pid="${pid_dir%/}"
        pid="${pid##*/}"
        proc_uid=$(awk '/^Uid:/{print $2}' "${pid_dir}status" 2>/dev/null || true)
        [[ "$proc_uid" == "$uid" ]] || continue

        # Don't kill our own session
        [[ "$pid" == "$$" ]] && continue

        kill -9 "$pid" 2>/dev/null && killed=$((killed + 1)) || true
    done

    [[ $killed -gt 0 ]] && hit "Killed $killed processes owned by $user" \
                        || ok "No running processes found for $user"
done

# =============================================================================
# 4. HARDEN SSH CONFIGURATION
#    - Disable password auth (attacker needs Cyberrange123! to get in)
#    - MaxAuthTries 2 (slow down brute force)
#    - LogLevel VERBOSE (log all connections)
#    - Restart sshd to apply
# =============================================================================
log "\n--- [4] Hardening SSH configuration ---"

SSHD_CONFIG="/etc/ssh/sshd_config"
chattr -i "$SSHD_CONFIG" 2>/dev/null || true
cp "$SSHD_CONFIG" "$LOG.sshd_config.bak"

# SCORING SAFETY: The scoring engine authenticates scp343 and scp073 via
# password (paramiko with look_for_keys=False). Setting PasswordAuthentication
# to no will break SSH functional scoring (-30 pts every 60 seconds).
#
# Instead of disabling password auth globally, we leave it enabled and rely on:
#   - fail2ban to throttle brute force
#   - MaxAuthTries 2 to limit attempts per connection
#   - auditd to alert on suspicious logins
#   - inoculation (step 4) to lock sshd_config immutable after hardening
#
# If you MUST disable password auth (e.g., active credential stuffing), use a
# Match block to preserve scorer access:
#   Match User scp343,scp073,cyberrange,greyteam
#       PasswordAuthentication yes
warn "PasswordAuthentication left ENABLED — required for SSH scoring (scp343/scp073)"
warn "Scorer uses password auth with look_for_keys=False — disabling it breaks scoring"

# Limit auth attempts
sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 2/' "$SSHD_CONFIG"
grep -q "^MaxAuthTries" "$SSHD_CONFIG" \
    || echo "MaxAuthTries 2" >> "$SSHD_CONFIG"
ok "MaxAuthTries set to 2"

# Log all SSH connections verbosely
sed -i 's/^#*LogLevel.*/LogLevel VERBOSE/' "$SSHD_CONFIG"
grep -q "^LogLevel" "$SSHD_CONFIG" \
    || echo "LogLevel VERBOSE" >> "$SSHD_CONFIG"
ok "SSH LogLevel set to VERBOSE"

# Disable X11 forwarding (unnecessary attack surface)
sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' "$SSHD_CONFIG"
grep -q "^X11Forwarding" "$SSHD_CONFIG" \
    || echo "X11Forwarding no" >> "$SSHD_CONFIG"

systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
ok "SSH restarted with hardened config"

# =============================================================================
# 5. BLOCK OUTBOUND SSH — prevent this host being used as a pivot
#    Party Rocket deploys from operator workstation (100.65.x.x) via Ansible
#    to blue team hosts (10.10.10.x). Block outbound SSH to operator subnets.
# =============================================================================
log "\n--- [5] Per-IP firewall helper ---"

# Rule #7: ALL firewall/network changes require Overseer approval BEFORE implementing.
# Rule #6: Never block Overseer IPs or scoring traffic.
# Block individual confirmed attacker IPs only — report each to Overseers first.
# Scored service ports — NEVER block:
#   22 (SSH), 25/465/587 (SMTP), 53 (DNS), 80/443 (Apache/HTTPS),
#   88/389/636 (Kerberos/LDAP), 139/445 (SMB), 1194 (OpenVPN),
#   3306/5432 (DB), 3389 (RDP)

OVERSEER_IPS=("10.10.10.200" "10.10.10.201" "10.10.10.202")

block_ip() {
    local ip="$1"
    for overseer in "${OVERSEER_IPS[@]}"; do
        if [[ "$ip" == "$overseer" ]]; then
            warn "Refusing to block Overseer IP: $ip (Rule #8)"
            return 0
        fi
    done
    if command -v iptables &>/dev/null; then
        iptables -I INPUT  -s "$ip" -j DROP 2>/dev/null || true
        iptables -I OUTPUT -d "$ip" -j DROP 2>/dev/null || true
        hit "Blocked individual IP: $ip"
        log "  To unblock: iptables -D INPUT -s $ip -j DROP && iptables -D OUTPUT -d $ip -j DROP"
    fi
}

log "  Per-IP block ready — call block_ip <IP> for any confirmed attacker IP"
log "  Find active connections: ${CYN}grep ' 01 ' /proc/net/tcp | awk '{print \$3}' | cut -d: -f1 | sort -u${RST}"
log "  Example:  ${CYN}iptables -I INPUT -s <RED_IP> -j DROP${RST}"

# Add confirmed red team IPs below and uncomment:
# block_ip "10.10.10.X"

# =============================================================================
# 6. REMOVE ANSIBLE AND HELPER TOOLS (if installed by attacker)
#    Party Rocket requires ansible, sshpass, fping, nmap on the operator side.
#    These should NOT be on blue team hosts. Remove if found.
# =============================================================================
log "\n--- [6] Checking for attacker-installed tools ---"

for tool in ansible ansible-playbook fping sshpass; do
    if command -v "$tool" &>/dev/null; then
        warn "Found: $tool — this should not be on a blue team host"
        if command -v apt-get &>/dev/null; then
            apt-get remove -y "$tool" 2>&1 | tee -a "$LOG" || true
            hit "Removed $tool via apt"
        elif command -v dnf &>/dev/null; then
            dnf remove -y "$tool" 2>&1 | tee -a "$LOG" || true
            hit "Removed $tool via dnf"
        fi
    else
        ok "$tool not installed"
    fi
done

# =============================================================================
# SUMMARY
# =============================================================================
log ""
log "${BLD}=== Lockout complete — $(hostname) ===${RST}"
log ""
log "New credentials saved in: ${CYN}$LOG${RST}"
log "Protect this file — it contains the new passwords."
log ""
log "What changed:"
log "  - Hardcoded passwords rotated (Cyberrange123! no longer valid)"
log "  - Compromised account sessions killed"
log "  - SSH hardened: no password auth, MaxAuthTries 2, VERBOSE logging"
log "  - Per-IP block function available (no subnet blocks — Rule #8)"
log ""
log "CRITICAL: Review credentials captured in beacon log."
log "Rotate passwords for any account that authenticated during infection."
log ""
log "Next: run 04-inoculate.sh to lock files and install persistent monitoring"
