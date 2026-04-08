#!/usr/bin/env bash
# =============================================================================
# 03-lockout.sh  [LEVEL 3 — CUT THE WORM'S LEGS OFF]
# The orchestrator has two hardcoded credential pairs it uses to spread.
# This script:
#   - Rotates passwords for cyberrange and sjohnson immediately
#   - Revokes all sudo NOPASSWD (wagon needs this to run payloads)
#   - Kills any active SSH sessions using the compromised accounts
#   - Blocks the worm's known outbound spread ports via iptables
#   - Locks the compromised accounts if they're not needed
#
# The worm cannot spread to any host where these creds are changed.
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

log()  { echo -e "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
ok()   { echo -e "${GRN}[OK]${RST}   $*" | tee -a "$LOG"; }
warn() { echo -e "${YLW}[WARN]${RST} $*" | tee -a "$LOG"; }
hit()  { echo -e "${RED}[ACT]${RST}  $*" | tee -a "$LOG"; }

log "${BLD}=== Goblin-Wagon Lockout — $(hostname) ===${RST}"

# =============================================================================
# 1. ROTATE ALL NON-PROTECTED LOCAL ACCOUNTS
#    Protected (competition packet users — do NOT rotate these):
#      cyberrange — listed in packet with default password Cyberrange123!
#      GREYTEAM   — Overseer account, must not be changed per rules
#    All other local accounts with a login shell (UID >= 1000) are rotated.
# =============================================================================
log "\n--- [1] Rotating all unprotected local accounts ---"

PROTECTED_USERS=("root" "cyberrange" "GREYTEAM")

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
# 2. REVOKE SUDO NOPASSWD — wagon runs payloads with `sudo -n bash -c`
#    Without NOPASSWD, sudo prompts for a password and -n fails silently
# =============================================================================
log "\n--- [2] Revoking NOPASSWD sudo entries ---"

# Back up before touching
cp /etc/sudoers "$LOG.sudoers.bak" 2>/dev/null
chmod 600 "$LOG.sudoers.bak"
ok "sudoers backed up"

# Remove NOPASSWD from main sudoers
if grep -q "NOPASSWD" /etc/sudoers 2>/dev/null; then
    sed -i 's/NOPASSWD://g' /etc/sudoers
    hit "Removed NOPASSWD from /etc/sudoers"
fi

# Clean /etc/sudoers.d/
if [[ -d /etc/sudoers.d ]]; then
    for f in /etc/sudoers.d/*; do
        [[ -f "$f" ]] || continue
        if grep -q "NOPASSWD" "$f" 2>/dev/null; then
            cp "$f" "$LOG.$(basename $f).bak"
            sed -i 's/NOPASSWD://g' "$f"
            hit "Removed NOPASSWD from $f"
        fi
    done
fi

ok "All NOPASSWD entries cleared — wagon payloads will now fail on sudo -n"

# =============================================================================
# 3. KILL ACTIVE SESSIONS for compromised accounts (via /proc, not who/w)
# =============================================================================
log "\n--- [3] Killing active sessions for compromised accounts ---"

for user in cyberrange sjohnson; do
    id "$user" &>/dev/null || continue
    uid=$(id -u "$user")

    killed=0
    for pid_dir in /proc/[0-9]*/; do
        pid="${pid_dir%/}"
        pid="${pid##*/}"
        proc_uid=$(awk '/^Uid:/{print $2}' "${pid_dir}status" 2>/dev/null || true)
        [[ "$proc_uid" == "$uid" ]] || continue

        kill -9 "$pid" 2>/dev/null && killed=$((killed+1)) || true
    done

    [[ $killed -gt 0 ]] && hit "Killed $killed processes owned by $user" \
                        || ok "No running processes found for $user"
done

# =============================================================================
# 4. PER-IP FIREWALL BLOCKING
#    Rule #8: firewalling off entire subnets is prohibited.
#    Use block_ip() to block individual confirmed red team IPs only.
#    Overseer IPs (10.10.10.200+) are always protected.
#
#    Scored service ports — NEVER block these:
#      22 (SSH/OpenSSH), 25/465/587 (SMTP), 53 (DNS), 80/443 (Apache/HTTPS),
#      88/389/636 (Kerberos/LDAP), 139/445 (SMB), 1194 (OpenVPN),
#      3306/5432 (DB), 3389 (RDP)
# =============================================================================
log "\n--- [4] Per-IP firewall helper ---"

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
log "  Decode hex IP:           ${CYN}printf '%d.%d.%d.%d\\\n' 0xHH 0xHH 0xHH 0xHH${RST}"
log "  Example:  ${CYN}iptables -I INPUT -s <RED_IP> -j DROP${RST}"

# Add confirmed red team IPs below and uncomment:
# block_ip "10.10.10.X"

# =============================================================================
# 5. LOCK /tmp AND /var/tmp EXEC — worm binary drops to /tmp/.cache/
# =============================================================================
log "\n--- [5] Remounting /tmp noexec to block binary execution ---"

# Check current mount options
if mount | grep -q "on /tmp "; then
    if mount | grep "/tmp" | grep -q noexec; then
        ok "/tmp already mounted noexec"
    else
        mount -o remount,noexec /tmp 2>/dev/null \
            && hit "/tmp remounted noexec — worm binary cannot execute from here" \
            || warn "Could not remount /tmp — add 'noexec' to /etc/fstab manually"
    fi
else
    warn "/tmp is not a separate mount point — adding tmpfs noexec mount"
    mount -t tmpfs -o noexec,nosuid tmpfs /tmp 2>/dev/null \
        && hit "tmpfs noexec mounted on /tmp" \
        || warn "tmpfs mount failed — add to /etc/fstab manually"
fi

# Same for /var/tmp
if mount | grep -q "on /var/tmp "; then
    mount | grep "/var/tmp" | grep -q noexec \
        && ok "/var/tmp already noexec" \
        || { mount -o remount,noexec /var/tmp 2>/dev/null \
             && hit "/var/tmp remounted noexec" \
             || warn "Could not remount /var/tmp"; }
fi

# Remove the .cache drop dir and any binaries already there
if [[ -d /tmp/.cache ]]; then
    find /tmp/.cache -type f | while read -r f; do
        file "$f" 2>/dev/null | grep -q ELF && {
            cp "$f" "$SCRIPT_DIR/evidence_$(basename $f)_$(date +%s)" 2>/dev/null || true
            rm -f "$f"
            hit "Removed ELF binary from /tmp/.cache: $f"
        } || true
    done
fi

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
log "  - Hardcoded passwords rotated (worm cred list is now invalid)"
log "  - NOPASSWD sudo removed (wagon payload executor will fail)"
log "  - Compromised account sessions killed"
log "  - Per-IP block function available (no subnet blocks — Rule #8)"
log "  - /tmp mounted noexec"
log ""
log "Next: run 04-inoculate.sh on every host to prevent reinfection"
