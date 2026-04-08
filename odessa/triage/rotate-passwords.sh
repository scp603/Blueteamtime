#!/usr/bin/env bash
# =============================================================================
# rotate-passwords.sh — Nine-Tailed Fox CDT Competition
#
# Rotates passwords for all local Linux users EXCEPT:
#   - root
#   - cyberrange    (packet-specified, scoring checks use Cyberrange123!)
#   - GREYTEAM      (Overseer account — must not be changed per rules)
#
# When the supplemental packet drops with additional scored local users,
# add them to PROTECTED_USERS before running.
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
LOG="$SCRIPT_DIR/passwords_$(hostname)_$(date +%Y%m%d_%H%M%S).log"

log()  { echo -e "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
ok()   { echo -e "${GRN}[OK]${RST}   $*" | tee -a "$LOG"; }
warn() { echo -e "${YLW}[WARN]${RST} $*" | tee -a "$LOG"; }
hit()  { echo -e "${RED}[ROT]${RST}  $*" | tee -a "$LOG"; }

# =============================================================================
# PROTECTED USERS — DO NOT ROTATE
#
# root:       obvious
# cyberrange: packet-defined user, scoring infra authenticates as Cyberrange123!
# GREYTEAM:   Overseer account — changing it violates competition rules
#
# ADD supplemental packet users here when that packet is released:
# e.g., PROTECTED_USERS+=("scp_admin" "d_class")
# =============================================================================
PROTECTED_USERS=("root" "cyberrange" "GREYTEAM")

log "${BLD}=== Password Rotation — $(hostname) ===${RST}"
log "Protected (skipped): ${PROTECTED_USERS[*]}"
log "Credentials will be saved to: ${CYN}$LOG${RST}"
log "${YLW}Protect this file.${RST}"
log ""

rotated=0
skipped=0

while IFS=: read -r username _x uid _gid _comment _home shell; do
    # Skip system accounts (UID < 1000)
    [[ "$uid" -ge 1000 ]] || continue

    # Skip accounts with no-login shells
    [[ "$shell" == */nologin || "$shell" == */false || "$shell" == */sync ]] && continue

    # Skip protected users
    skip=0
    for p in "${PROTECTED_USERS[@]}"; do
        [[ "$username" == "$p" ]] && skip=1 && break
    done
    if [[ $skip -eq 1 ]]; then
        ok "Skipping protected account: $username"
        skipped=$((skipped + 1))
        continue
    fi

    # Generate a strong random password
    new_pass=$(tr -dc 'A-Za-z0-9!@#$%^&*()-_=+[]{}' < /dev/urandom | head -c 28)

    echo "$username:$new_pass" | chpasswd 2>/dev/null \
        && hit "Rotated: $username" \
        || { warn "chpasswd failed for $username"; continue; }

    # Log the credential (this file should be read-protected after the script)
    log "  ${CYN}$username${RST}  →  $new_pass"

    rotated=$((rotated + 1))
done < /etc/passwd

log ""
log "${BLD}=== Rotation complete ===${RST}"
log "  Rotated:  $rotated account(s)"
log "  Skipped:  $skipped protected account(s)"
log ""

# Lock the credential log
chmod 600 "$LOG"
chattr +i "$LOG" 2>/dev/null && ok "Credential log locked immutable: $LOG" \
    || warn "Could not set immutable on log — protect it manually"

log ""
log "${YLW}NOTE: When the supplemental packet drops with additional local users,${RST}"
log "${YLW}add them to PROTECTED_USERS in this script before running on fresh boxes.${RST}"
log ""
log "To change a specific user later (while this file is immutable):"
log "  ${CYN}chattr -i $LOG${RST}"
log "  then re-run or use:  ${CYN}passwd <username>${RST}"
