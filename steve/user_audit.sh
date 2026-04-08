#!/bin/bash

### Rocky Linux User Audit Script
### Prints findings to terminal and saves to txt file
### Run with sudo ./user_audit.sh

APPROVED_USERS=(
    "root"
    "cyberrange"
    "GREYTEAM"
)

OUTPUT="user_audit_$(hostname)_$(date +%Y-%m-%d_%H-%M-%S).txt"

### Create output file
touch "$OUTPUT"

### Logging Function
log() {
    echo "$1" | tee -a "$OUTPUT"
}

### Alert Function
alert() {
    echo "[ALERT] $1" | tee -a "$OUTPUT"
}

### Check if user is approved
is_approved() {
    local user="$1"

    for approved in "${APPROVED_USERS[@]}"; do
        if [[ "$user" == "$approved" ]]; then
            return 0
        fi
    done

    return 1
}

### Header
log "======================================"
log "      ROCKY LINUX USER AUDIT"
log "======================================"
log "Hostname: $(hostname)"
log "Date: $(date)"
log ""

### Print all login-capable users
log "### LOGIN CAPABLE USERS ###"

awk -F: '
$7 ~ /(bash|sh|zsh)$/ {
    print $1 " | UID=" $3 " | HOME=" $6 " | SHELL=" $7
}
' /etc/passwd | tee -a "$OUTPUT"

log ""

### Flag unknown login users
log "### UNKNOWN USERS CHECK ###"

UNKNOWN_FOUND=0

while IFS=: read -r user x uid gid comment home shell
do
    if [[ "$shell" =~ (bash|sh|zsh)$ ]]; then

        if ! is_approved "$user"; then
            alert "Unknown Login User Found -> $user"
            UNKNOWN_FOUND=1
        fi

    fi

done < /etc/passwd

if [[ "$UNKNOWN_FOUND" -eq 0 ]]; then
    log "No Unknown Users Found."
fi

log ""

### Check UID 0 users
log "### UID 0 CHECK ###"

while IFS=: read -r user x uid gid comment home shell
do
    if [[ "$uid" -eq 0 ]]; then

        if [[ "$user" == "root" ]]; then
            log "Root Account Found -> $user"
        else
            alert "Non-Root UID 0 Account -> $user"
        fi

    fi

done < /etc/passwd

log ""

### Check wheel group
log "### WHEEL GROUP CHECK ###"

WHEEL_MEMBERS=$(getent group wheel | cut -d: -f4)

echo "$WHEEL_MEMBERS" | tr ',' '\n' | while read member
do
    if [[ -n "$member" ]]; then

        if is_approved "$member"; then
            log "Approved Wheel Member -> $member"
        else
            alert "Unexpected Wheel Member -> $member"
        fi

    fi
done

log ""

### Check home directory permissions
log "### HOME DIRECTORY PERMISSIONS ###"

while IFS=: read -r user x uid gid comment home shell
do
    if [[ -d "$home" ]]; then

        perms=$(stat -c "%a" "$home")

        log "$user -> $home -> $perms"

        last_digit=${perms: -1}

        if [[ "$last_digit" =~ [2367] ]]; then
            alert "World Writable Home Directory -> $user"
        fi

    fi

done < /etc/passwd

log ""
log "======================================"
log " Audit Complete"
log " Saved To: $OUTPUT"
log "======================================"