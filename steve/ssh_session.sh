#!/bin/bash

### SSH User Source IP Audit Script

### Output file name
OUTPUT="ssh_user_ip_audit_$(hostname)_$(date +%Y-%m-%d_%H-%M-%S).txt"

### Create output file
touch "$OUTPUT"

### Print and save normal output
log() {
    echo "$1" | tee -a "$OUTPUT"
}

### Print and save alert output
alert() {
    echo "[ALERT] $1" | tee -a "$OUTPUT"
}

### Approved IP list
ALLOWED_IPS=(
    "10.10.10.21"
    "10.10.10.22"
    "10.10.10.23"
    "10.10.10.41"
    "10.10.10.42"
    "10.10.10.43"
    "10.10.10.44"
    "10.10.10.45"
)

### Function to check approved IPs
is_allowed_ip() {
    local ip="$1"

    ### Check approved Blue Team IPs
    for allowed in "${ALLOWED_IPS[@]}"; do
        if [[ "$ip" == "$allowed" ]]; then
            return 0
        fi
    done

    ### Allow Grey Team / Overseer IPs above 200
    if [[ "$ip" =~ ^10\.10\.10\.([0-9]+)$ ]]; then
        OCTET="${BASH_REMATCH[1]}"

        if (( OCTET >= 200 )); then
            return 0
        fi
    fi

    return 1
}

### Print header
log "SSH User / IP Audit"
log "Host: $(hostname)"
log "Date: $(date)"
log ""

### Read active SSH sessions from who
while read -r USER TTY DATE TIME IP
do

    ### Skip blank lines
    [[ -z "$USER" ]] && continue

    ### Remove parentheses from IP
    CLEAN_IP=$(echo "$IP" | tr -d '()')

    ### Check if IP is approved
    if is_allowed_ip "$CLEAN_IP"; then
        log "User: $USER | TTY: $TTY | Source IP: $CLEAN_IP"
    else
        alert "User: $USER | TTY: $TTY | Unapproved IP: $CLEAN_IP"
    fi

done < <(who)

### Print save location
log ""
log "Saved To: $OUTPUT"