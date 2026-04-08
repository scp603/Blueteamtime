#!/bin/bash

### Rocky Linux Service Audit Script

### Output file name
OUTPUT="service_audit_$(hostname)_$(date +%Y-%m-%d_%H-%M-%S).txt"

### Create output file
touch "$OUTPUT"

### Print to terminal and save to file
log() {
    echo "$1" | tee -a "$OUTPUT"
}

### Print alert message
alert() {
    echo "[ALERT] $1" | tee -a "$OUTPUT"
}

log "Rocky Linux Service Audit"
log "Host: $(hostname)"
log "Date: $(date)"
log ""

### Check SSH service
log "SSH Service"

SSH_STATUS=$(systemctl is-active sshd 2>/dev/null)

if [[ "$SSH_STATUS" == "active" ]]; then
    log "ACTIVE"
else
    alert "$SSH_STATUS"
fi

log ""

### Check OpenVPN service
log "OpenVPN Service"

VPN_STATUS=$(systemctl is-active openvpn-server@server 2>/dev/null)

if [[ "$VPN_STATUS" == "active" ]]; then
    log "ACTIVE"
else
    alert "$VPN_STATUS"
fi

log ""

### Print listening ports
log "Listening Ports"
ss -tulpn | tee -a "$OUTPUT"

log ""

### Verify SSH port
log "SSH Port Check"

if ss -tulpn | grep -q ":22 "; then
    log "Port 22 Open"
else
    alert "Port 22 Missing"
fi

log ""

### Verify VPN port
log "VPN Port Check"

if ss -tulpn | grep -q ":1194 "; then
    log "Port 1194 Open"
else
    alert "Port 1194 Missing"
fi

log ""

### Print active network connections
log "Active Connections"
ss -tunap | tee -a "$OUTPUT"

log ""

### Print running services
log "Running Services"
systemctl list-units --type=service --state=running | tee -a "$OUTPUT"

log ""

### Print top processes
log "Top Processes"
ps aux --sort=-%cpu | head -15 | tee -a "$OUTPUT"

log ""

### Final output location
log "Saved To: $OUTPUT"