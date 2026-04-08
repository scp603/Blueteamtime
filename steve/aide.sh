#!/bin/bash

### AIDE setup script for Rocky Linux
### Installs AIDE
### Adds important folders/files to monitor
### Initializes the AIDE database

CONFIG="/etc/aide.conf"
BACKUP="/etc/aide.conf.bak_$(date +%Y-%m-%d_%H-%M-%S)"

echo "Installing AIDE..."
sudo dnf install -y aide

if [[ $? -ne 0 ]]; then
    echo "AIDE install failed"
    exit 1
fi

### Backup current config
if [[ -f "$CONFIG" ]]; then
    sudo cp "$CONFIG" "$BACKUP"
    echo "Backed up existing config to $BACKUP"
fi

### Add custom monitor rules
sudo tee -a "$CONFIG" > /dev/null <<'EOF'

### Competition monitoring rules
/etc/ssh NORMAL
/etc/openvpn NORMAL
/etc/passwd NORMAL
/etc/group NORMAL
/etc/shadow NORMAL
/etc/sudoers NORMAL
/etc/sudoers.d NORMAL
/etc/systemd/system NORMAL
/usr/sbin NORMAL
/usr/bin NORMAL

### Ignore noisy paths
!/tmp
!/var/tmp
!/dev/shm
!/proc
!/sys
!/run
EOF

echo "Added monitoring rules to $CONFIG"

### Initialize AIDE database
echo "Initializing AIDE database..."
sudo aide --init

if [[ -f /var/lib/aide/aide.db.new.gz ]]; then
    sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    echo "AIDE database initialized"
else
    echo "AIDE database not found after init"
    exit 1
fi

echo ""
echo "Setup complete"
echo "Run a check later with:"
echo "sudo aide --check"