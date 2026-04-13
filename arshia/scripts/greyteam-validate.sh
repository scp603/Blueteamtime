#!/bin/bash

# === CONFIGURE THESE ===
GREY_TEAM_IPS=("10.10.10.200" "10.10.10.201")
# ======================

echo "[*] Installing UFW (if not already installed)..."
apt update -y
apt install -y ufw

echo "[*] Allowing MySQL (3306) access from Grey Team..."
for ip in "${GREY_TEAM_IPS[@]}"; do
    ufw allow from $ip to any port 3306 proto tcp comment "Grey Team MySQL"
done

echo "[*] Allowing ICMP (ping) from Grey Team..."
for ip in "${GREY_TEAM_IPS[@]}"; do
    ufw allow from $ip proto icmp comment "Grey Team ICMP"
done

echo "[*] Reloading UFW to apply rules..."
ufw reload

echo "[*] Current UFW rules:"
ufw status numbered

echo "[+] Grey Team access validation complete!"
echo "    - MySQL (3306) allowed from Grey Team IPs"
echo "    - ICMP allowed from Grey Team IPs"