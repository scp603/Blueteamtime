#!/bin/bash

# === CONFIGURE THESE FIRST ===
APACHE_IP="10.10.10.101"          # SVC-APACHE-01
DC_IP="10.10.10.1"                # Domain Controller (if applicable)

# Grey Team IPs (scoring engine)
GREY_TEAM_IPS=("10.10.10.200" "10.10.10.201")

# Blue Team systems to block from MySQL
BLOCKED_IPS=("10.10.10.10" "10.10.10.11" "10.10.10.12")

# ============================

echo "[*] Installing UFW..."
apt update -y
apt install ufw -y

echo "[*] Resetting UFW..."
ufw --force reset

echo "[*] Setting default policies..."
ufw default deny incoming
ufw default allow outgoing

echo "[*] Allowing SSH (port 22)..."
ufw allow 22/tcp comment "SSH Access"

echo "[*] Allowing MySQL from Apache..."
ufw allow from $APACHE_IP to any port 3306 proto tcp comment "MySQL from Apache"

echo "[*] Allowing MySQL from Grey Team..."
for ip in "${GREY_TEAM_IPS[@]}"; do
    ufw allow from $ip to any port 3306 proto tcp comment "MySQL Grey Team"
done

echo "[*] Blocking MySQL from other Blue Team systems..."
for ip in "${BLOCKED_IPS[@]}"; do
    ufw deny from $ip to any port 3306 proto tcp comment "Blocked MySQL"
done

echo "[*] Blocking ICMP (ping)..."
ufw deny proto icmp

echo "[*] Allowing loopback traffic..."
ufw allow in on lo
ufw allow out on lo

echo "[*] Restricting DNS outbound to DC..."
ufw allow out to $DC_IP port 53 proto udp comment "DNS to DC"
ufw allow out to $DC_IP port 53 proto tcp comment "DNS to DC"

echo "[*] Enabling UFW..."
ufw --force enable

echo "[*] Final UFW status:"
ufw status verbose

echo "[+] Port hardening complete!"
echo "    - MySQL (3306): Allowed from Apache + Grey Team only"
echo "    - SSH (22): Allowed"
echo "    - ICMP: Blocked"