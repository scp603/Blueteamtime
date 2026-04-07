#!/bin/bash
# OpenVPN Specific Hardening Script - SCP-OPENVPN-01
# Focus: Securing scoring ports (1194, 7505, telnet) and protecting keys
# still need to test

echo "[+] Securing OpenVPN sensitive files (excluding mgmt-pass)..."
# Lock down private keys to root read-only. 
# We explicitly avoid modifying /etc/openvpn/server/mgmt-pass.
find /etc/openvpn/server -type f -name "*.key" -exec chmod 400 {} \;
find /etc/openvpn/server -type f -name "*.crt" -exec chmod 644 {} \;

echo "[+] Hardening Firewalld for Scoring Ports..."
# Allow standard OpenVPN traffic (1194)
firewall-cmd --permanent --add-port=1194/udp
firewall-cmd --permanent --add-port=1194/tcp

# Restrict the OpenVPN Management Port (7505) and Telnet (23) to the Overseer subnet ONLY.
# This prevents Red Team from telnetting into the management interface to drop the VPN.
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.10.10.200/24" port port="7505" protocol="tcp" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.10.10.200/24" port port="23" protocol="tcp" accept'

# Ensure these ports aren't globally open elsewhere in the firewall
firewall-cmd --permanent --remove-port=7505/tcp 2>/dev/null
firewall-cmd --permanent --remove-port=23/tcp 2>/dev/null

firewall-cmd --reload
echo "[+] Firewall rules applied."

echo "[+] Restarting OpenVPN to verify functionality..."
systemctl restart openvpn*
systemctl status openvpn* | grep "Active:"

echo "[+] OpenVPN hardening complete."