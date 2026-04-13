#!/usr/bin/env bash
# =============================================================================
# fix-openvpn.sh — Restore OpenVPN scoring on SCP-OPENVPN-01 (10.10.10.104, Rocky)
#
# Scoring requires:
#   1. UDP 1194 responds to OpenVPN probe
#   2. SSH into host as scorer user → nc 127.0.0.1 7505 returns management status
#
# Common breaks:
#   - openvpn service stopped/crashed
#   - server.conf deleted/corrupted
#   - PKI certs missing or permissions wrong
#   - management interface not configured (missing mgmt-pass)
#   - firewalld blocking 1194/udp
#   - root password empty (passwordless root) — not scoring-relevant but fix anyway
#   - sshd broken (needed for management check via SSH)
#   - scorer user missing or password wrong
#
# Run as root on 10.10.10.104.
# =============================================================================

set -uo pipefail

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLD='\033[1m'
RST='\033[0m'

[[ $EUID -ne 0 ]] && { echo "Run as root" >&2; exit 1; }

ok()   { echo -e "${GRN}[OK]${RST}   $*"; }
fix()  { echo -e "${YLW}[FIX]${RST}  $*"; }
err()  { echo -e "${RED}[ERR]${RST}  $*"; }

echo -e "${BLD}=== OpenVPN Break-Fix — $(hostname) ===${RST}\n"

# ─── Strip immutable bits ────────────────────────────────────────────────────
for f in /etc/openvpn/server/server.conf /etc/ssh/sshd_config /etc/passwd /etc/shadow; do
    chattr -i "$f" 2>/dev/null || true
done

# ─── Fix root password (Grey Team left it empty = passwordless root SSH) ─────
# Set a strong root password. This doesn't affect scoring but closes a huge hole.
if awk -F: '$1=="root" && $2=="" {found=1} END{exit !found}' /etc/shadow 2>/dev/null; then
    echo "root:$(tr -dc 'A-Za-z0-9!@#$%^&*' < /dev/urandom | head -c 24)" | chpasswd
    fix "Root had empty password — set random password"
fi

# ─── Fix /etc/passwd (bin user has wrong shell) ──────────────────────────────
if grep -q '/usr/sbin/bin/bash' /etc/passwd; then
    sed -i 's|/usr/sbin/bin/bash|/usr/sbin/nologin|g' /etc/passwd
    fix "Fixed bin user shell path"
fi

# ─── Ensure scored/system users exist ────────────────────────────────────────
ensure_user() {
    local user="$1" pass="$2"
    if ! id "$user" &>/dev/null; then
        useradd -m -s /bin/bash "$user"
        fix "Created missing user: $user"
    fi
    passwd -u "$user" 2>/dev/null || true
    usermod -s /bin/bash "$user" 2>/dev/null || true
    echo "$user:$pass" | chpasswd
    ok "User $user: exists, unlocked, password set"
}

ensure_user "cyberrange" "Cyberrange123!"
ensure_user "ntf" "s3cuRe-c0n+a1n-Pr0tecT"
ensure_user "scp073" "abel_is_dead"
ensure_user "scp343" "4ll-p0w3rfuL"

# The scoring engine SSHes in as "scorer" to query management.
# Check if scorer user is configured in the .env — if not, cyberrange is the fallback.
# Create scorer if it doesn't exist (the scoring vars reference openvpn_ssh_user: "scorer")
if ! id scorer &>/dev/null; then
    useradd -m -s /bin/bash scorer
    fix "Created scorer user for management check"
fi
# Set a known password — update scoring .env to match if needed
echo "scorer:Cyberrange123!" | chpasswd
ok "scorer user ready"

# ─── Ensure OpenVPN is installed ─────────────────────────────────────────────
if ! command -v openvpn &>/dev/null; then
    dnf install -y openvpn easy-rsa 2>&1 | tail -3
    fix "Installed openvpn package"
fi

# ─── Ensure PKI exists ──────────────────────────────────────────────────────
if [[ ! -f /etc/openvpn/pki/ca.crt ]]; then
    err "PKI missing — attempting to rebuild"
    mkdir -p /etc/openvpn/pki/{private,issued,reqs,certs}
    cd /etc/openvpn
    # Find easyrsa binary — path varies between Rocky versions
    EASYRSA=$(find /usr/share/easy-rsa -name easyrsa -type f 2>/dev/null | head -1)
    [[ -z "$EASYRSA" ]] && EASYRSA="/usr/share/easy-rsa/3/easyrsa"
    "$EASYRSA" --batch init-pki 2>/dev/null || true
    "$EASYRSA" --batch build-ca nopass 2>/dev/null || true
    "$EASYRSA" --batch build-server-full server nopass 2>/dev/null || true
    "$EASYRSA" --batch build-client-full client1 nopass 2>/dev/null || true
    "$EASYRSA" gen-dh 2>/dev/null || true
    fix "PKI rebuilt"
    cd /
fi

# ─── Ensure server.conf exists and is correct ────────────────────────────────
CONF="/etc/openvpn/server/server.conf"
mkdir -p /etc/openvpn/server

if [[ ! -f "$CONF" ]] || ! grep -q "^port 1194" "$CONF" 2>/dev/null; then
    cat > "$CONF" <<'VPNEOF'
port 1194
proto udp
dev tun

ca /etc/openvpn/pki/ca.crt
cert /etc/openvpn/pki/issued/server.crt
key /etc/openvpn/pki/private/server.key
dh /etc/openvpn/pki/dh.pem

management localhost 7505 /etc/openvpn/server/mgmt-pass
server 10.8.0.0 255.255.255.0
keepalive 10 120
persist-key
persist-tun

tls-version-min 1.0
tls-version-max 1.2
tls-cipher TLS-DHE-RSA-WITH-AES-128-CBC-SHA

verb 3
VPNEOF
    fix "Wrote server.conf"
fi

# ─── Ensure management password file exists ──────────────────────────────────
MGMT_PASS="/etc/openvpn/server/mgmt-pass"
if [[ ! -f "$MGMT_PASS" ]]; then
    echo "scp_mgmt_2026" > "$MGMT_PASS"
    chmod 600 "$MGMT_PASS"
    fix "Created management password file"
fi

# ─── IP forwarding ──────────────────────────────────────────────────────────
sysctl -w net.ipv4.ip_forward=1 >/dev/null
ok "IP forwarding enabled"

# ─── Firewall ───────────────────────────────────────────────────────────────
if command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --add-port=1194/udp 2>/dev/null || true
    firewall-cmd --permanent --add-service=ssh 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
    ok "firewalld: 1194/udp and SSH allowed"
fi
# Also clear any iptables blocks
if command -v iptables &>/dev/null; then
    while iptables -D INPUT -p udp --dport 1194 -j DROP 2>/dev/null; do :; done
    while iptables -D INPUT -p tcp --dport 22 -j DROP 2>/dev/null; do :; done
fi

# ─── Fix sshd (needed for scoring management check) ─────────────────────────
chattr -i /etc/ssh/sshd_config 2>/dev/null || true
# Ensure PasswordAuthentication is yes and PermitEmptyPasswords is no
if [[ -f /etc/ssh/sshd_config ]]; then
    sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^PermitEmptyPasswords yes/PermitEmptyPasswords no/' /etc/ssh/sshd_config
    # Make sure PasswordAuthentication is yes (scorer needs it)
    if grep -q "^PasswordAuthentication" /etc/ssh/sshd_config; then
        sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
    else
        echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
    fi
fi
# Fix SSH dir perms
chmod 755 /etc/ssh
chmod 644 /etc/ssh/sshd_config
chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null || true

# Clean PAM
for pf in /etc/pam.d/sshd /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    if [[ -f "$pf" ]]; then
        chattr -i "$pf" 2>/dev/null || true
        sed -i '/pam_exec.*ssh-auth-check/d' "$pf" 2>/dev/null || true
        sed -i '/pam_error_mod/d' "$pf" 2>/dev/null || true
    fi
done

if sshd -t 2>/dev/null; then
    systemctl restart sshd
    ok "sshd restarted"
else
    err "sshd config invalid — check sshd -t"
fi

# ─── Ensure nc (netcat) is available (scoring check uses it) ─────────────────
if ! command -v nc &>/dev/null; then
    dnf install -y nmap-ncat 2>&1 | tail -2
    fix "Installed ncat"
fi

# ─── Restart OpenVPN ─────────────────────────────────────────────────────────
systemctl enable openvpn-server@server 2>/dev/null || true
if systemctl restart openvpn-server@server 2>/dev/null; then
    ok "openvpn-server@server restarted"
else
    err "OpenVPN failed to start — check: journalctl -u openvpn-server@server"
    systemctl status openvpn-server@server --no-pager 2>&1 | tail -10
fi

# ─── Verify ──────────────────────────────────────────────────────────────────
sleep 1

if ss -ulnp | grep -q ':1194 '; then
    ok "UDP 1194 is listening"
else
    err "UDP 1194 NOT listening"
fi

if ss -tlnp | grep -q ':22 '; then
    ok "Port 22 is listening"
else
    err "Port 22 NOT listening"
fi

# Test management interface
if echo -e "status\nquit" | nc -w 3 127.0.0.1 7505 2>/dev/null | grep -qE "CLIENT_LIST|END|OpenVPN"; then
    ok "Management interface responding on 7505"
else
    err "Management interface not responding — check mgmt-pass and server.conf"
fi

echo -e "\n${BLD}=== OpenVPN break-fix complete ===${RST}"
