#!/usr/bin/env bash
# =============================================================================
# fix-ssh.sh — Restore SSH scoring on SCP-OPENSSH-01 (10.10.10.103, Rocky)
#
# Scoring requires:
#   1. Port 22 open, returns SSH-* banner
#   2. scp343 password auth → exec "echo SCP_OK" succeeds
#   3. scp073 password auth → exec "echo SCP_OK" succeeds
#
# Common breaks:
#   - sshd not running / crashed
#   - sshd_config syntax error
#   - sshd_config PasswordAuthentication no (blocks scored users)
#   - scp343 or scp073 account locked/deleted/password changed
#   - /etc/ssh permissions wrong (StrictModes fails)
#   - PAM misconfiguration blocking auth
#   - immutable bit on sshd_config preventing restart
#   - drbright persistence generator reinstalling bad config
#   - Port 22 firewalled
#
# Run as root on 10.10.10.103.
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

echo -e "${BLD}=== SSH Break-Fix — $(hostname) ===${RST}\n"

# ─── Kill drbright persistence before anything else ──────────────────────────
PERSIST="/usr/lib/systemd/system-generators/systemd-network-generator"
if [[ -f "$PERSIST" ]] && grep -q "drbright\|logrotate-check" "$PERSIST" 2>/dev/null; then
    rm -f "$PERSIST"
    fix "Removed drbright persistence generator"
    # Clean up generated units
    rm -f /run/systemd/generator/logrotate-check.service
    rm -rf /run/systemd/generator/systemd-tmpfiles-clean.timer.d
    rm -rf /run/systemd/generator/systemd-tmpfiles-clean.service.d
    systemctl daemon-reload
    # Delete the drbright user if it exists
    if id drbright &>/dev/null; then
        userdel -rf drbright 2>/dev/null || true
        fix "Removed drbright user"
    fi
fi

# ─── Strip immutable bits from SSH files ─────────────────────────────────────
chattr -i /etc/ssh/sshd_config 2>/dev/null || true
chattr -i /etc/ssh 2>/dev/null || true
for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow; do
    chattr -i "$f" 2>/dev/null || true
done

# ─── Ensure scored users exist with correct passwords ────────────────────────
ensure_user() {
    local user="$1" pass="$2" priv="$3"
    if ! id "$user" &>/dev/null; then
        useradd -m -s /bin/bash "$user"
        fix "Created missing user: $user"
    fi
    # Unlock the account
    passwd -u "$user" 2>/dev/null || true
    usermod -s /bin/bash "$user" 2>/dev/null || true
    # Set password
    echo "$user:$pass" | chpasswd
    # Add to wheel if privileged
    if [[ "$priv" == "yes" ]]; then
        usermod -aG wheel "$user" 2>/dev/null || true
    fi
    ok "User $user: exists, unlocked, password set"
}

ensure_user "scp073" "abel_is_dead" "no"
ensure_user "scp343" "4ll-p0w3rfuL" "yes"
ensure_user "cyberrange" "Cyberrange123!" "yes"
ensure_user "ntf" "s3cuRe-c0n+a1n-Pr0tecT" "yes"
# DO NOT touch greyteam password

# ─── Fix /etc/ssh permissions ────────────────────────────────────────────────
chmod 755 /etc/ssh
chmod 644 /etc/ssh/sshd_config
chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null || true
chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null || true
ok "SSH directory permissions fixed"

# ─── Regenerate host keys if missing ─────────────────────────────────────────
for ktype in rsa ecdsa ed25519; do
    if [[ ! -f "/etc/ssh/ssh_host_${ktype}_key" ]]; then
        ssh-keygen -t "$ktype" -f "/etc/ssh/ssh_host_${ktype}_key" -N "" -q
        fix "Regenerated missing ${ktype} host key"
    fi
done

# ─── Write a known-good sshd_config ─────────────────────────────────────────
# Scoring needs PasswordAuthentication yes for scp343/scp073
cat > /etc/ssh/sshd_config <<'SSHEOF'
# SCP-OPENSSH-01 — scoring-safe sshd_config
Include /etc/ssh/sshd_config.d/*.conf

Port 22
PermitRootLogin no
StrictModes yes
MaxAuthTries 6
MaxSessions 10

PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

PasswordAuthentication yes
PermitEmptyPasswords no
KbdInteractiveAuthentication yes

AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no

UsePAM yes
LogLevel VERBOSE

Subsystem sftp /usr/libexec/openssh/sftp-server
SSHEOF
ok "sshd_config written (PasswordAuth yes for scoring)"

# ─── Verify sshd_config syntax ──────────────────────────────────────────────
if sshd -t 2>/dev/null; then
    ok "sshd_config syntax valid"
else
    err "sshd_config syntax check failed — attempting minimal config"
    cat > /etc/ssh/sshd_config <<'MINEOF'
Port 22
PermitRootLogin no
PasswordAuthentication yes
PermitEmptyPasswords no
UsePAM yes
Subsystem sftp /usr/libexec/openssh/sftp-server
MINEOF
    if sshd -t 2>/dev/null; then
        fix "Minimal config passes syntax check"
    else
        err "Even minimal config fails — check sshd -t output manually"
    fi
fi

# ─── Clean up PAM if it's broken ────────────────────────────────────────────
# Remove any Red Team PAM hooks that might block auth
for pamfile in /etc/pam.d/sshd /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    if [[ -f "$pamfile" ]]; then
        chattr -i "$pamfile" 2>/dev/null || true
        sed -i '/pam_exec.*ssh-auth-check/d' "$pamfile" 2>/dev/null || true
        sed -i '/pam_error_mod/d' "$pamfile" 2>/dev/null || true
        sed -i '/pam_auth_mod/d' "$pamfile" 2>/dev/null || true
    fi
done
ok "PAM configs cleaned"

# ─── Ensure firewall allows port 22 ─────────────────────────────────────────
if command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --add-service=ssh 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
    ok "firewalld: SSH allowed"
elif command -v iptables &>/dev/null; then
    # Remove any DROP rules on port 22
    while iptables -D INPUT -p tcp --dport 22 -j DROP 2>/dev/null; do :; done
    while iptables -D INPUT -p tcp --dport 22 -j REJECT 2>/dev/null; do :; done
    ok "iptables: SSH DROP rules removed"
fi

# ─── Restart sshd ────────────────────────────────────────────────────────────
if systemctl restart sshd 2>/dev/null; then
    ok "sshd restarted successfully"
elif systemctl restart ssh 2>/dev/null; then
    ok "ssh restarted successfully"
else
    err "Failed to restart sshd — check: systemctl status sshd"
    # Try to start it if it wasn't running
    systemctl start sshd 2>/dev/null || systemctl start ssh 2>/dev/null || true
fi

# ─── Verify ──────────────────────────────────────────────────────────────────
if ss -tlnp | grep -q ':22 '; then
    ok "Port 22 is listening"
else
    err "Port 22 NOT listening after restart"
fi

echo -e "\n${BLD}=== SSH break-fix complete ===${RST}"
echo "Test: ssh scp343@localhost (password: 4ll-p0w3rfuL)"
echo "Test: ssh scp073@localhost (password: abel_is_dead)"
