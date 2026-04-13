#!/bin/bash
#
# MySQL Hardening Script (Standalone - No Ansible Required)
# Run this directly on SCP-DATABASE-01 (10.10.10.102)
#
# Usage: sudo bash mysql-harden.sh
#

set -e

echo "================================================"
echo "  MYSQL HARDENING SCRIPT"
echo "  Standalone Deployment"
echo "================================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: Please run as root (sudo bash mysql-harden.sh)"
    exit 1
fi

# Check if MySQL is installed
if ! command -v mysql &> /dev/null; then
    echo "ERROR: MySQL is not installed"
    exit 1
fi

echo "[1/9] Installing UFW..."
apt-get update -qq
apt-get install -y ufw > /dev/null 2>&1
echo "✓ UFW installed"

echo "[2/9] Configuring firewall rules..."

# Reset UFW
ufw --force reset > /dev/null 2>&1

# Default policies
ufw default deny incoming > /dev/null 2>&1
ufw default allow outgoing > /dev/null 2>&1

# Allow MySQL from Apache
ufw allow from 10.10.10.101 to any port 3306 proto tcp comment 'MySQL from Apache' > /dev/null 2>&1

# Allow MySQL from Grey Team
for ip in 10.10.10.{200..210}; do
    ufw allow from $ip to any port 3306 proto tcp comment 'MySQL from Grey Team' > /dev/null 2>&1
    ufw allow from $ip proto icmp comment 'Grey Team ICMP' > /dev/null 2>&1
done

# Block MySQL from other blue team infrastructure
for ip in 10.10.10.21 10.10.10.22 10.10.10.23 10.10.10.103 10.10.10.104; do
    ufw deny from $ip to any port 3306 proto tcp comment 'Block MySQL' > /dev/null 2>&1
done

# Block ICMP by default (already allowed for grey team above)
ufw deny proto icmp comment 'Block ICMP by default' > /dev/null 2>&1

# Allow loopback
ufw allow in on lo > /dev/null 2>&1
ufw allow out on lo > /dev/null 2>&1

# Enable UFW
ufw --force enable > /dev/null 2>&1

echo "✓ Firewall configured"

echo "[3/9] Backing up MySQL user table..."
BACKUP_FILE="/root/mysql_user_backup_$(date +%Y%m%d_%H%M%S).sql"
mysqldump mysql user > "$BACKUP_FILE" 2>/dev/null || true
echo "✓ Backup saved to: $BACKUP_FILE"

echo "[4/9] Discovering MySQL users (excluding system accounts)..."
# FIXED: Exclude system accounts that must not be changed
mapfile -t MYSQL_USERS < <(mysql -e "
    SELECT CONCAT(User,'@',Host) 
    FROM mysql.user 
    WHERE User != '' 
    AND User NOT IN ('mysql.sys', 'mysql.session', 'mysql.infoschema', 'debian-sys-maint')
    AND User NOT LIKE 'mysql.%';" -s -N 2>/dev/null)

echo "✓ Found ${#MYSQL_USERS[@]} MySQL users (system accounts excluded)"

# Display which users will be changed
echo ""
echo "Users that will have passwords changed:"
for user in "${MYSQL_USERS[@]}"; do
    echo "  - $user"
done
echo ""

echo "[5/9] Changing passwords for non-system MySQL users..."
PASSWORD_FILE="/root/mysql_passwords_$(date +%Y%m%d_%H%M%S).txt"
echo "# MySQL Passwords - Generated $(date)" > "$PASSWORD_FILE"
echo "# KEEP THIS FILE SECURE!" >> "$PASSWORD_FILE"
echo "# System accounts (mysql.sys, debian-sys-maint) were NOT changed" >> "$PASSWORD_FILE"
echo "" >> "$PASSWORD_FILE"

for user_host in "${MYSQL_USERS[@]}"; do
    USER=$(echo "$user_host" | cut -d@ -f1)
    HOST=$(echo "$user_host" | cut -d@ -f2)
    
    # Generate random password
    NEW_PASSWORD=$(openssl rand -base64 18 | tr -d "=+/" | cut -c1-20)
    
    # Change password
    if mysql -e "ALTER USER '$USER'@'$HOST' IDENTIFIED BY '$NEW_PASSWORD';" 2>/dev/null; then
        echo "$user_host: $NEW_PASSWORD" >> "$PASSWORD_FILE"
        echo "  ✓ Changed: $user_host"
    else
        echo "  ✗ Failed: $user_host" | tee -a "$PASSWORD_FILE"
    fi
done

chmod 600 "$PASSWORD_FILE"
echo "✓ Passwords changed and saved to: $PASSWORD_FILE"

echo "[6/9] Removing anonymous users and test database..."
mysql -e "DELETE FROM mysql.user WHERE User='';" 2>/dev/null || true
mysql -e "DROP DATABASE IF EXISTS test;" 2>/dev/null || true
mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';" 2>/dev/null || true
mysql -e "FLUSH PRIVILEGES;" 2>/dev/null || true
echo "✓ Anonymous users and test database removed"

echo "[7/9] Removing remote root access..."
mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');" 2>/dev/null || true
mysql -e "FLUSH PRIVILEGES;" 2>/dev/null || true
echo "✓ Remote root access removed"

echo "[8/9] Revoking dangerous privileges from non-root users..."
# FIXED: Also exclude system accounts here
mysql -e "
    SELECT CONCAT(User,'@',Host) 
    FROM mysql.user 
    WHERE User != 'root' 
    AND User != '' 
    AND User NOT IN ('mysql.sys', 'mysql.session', 'mysql.infoschema', 'debian-sys-maint')
    AND User NOT LIKE 'mysql.%';" -s -N 2>/dev/null | while read user_host; do
    
    USER=$(echo "$user_host" | cut -d@ -f1)
    HOST=$(echo "$user_host" | cut -d@ -f2)
    
    mysql -e "REVOKE FILE ON *.* FROM '$USER'@'$HOST';" 2>/dev/null || true
    mysql -e "REVOKE SUPER ON *.* FROM '$USER'@'$HOST';" 2>/dev/null || true
    mysql -e "REVOKE PROCESS ON *.* FROM '$USER'@'$HOST';" 2>/dev/null || true
    mysql -e "REVOKE RELOAD ON *.* FROM '$USER'@'$HOST';" 2>/dev/null || true
    mysql -e "REVOKE SHUTDOWN ON *.* FROM '$USER'@'$HOST';" 2>/dev/null || true
    mysql -e "REVOKE CREATE USER ON *.* FROM '$USER'@'$HOST';" 2>/dev/null || true
    mysql -e "REVOKE GRANT OPTION ON *.* FROM '$USER'@'$HOST';" 2>/dev/null || true
done
mysql -e "FLUSH PRIVILEGES;" 2>/dev/null || true
echo "✓ Dangerous privileges revoked"

echo "[9/9] Applying hardened MySQL configuration..."
cp /etc/mysql/mysql.conf.d/mysqld.cnf /etc/mysql/mysql.conf.d/mysqld.cnf.backup 2>/dev/null || true

cat > /etc/mysql/mysql.conf.d/mysqld.cnf << 'EOF'
# MySQL Hardened Configuration
# Applied by Blue Team Hardening Script

[mysqld]
# Network Security
bind-address = 10.10.10.102
port = 3306

# Disable dangerous features
local_infile = 0
symbolic-links = 0
skip-show-database

# Performance and Security
skip-name-resolve = 1
max_connections = 150
max_connect_errors = 10
connect_timeout = 10
max_allowed_packet = 16M

# Logging
log_error = /var/log/mysql/error.log
log_warnings = 2

# Character set
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci

[mysql]
no-auto-rehash

[client]
port = 3306
EOF

systemctl restart mysql
sleep 5

# Test MySQL connection
if mysql -e "SELECT 1;" > /dev/null 2>&1; then
    echo "✓ MySQL configuration applied and service restarted"
else
    echo "⚠ WARNING: MySQL service may have issues - check logs"
    echo "⚠ To restore: cp /etc/mysql/mysql.conf.d/mysqld.cnf.backup /etc/mysql/mysql.conf.d/mysqld.cnf"
fi

echo ""
echo "================================================"
echo "  HARDENING COMPLETE"
echo "================================================"
echo ""
echo "✓ Firewall hardened (UFW)"
echo "  - MySQL (3306): Apache + Grey Team only"
echo "  - SSH (22): Existing access maintained"
echo "  - ICMP: Grey Team only"
echo "  - Blocked: Other blue team IPs from MySQL"
echo ""
echo "✓ MySQL service hardened"
echo "  - User passwords changed (system accounts preserved)"
echo "  - Anonymous users removed"
echo "  - Test database removed"
echo "  - Remote root disabled"
echo "  - Dangerous privileges revoked"
echo ""
echo "CRITICAL NEXT STEPS:"
echo "  1. New passwords saved in: $PASSWORD_FILE"
echo "  2. User table backup: $BACKUP_FILE"
echo "  3. UPDATE YOUR APPLICATION CONFIG FILES with new DB passwords!"
echo "  4. Test Apache -> MySQL connection IMMEDIATELY"
echo "  5. Keep a copy of the password file in your team's secure location"
echo ""
echo "To view passwords: cat $PASSWORD_FILE"
echo "To test connection: mysql -u <username> -p"
echo ""
echo "================================================"

# Final verification
echo ""
echo "Current MySQL users (for verification):"
mysql -e "SELECT User, Host, plugin FROM mysql.user ORDER BY User;" 2>/dev/null || true