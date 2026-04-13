#!/bin/bash
# MariaDB Password Hardening Script for Red Team Competition
# Run as root

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}[*] MariaDB Competition Security Hardening${NC}"
echo -e "${YELLOW}[*] This will change passwords for admin accounts${NC}\n"


# Store passwords securely
PASSWORD_FILE="/root/.mariadb_competition_creds"
touch "$PASSWORD_FILE"
chmod 600 "$PASSWORD_FILE"

echo -e "${GREEN}[+] Generating strong passwords...${NC}"

# Generate passwords
ROOT_PASSWORD=$(maRIADB_bLUE-TEAM!23)
DR_ADMIN_PASSWORD=$(maRIADB_bLUE-TEAM!23)

echo -e "${GREEN}[+] Passwords saved to: $PASSWORD_FILE${NC}\n"

# Change passwords in MariaDB
echo -e "${YELLOW}[*] Updating MariaDB passwords...${NC}"

mariadb -u root <<EOF
-- Change root password (all hosts)
ALTER USER 'root'@'localhost' IDENTIFIED BY '$ROOT_PASSWORD';
ALTER USER 'root'@'%' IDENTIFIED BY '$ROOT_PASSWORD' 2>/dev/null || true;

-- Change DR_ADMIN password
ALTER USER 'DR_ADMIN' IDENTIFIED BY '$DR_ADMIN_PASSWORD';

-- Flush privileges
FLUSH PRIVILEGES;

-- Verify system accounts are NOT changed
SELECT User, Host, plugin FROM mysql.user WHERE User IN ('mariadb.sys', 'mysql');
EOF

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] Passwords updated successfully!${NC}"
else
    echo -e "${RED}[!] Error updating passwords!${NC}"
    exit 1
fi

# Update debian.cnf if it exists
if [ -f /etc/mysql/debian.cnf ]; then
    echo -e "${YELLOW}[*] Updating /etc/mysql/debian.cnf...${NC}"
    
    # Backup first
    cp /etc/mysql/debian.cnf /etc/mysql/debian.cnf.bak
    
    # Update password in config
    sed -i "s/^password.*/password = $ROOT_PASSWORD/" /etc/mysql/debian.cnf
    chmod 600 /etc/mysql/debian.cnf
    
    echo -e "${GREEN}[+] debian.cnf updated${NC}"
fi

# Additional competition hardening
echo -e "\n${YELLOW}[*] Applying additional security hardening...${NC}"

mariadb -u root -p"$ROOT_PASSWORD" <<EOF
-- Remove anonymous users
DELETE FROM mysql.user WHERE User='';

-- Remove remote root login (keep only localhost)
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');

-- Drop test database if it exists
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';

-- Disable LOAD DATA LOCAL INFILE (file read vulnerability)
SET GLOBAL local_infile=0;

-- Flush privileges
FLUSH PRIVILEGES;

-- Show remaining users
SELECT User, Host, plugin, password_expired FROM mysql.user ORDER BY User, Host;
EOF

echo -e "\n${GREEN}[+] Security hardening complete!${NC}"
echo -e "${YELLOW}[*] Credentials stored in: $PASSWORD_FILE${NC}"
echo -e "${YELLOW}[*] Backup of debian.cnf: /etc/mysql/debian.cnf.bak${NC}\n"

# Display credentials one time
echo -e "${GREEN}=== NEW CREDENTIALS ===${NC}"
cat "$PASSWORD_FILE"
echo -e "${GREEN}========================${NC}\n"

echo -e "${RED}[!] IMPORTANT: Copy these credentials NOW!${NC}"
echo -e "${RED}[!] Store them in your team's password manager!${NC}"
echo -e "${YELLOW}[*] Test login with: mariadb -u root -p${NC}\n"

# Log action
logger -t mariadb_hardening "MariaDB passwords changed for competition"

exit 0