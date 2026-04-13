#!/usr/bin/env bash
# =============================================================================
# fix-mysql.sh — Restore MySQL scoring on SCP-DATABASE-01 (10.10.10.102, Debian)
#
# Scoring requires:
#   1. Port 3306 open, valid MySQL/MariaDB greeting
#   2. SCORER_GREYTEAM authenticates with Th3ScoreUser@9034!
#   3. SELECT 1 on foundation_db succeeds
#
# Common breaks:
#   - mariadb service stopped/crashed
#   - SCORER_GREYTEAM user dropped or password changed
#   - foundation_db database dropped
#   - 50-server.cnf corrupted
#   - bind-address set to 127.0.0.1 (scorer connects remotely)
#   - Port 3306 firewalled
#   - Disk full (mysql won't start)
#   - SQL_APACHE_GREYTEAM dropped (breaks Apache→DB link, indirect scoring)
#   - Socket file missing
#
# Run as root on 10.10.10.102.
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

echo -e "${BLD}=== MySQL Break-Fix — $(hostname) ===${RST}\n"

# ─── Ensure MariaDB is installed ─────────────────────────────────────────────
if ! command -v mariadbd &>/dev/null && ! dpkg -l mariadb-server 2>/dev/null | grep -q '^ii'; then
    apt-get update -qq && apt-get install -y mariadb-server mariadb-client python3-pymysql 2>&1 | tail -3
    fix "Installed mariadb-server"
fi

# ─── Ensure 50-server.cnf has bind-address 0.0.0.0 ──────────────────────────
# Scorer connects REMOTELY — bind-address must not be 127.0.0.1
CNF="/etc/mysql/mariadb.conf.d/50-server.cnf"
if [[ -f "$CNF" ]]; then
    # Fix bind-address if set to localhost
    if grep -q "bind-address.*127\.0\.0\.1" "$CNF"; then
        sed -i 's/bind-address.*=.*127\.0\.0\.1/bind-address = 0.0.0.0/' "$CNF"
        fix "Changed bind-address from 127.0.0.1 to 0.0.0.0"
    fi
    # Ensure bind-address exists
    if ! grep -q "^bind-address" "$CNF"; then
        sed -i '/^\[mysqld\]/a bind-address = 0.0.0.0' "$CNF"
        fix "Added bind-address = 0.0.0.0"
    fi
else
    # Config is missing entirely — write a minimal working one
    mkdir -p /etc/mysql/mariadb.conf.d
    cat > "$CNF" <<'CNFEOF'
[server]
user                    = mysql
pid-file                = /run/mysqld/mysqld.pid
socket                  = /run/mysqld/mysqld.sock
basedir                 = /usr
datadir                 = /var/lib/mysql
tmpdir                  = /tmp
lc-messages-dir         = /usr/share/mysql
bind-address            = 0.0.0.0
port                    = 3306

symbolic-links          = 0

[mysqld]
skip-external-locking
bind-address            = 0.0.0.0
port                    = 3306

log_error               = /var/log/mysql/error.log

character-set-server    = utf8mb4
collation-server        = utf8mb4_general_ci

local-infile            = 0
CNFEOF
    fix "Wrote minimal 50-server.cnf"
fi

# ─── Ensure socket directory exists ──────────────────────────────────────────
mkdir -p /run/mysqld
chown mysql:mysql /run/mysqld

# ─── Start MariaDB ──────────────────────────────────────────────────────────
systemctl enable mysql 2>/dev/null || systemctl enable mariadb 2>/dev/null || true
if ! systemctl is-active --quiet mysql 2>/dev/null && ! systemctl is-active --quiet mariadb 2>/dev/null; then
    systemctl start mysql 2>/dev/null || systemctl start mariadb 2>/dev/null
    if systemctl is-active --quiet mysql 2>/dev/null || systemctl is-active --quiet mariadb 2>/dev/null; then
        fix "MariaDB started"
    else
        err "MariaDB failed to start — check: journalctl -u mysql"
        systemctl status mysql --no-pager 2>&1 | tail -10
        # Common fix: corrupted ibdata or ib_logfile
        echo "  Try: systemctl stop mysql && mv /var/lib/mysql/ib_logfile* /tmp/ && systemctl start mysql"
        exit 1
    fi
else
    ok "MariaDB is running"
fi

# ─── Wait for socket ────────────────────────────────────────────────────────
for i in $(seq 1 10); do
    [[ -S /run/mysqld/mysqld.sock ]] && break
    sleep 1
done
if [[ ! -S /run/mysqld/mysqld.sock ]]; then
    err "MySQL socket not found after 10s"
    exit 1
fi

# ─── Ensure foundation_db exists ─────────────────────────────────────────────
mysql --socket=/run/mysqld/mysqld.sock -e "CREATE DATABASE IF NOT EXISTS foundation_db;" 2>/dev/null \
    && ok "foundation_db exists" \
    || err "Could not create foundation_db"

# ─── Ensure SCPFlagger table exists (scoring may query it) ───────────────────
mysql --socket=/run/mysqld/mysqld.sock foundation_db -e \
    "CREATE TABLE IF NOT EXISTS SCPFlagger (flag VARCHAR(255));" 2>/dev/null || true

# ─── Ensure SCORER_GREYTEAM user exists with correct password ────────────────
mysql --socket=/run/mysqld/mysqld.sock -e "
  CREATE USER IF NOT EXISTS 'SCORER_GREYTEAM'@'%' IDENTIFIED BY 'Th3ScoreUser@9034!';
  ALTER USER 'SCORER_GREYTEAM'@'%' IDENTIFIED BY 'Th3ScoreUser@9034!';
  GRANT SELECT ON foundation_db.* TO 'SCORER_GREYTEAM'@'%';
  FLUSH PRIVILEGES;
" 2>/dev/null \
    && ok "SCORER_GREYTEAM user ready" \
    || err "Failed to create/update SCORER_GREYTEAM"

# ─── Ensure SQL_APACHE_GREYTEAM user exists (Apache needs it) ────────────────
mysql --socket=/run/mysqld/mysqld.sock -e "
  CREATE USER IF NOT EXISTS 'SQL_APACHE_GREYTEAM'@'%' IDENTIFIED BY 'SQ1APACH3User#0544!';
  ALTER USER 'SQL_APACHE_GREYTEAM'@'%' IDENTIFIED BY 'SQ1APACH3User#0544!';
  GRANT ALL ON foundation_db.* TO 'SQL_APACHE_GREYTEAM'@'%';
  FLUSH PRIVILEGES;
" 2>/dev/null \
    && ok "SQL_APACHE_GREYTEAM user ready" \
    || err "Failed to create/update SQL_APACHE_GREYTEAM"

# ─── Ensure GREY_ADMIN exists (root-equivalent for Grey Team) ────────────────
mysql --socket=/run/mysqld/mysqld.sock -e "
  CREATE USER IF NOT EXISTS 'GREY_ADMIN'@'localhost' IDENTIFIED BY 'Gr3yTeamDB!Admin#2026';
  GRANT ALL PRIVILEGES ON *.* TO 'GREY_ADMIN'@'localhost' WITH GRANT OPTION;
  FLUSH PRIVILEGES;
" 2>/dev/null || true

# ─── Ensure Blue Team DR_ADMIN exists ────────────────────────────────────────
mysql --socket=/run/mysqld/mysqld.sock -e "
  CREATE USER IF NOT EXISTS 'DR_ADMIN'@'%' IDENTIFIED BY 'Blu3TeamDB!20265';
  GRANT SUPER, PROCESS, RELOAD, SELECT, SHOW DATABASES ON *.* TO 'DR_ADMIN'@'%';
  FLUSH PRIVILEGES;
" 2>/dev/null || true

# ─── Firewall ───────────────────────────────────────────────────────────────
if command -v ufw &>/dev/null; then
    ufw allow 3306/tcp 2>/dev/null || true
    ufw allow 22/tcp 2>/dev/null || true
fi
if command -v iptables &>/dev/null; then
    while iptables -D INPUT -p tcp --dport 3306 -j DROP 2>/dev/null; do :; done
    while iptables -D INPUT -p tcp --dport 3306 -j REJECT 2>/dev/null; do :; done
fi

# ─── Restart MySQL to pick up any config changes ────────────────────────────
systemctl restart mysql 2>/dev/null || systemctl restart mariadb 2>/dev/null
sleep 2

# ─── Verify ──────────────────────────────────────────────────────────────────
if ss -tlnp | grep -q ':3306 '; then
    ok "Port 3306 is listening"
else
    err "Port 3306 NOT listening"
fi

# Test scorer authentication
if command -v mysql &>/dev/null; then
    RESULT=$(mysql -h 127.0.0.1 -P 3306 -u SCORER_GREYTEAM -p'Th3ScoreUser@9034!' foundation_db -e "SELECT 1 AS test;" 2>/dev/null)
    if echo "$RESULT" | grep -q "1"; then
        ok "SCORER_GREYTEAM auth + query succeeded"
    else
        err "SCORER_GREYTEAM auth/query failed"
    fi
fi

echo -e "\n${BLD}=== MySQL break-fix complete ===${RST}"
