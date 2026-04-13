#!/usr/bin/env bash
# =============================================================================
# fix-apache.sh — Restore Apache scoring on SCP-APACHE-01 (10.10.10.101, Debian)
#
# Scoring requires:
#   1. Port 80 accepting TCP connections
#   2. HTTP GET / returns 200
#   3. Response body contains "SCP Foundation"
#
# Common breaks:
#   - apache2 service stopped/crashed
#   - index.php deleted or corrupted (keyword missing)
#   - VirtualHost config broken
#   - PHP module not loaded
#   - Port 80 firewalled
#   - index.html taking precedence over index.php
#   - db_config.php deleted (index.php tries to require it)
#   - webshell replacing index.php
#
# Run as root on 10.10.10.101.
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

echo -e "${BLD}=== Apache Break-Fix — $(hostname) ===${RST}\n"

WEBROOT="/var/www/html"
KEYWORD="SCP Foundation"

# ─── Ensure Apache is installed ──────────────────────────────────────────────
if ! command -v apache2 &>/dev/null && ! dpkg -l apache2 2>/dev/null | grep -q '^ii'; then
    apt-get update -qq && apt-get install -y apache2 php libapache2-mod-php php-mysqli 2>&1 | tail -3
    fix "Installed apache2 + PHP"
fi

# ─── Ensure index.php exists and contains the scoring keyword ────────────────
if [[ ! -f "$WEBROOT/index.php" ]] || ! grep -qi "SCP Foundation" "$WEBROOT/index.php" 2>/dev/null; then
    fix "index.php missing or keyword absent — restoring"
    cat > "$WEBROOT/index.php" <<'PHPEOF'
<?php
/**
 * SCP Foundation — Site Golisano Personnel Portal
 * CLEARANCE LEVEL 2 REQUIRED FOR ACCESS
 */
$db_connected = false;
try {
    if (file_exists('db_config.php')) {
        require_once('db_config.php');
        $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
        if (!$conn->connect_error) {
            $db_connected = true;
        }
    }
} catch (Exception $e) {
    // Connection issue — site still loads
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SCP Foundation — Site Golisano</title>
</head>
<body style="background:#0a0a0a;color:#ccc;font-family:monospace;">
<div style="background:#111;border-bottom:2px solid #c00;padding:20px 40px;display:flex;align-items:center;gap:20px;">
    <div style="font-size:3em;font-weight:bold;color:#c00;">SCP</div>
    <div>
        <h1 style="color:#fff;margin:0;font-size:1.2em;">FOUNDATION — SITE GOLISANO PERSONNEL PORTAL</h1>
        <p style="color:#888;margin:4px 0 0;font-size:0.75em;">SCP Foundation &bull; Secure. Contain. Protect. &bull; CLEARANCE: LEVEL 2</p>
    </div>
</div>
<div style="background:#1a0000;border:1px solid #600;margin:20px 40px;padding:15px 20px;color:#f44;font-size:0.85em;">
    WARNING: AUTHORIZED PERSONNEL ONLY — All access is logged and monitored.
</div>
<div style="padding:20px 40px;">
    <p>Containment status: <span style="color:#0c6;">NOMINAL</span></p>
    <p>Database: <span style="color:<?= $db_connected ? '#0c6' : '#c00' ?>;"><?= $db_connected ? 'CONNECTED' : 'OFFLINE' ?></span></p>
    <p>Mobile Task Force Epsilon-11 "Nine-Tailed Fox" has been dispatched.</p>
</div>
<footer style="border-top:1px solid #222;margin-top:40px;padding:16px 40px;font-size:0.7em;color:#444;">
    SCP Foundation — Site Golisano &bull; <?= date('Y') ?>
</footer>
</body>
</html>
PHPEOF
    chown www-data:www-data "$WEBROOT/index.php"
    chmod 644 "$WEBROOT/index.php"
    ok "index.php restored with scoring keyword"
fi

# ─── Ensure db_config.php exists (index.php requires it) ────────────────────
if [[ ! -f "$WEBROOT/db_config.php" ]]; then
    cat > "$WEBROOT/db_config.php" <<'DBEOF'
<?php
define('DB_HOST', '10.10.10.102');
define('DB_NAME', 'foundation_db');
define('DB_USER', 'SQL_APACHE_GREYTEAM');
define('DB_PASS', 'SQ1APACH3User#0544!');
DBEOF
    chown www-data:www-data "$WEBROOT/db_config.php"
    chmod 640 "$WEBROOT/db_config.php"
    fix "Restored db_config.php"
fi

# ─── Remove index.html if it exists (takes precedence over index.php) ────────
if [[ -f "$WEBROOT/index.html" ]]; then
    rm -f "$WEBROOT/index.html"
    fix "Removed index.html (was shadowing index.php)"
fi

# ─── Ensure PHP module is enabled ────────────────────────────────────────────
if ! apache2ctl -M 2>/dev/null | grep -qi php; then
    a2enmod php* 2>/dev/null || true
    fix "Enabled PHP module"
fi

# ─── Ensure a working VirtualHost config exists ──────────────────────────────
VHOST="/etc/apache2/sites-available/scp-site.conf"
if [[ ! -f "$VHOST" ]] || ! grep -q "DocumentRoot.*$WEBROOT" "$VHOST" 2>/dev/null; then
    cat > "$VHOST" <<'VHEOF'
<VirtualHost *:80>
    ServerName scp-apache-01.scp.com
    ServerAdmin webmaster@scp.com
    DocumentRoot /var/www/html

    <Directory /var/www/html>
        Options -Indexes -FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    <Directory /var/www/html/uploads>
        Options -Indexes -ExecCGI
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/scp-error.log
    CustomLog ${APACHE_LOG_DIR}/scp-access.log combined
</VirtualHost>
VHEOF
    fix "Restored VirtualHost config"
fi

# Enable our site, disable default
a2dissite 000-default.conf 2>/dev/null || true
a2ensite scp-site.conf 2>/dev/null || true

# ─── Ensure Apache listens on port 80 ───────────────────────────────────────
if ! grep -q "Listen 80" /etc/apache2/ports.conf 2>/dev/null; then
    echo "Listen 80" >> /etc/apache2/ports.conf
    fix "Added Listen 80 to ports.conf"
fi

# ─── Firewall ───────────────────────────────────────────────────────────────
if command -v ufw &>/dev/null; then
    ufw allow 80/tcp 2>/dev/null || true
    ufw allow 22/tcp 2>/dev/null || true
fi
if command -v iptables &>/dev/null; then
    while iptables -D INPUT -p tcp --dport 80 -j DROP 2>/dev/null; do :; done
    while iptables -D INPUT -p tcp --dport 80 -j REJECT 2>/dev/null; do :; done
fi

# ─── Test Apache config syntax ───────────────────────────────────────────────
if apache2ctl configtest 2>&1 | grep -q "Syntax OK"; then
    ok "Apache config syntax OK"
else
    err "Apache config has errors:"
    apache2ctl configtest 2>&1
fi

# ─── Restart Apache ──────────────────────────────────────────────────────────
if systemctl restart apache2 2>/dev/null; then
    ok "Apache restarted"
else
    err "Apache failed to restart — check: journalctl -u apache2"
    systemctl status apache2 --no-pager 2>&1 | tail -10
fi

# ─── Verify ──────────────────────────────────────────────────────────────────
sleep 1

if ss -tlnp | grep -q ':80 '; then
    ok "Port 80 is listening"
else
    err "Port 80 NOT listening"
fi

# Check scoring keyword
BODY=$(curl -s --max-time 5 http://127.0.0.1/ 2>/dev/null)
if echo "$BODY" | grep -qi "SCP Foundation"; then
    ok "Scoring keyword 'SCP Foundation' found in response"
else
    err "Scoring keyword NOT found in response body"
    echo "  First 200 chars: ${BODY:0:200}"
fi

echo -e "\n${BLD}=== Apache break-fix complete ===${RST}"
