# 1. Check for other suspicious users
mariadb -u root -p -e "SELECT User, Host FROM mysql.user;"

# 2. Lock down MariaDB config
chmod 600 /etc/mysql/mariadb.conf.d/*
chmod 600 /etc/mysql/debian.cnf

# 3. Restrict network access (if DB is local-only)
# Edit /etc/mysql/mariadb.conf.d/50-server.cnf
# Ensure: bind-address = 127.0.0.1

# 4. Restart MariaDB to apply config changes
systemctl restart mariadb

# 5. Check for backdoor accounts the red team might have created
mariadb -u root -p -e "SELECT User, Host, authentication_string FROM mysql.user WHERE User NOT IN ('mariadb.sys', 'mysql', 'root', 'DR_ADMIN');"