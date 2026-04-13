# Blue Team MySQL Hardening

Automated MySQL hardening for CCDC-style competitions. Deploys restrictive firewall rules and MySQL security configurations to protect the database server while maintaining grey team scoring access and Apache connectivity.

## 🎯 What This Does

### Firewall Hardening (UFW)
- ✅ MySQL (3306) accessible ONLY from Apache (10.10.10.101) + Grey Team
- ✅ Blocks MySQL from DC, SMB, SMTP, OpenSSH, OpenVPN
- ✅ ICMP (ping) blocked except from Grey Team
- ✅ SSH (22) maintained for administration
- ✅ Default deny all other inbound traffic

### MySQL Service Hardening
- ✅ Changes passwords for ALL MySQL users (saved to file)
- ✅ Removes anonymous users
- ✅ Removes test database
- ✅ Disables remote root login (localhost only)
- ✅ Revokes dangerous privileges (FILE, SUPER, PROCESS, etc.) from non-root users
- ✅ Hardens MySQL configuration:
  - `bind-address = 10.10.10.102` (internal IP only)
  - `local_infile = 0` (prevents file read attacks)
  - `symbolic-links = 0` (prevents symlink attacks)
  - `skip-show-database` (info disclosure prevention)
  - Connection limits and timeouts

## 📋 Target Infrastructure

**SCP-DATABASE-01**: 10.10.10.102 (Debian 13, MySQL)

**Allowed Connections:**
- Apache Web Server: 10.10.10.101
- Grey Team (Scoring): 10.10.10.200 - 10.10.10.210

**Blocked Connections:**
- DC: 10.10.10.21
- SMB: 10.10.10.22
- SMTP: 10.10.10.23
- OpenSSH: 10.10.10.103
- OpenVPN: 10.10.10.104

## 🔧 Configuration

### Update IP Addresses

Edit `group_vars/all.yml`:

```yaml
# Grey Team IPs (Scoring Engine)
grey_team_ips:
  - 10.10.10.200
  - 10.10.10.201
  # ... add more if needed

# Service IPs
service_ips:
  apache: 10.10.10.101    # Change if different
  database: 10.10.10.102

# MySQL password length
mysql_password_length: 16   # Change if desired
```

## 📊 What Gets Changed

### MySQL Users
- **All passwords changed** to random 16-character strings
- Passwords saved to `/root/mysql_passwords_YYYYMMDD_HHMMSS.txt` on server
- Passwords downloaded to `./mysql_passwords_SCP-DATABASE-01.txt` locally

### MySQL Privileges Revoked
For all non-root users:
- `FILE` - Can't read/write OS files
- `SUPER` - Can't kill threads or change global variables
- `PROCESS` - Can't see other users' queries
- `RELOAD` - Can't flush tables/logs
- `SHUTDOWN` - Can't shutdown MySQL
- `CREATE USER` - Can't create new users
- `GRANT OPTION` - Can't grant privileges to others

### Files Modified
- `/etc/mysql/mysql.conf.d/mysqld.cnf` - Hardened configuration
  - Backup saved to: `/etc/mysql/mysql.conf.d/mysqld.cnf.backup`
- `/etc/ufw/` - Firewall rules

## ⚠️ Important Notes

### After Deployment

1. **Update Apache Configuration**
   - Apache needs the new MySQL password to connect
   - Find the password in `mysql_passwords_SCP-DATABASE-01.txt`
   - Update Apache's database connection config (often in `/var/www/html/config.php` or similar)

2. **Test Apache -> MySQL Connection**
   ```bash
   # On Apache server (10.10.10.101)
   mysql -h 10.10.10.102 -u <username> -p
   ```

3. **Verify Scoring Works**
   - Grey team should still be able to connect to MySQL
   - Monitor scoring to ensure no disruption

### Breaking Changes

This hardening **WILL BREAK**:
- Any application using old MySQL passwords (update configs!)
- Remote root access (now localhost only)
- Users trying to use FILE privilege for LOAD DATA INFILE

This hardening **WILL NOT BREAK**:
- Grey team scoring (full access preserved)
- Apache -> MySQL connection (after password update)
- Legitimate application database queries

## 🔄 Rollback

### Manual Rollback

```bash
# Disable firewall
ufw disable

# Restore MySQL config
cp /etc/mysql/mysql.conf.d/mysqld.cnf.backup /etc/mysql/mysql.conf.d/mysqld.cnf
systemctl restart mysql

# Restore passwords (if needed)
mysql < /root/mysql_user_backup_YYYYMMDD_HHMMSS.sql
```

## 🐛 Troubleshooting

### Apache Can't Connect to MySQL

**Symptom**: Web application shows database errors

**Solution**:
1. Check password file: `cat mysql_passwords_SCP-DATABASE-01.txt`
2. Find the application database user
3. Update Apache config with new password
4. Restart Apache: `systemctl restart apache2`

### Grey Team Scoring Fails

**Symptom**: MySQL checks fail on scoring engine

**Check**:
```bash
# On database server
ufw status numbered | grep 3306

# Should show rules allowing 10.10.10.200-210

### MySQL Won't Start

**Symptom**: `systemctl status mysql` shows failed

**Check**:
```bash
tail -f /var/log/mysql/error.log
```

**Common Issues**:
- Configuration syntax error - restore backup config
- Permissions on data directory - `chown -R mysql:mysql /var/lib/mysql`

### Locked Out of MySQL

**Symptom**: Can't login even with new passwords

**Solution**:
```bash
# Stop MySQL
systemctl stop mysql

# Start in safe mode (skip grant tables)
mysqld_safe --skip-grant-tables &

# Reset root password
mysql -e "FLUSH PRIVILEGES; ALTER USER 'root'@'localhost' IDENTIFIED BY 'newpassword';"

# Restart normally
systemctl restart mysql
```

## 📈 Verification Commands

### Test MySQL Connection
```bash
# From Apache server
mysql -h 10.10.10.102 -u <username> -p<password> -e "SELECT 1;"
```

## 🎯 Competition Workflow

```

# 3. Check password file
cat mysql_passwords_SCP-DATABASE-01.txt

# 4. Update Apache config with new DB password
ssh root@10.10.10.101
nano /var/www/html/config.php  # Update DB password
systemctl restart apache2

# 5. Test
curl http://10.10.10.101  # Check web app works

# 6. Monitor scoring
# Watch for any MySQL-related point losses
```

## 🛡️ Security Features

### Attack Surface Reduction
- MySQL only accessible from Apache + scoring engine
- No other blue team machines can reach database
- ICMP disabled (anti-reconnaissance)

### Privilege Minimization
- Non-root users can't escalate privileges
- No FILE privilege (can't read /etc/passwd)
- No SUPER privilege (can't kill processes)

### Configuration Hardening
- No local file reading (local_infile=0)
- No symbolic link attacks (symbolic-links=0)
- Bind to internal IP only (not 0.0.0.0)
- Skip hostname resolution (faster + more secure)

### Logging
- Error logging enabled
- Warning level 2 (connection issues logged)

## 📜 License

MIT License - Free for competition and educational use.

---

**Built for CCDC MySQL hardening | Secure the database** 🛡️
