Critical Post-Deployment Step
You MUST update Apache's database configuration with the new MySQL password or the web app will break:

Check: cat mysql_passwords_SCP-DATABASE-01.txt
Find your app user's new password
Update Apache config (usually /var/www/html/config.php or similar)
Restart Apache: systemctl restart apache2