# Gavin's Repo

## Contents

### dompascha.ps1

This grabs the json of the encrypted passwords and hash of them and decrypts, checks to see if they match the hash (if they don't the script fails), and then changes the password. This needs to be changed to be a little extra safe but I don't have the time before comp day 1 starts.

### fire.ps1

This is a cool lil firewall script thingy. It creates the firewall rules per box and then takes user input to determine what box it's running on, creating some extra rules per box.

### linpascha.sh

This just puts the password hash of the passwords I setup beforehand directly into /etc/shadow to change them to our password. This means it doesn't require any user input, pretty easy to run and automate

### localusr.ps1

This does basically the same thing as dompascha.ps1, but for local users.

### winhard.ps1

This does some windows hardening and I'm begging it to work properly.