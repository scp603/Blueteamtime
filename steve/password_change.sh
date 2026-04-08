#!/bin/bash

### Bulk Password Rotation Script
### Generates Random Password
### Prints Password To Terminal
### No Automatic Password Saving

### Protected users
PROTECTED_USERS=("GREYTEAM" "sud0")

### Generate random 16 character password
PASSWORD=$(openssl rand -base64 16 | tr -dc 'A-Za-z0-9!@#$%^&*' | head -c 16)

### Warning message
echo "WARNING: Generated password will ONLY be displayed once."
echo "WARNING: Password is NOT automatically saved."
echo "WARNING: Write down or securely store the password before continuing."
echo ""

### Print generated password
echo "Generated Password: $PASSWORD"
echo ""

### Check protected users
is_protected() {
    local USERNAME="$1"

    for USER in "${PROTECTED_USERS[@]}"; do
        if [[ "$USERNAME" == "$USER" ]]; then
            return 0
        fi
    done

    return 1
}

### Loop through users
while IFS=: read -r USERNAME x UID GID COMMENT HOME SHELL
do

    ### Skip system accounts
    if [[ "$UID" -lt 1000 && "$USERNAME" != "root" ]]; then
        continue
    fi

    ### Skip no login accounts
    if [[ "$SHELL" =~ (nologin|false) ]]; then
        continue
    fi

    ### Skip protected users
    if is_protected "$USERNAME"; then
        echo "Skipped protected user: $USERNAME"
        continue
    fi

    ### Change password
    echo "$USERNAME:$PASSWORD" | chpasswd

    echo "Changed password for: $USERNAME"

done < /etc/passwd

echo ""
echo "All passwords changed successfully."