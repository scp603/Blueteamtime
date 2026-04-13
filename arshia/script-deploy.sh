#!/bin/bash

chmod +x scripts/basic-hardening.sh
chmod +x scripts/harden_debian.sh
chmod +x scripts/harden_firewall.sh
chmod +x scripts/harden_ssh.sh
chmod +x scripts/harden_sysctl.sh
chmod +x scripts/remove_users.sh
chmod +x scripts/harden_sudo.sh

./scripts/basic-hardening.sh
./scripts/harden_debian.sh
./scripts/harden_firewall.sh
./scripts/harden_sysctl.sh
./scripts/remove_users.sh
./scripts/harden_sudo.sh