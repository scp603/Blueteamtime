# Blue Team Script Operational Documentation

This document provides operational guidance for each Blue Team triage script included in this toolkit.

---

## Table of Contents
- [service_check.sh](#service_checksh)
- [ssh_session.sh](#ssh_sessionsh)
- [user_audit.sh](#user_auditsh)
- [password_change.sh](#password_changesh)
- [breakglass_account.sh](#breakglass_accountsh)
- [aide.sh](#aidesh)
- [setup.sh](#setupsh)

---

# service_check.sh

## What Systems It's For
- Rocky Linux
- RHEL-based Linux systems
- Systems running SSH/OpenVPN

## How to Run It
    sudo ./service_check.sh

## What It Does
- Verifies SSH service status
- Verifies OpenVPN service status
- Checks listening ports
- Displays active network connections
- Shows running services and CPU-heavy processes

## How to Interpret the Output
- `ACTIVE` = Service is functioning normally
- `[ALERT]` = Service/port issue detected
- Review network/service output for anomalies

## What To Do If Errors Occur
- Verify script is run with sudo/root
- Confirm required services are installed
- Validate service names match system configuration

## Test Results
- Successfully detects service uptime/down states
- Successfully flags missing ports/services
- Successfully generates audit log file

---

# ssh_session.sh

## What Systems It's For
- Linux systems utilizing SSH remote access

## How to Run It
    sudo ./ssh_session.sh

## What It Does
- Audits active SSH sessions
- Identifies connected user IP addresses
- Compares IPs against approved ranges
- Flags unauthorized remote access attempts

## How to Interpret the Output
- Normal output = Approved session detected
- `[ALERT]` = Unapproved IP/source detected

## What To Do If Errors Occur
- Ensure active SSH sessions exist
- Update approved IP list if needed
- Verify sudo permissions

## Test Results
- Successfully identifies approved sessions
- Successfully flags unauthorized IPs
- Successfully writes audit logs

---

# user_audit.sh

## What Systems It's For
- Linux systems
- Rocky Linux / RHEL preferred

## How to Run It
    sudo ./user_audit.sh

## What It Does
- Lists login-capable users
- Flags unknown accounts
- Identifies UID 0 accounts
- Audits wheel group membership
- Reviews home directory permissions

## How to Interpret the Output
- Standard output = Expected/approved account
- `[ALERT]` = Suspicious user/permission issue

## What To Do If Errors Occur
- Ensure root privileges
- Verify passwd/group files exist
- Confirm wheel group configuration

## Test Results
- Successfully audits local users
- Successfully flags unknown users
- Successfully identifies insecure permissions

---

# password_change.sh

## What Systems It's For
- Linux systems using local password authentication

## How to Run It
    sudo ./password_change.sh

## What It Does
- Generates secure random password
- Rotates passwords for login-capable users
- Excludes protected users

## How to Interpret the Output
- Password displayed once = New generated password
- `Changed password for:` = Rotation successful
- `Skipped protected user:` = Protected exclusion successful

## What To Do If Errors Occur
- Ensure script is run as root
- Verify `openssl` installed
- Save password before terminal closes

## Test Results
- Successfully rotates passwords
- Successfully skips protected accounts
- Successfully generates secure password

---

# breakglass_account.sh

## What Systems It's For
- Linux systems requiring backup admin access

## How to Run It
    sudo ./breakglass_account.sh

## What It Does
- Creates backup administrator account
- Adds account to wheel group
- Prevents password expiration

## How to Interpret the Output
- `Created backup admin account` = Success
- No output = Account may already exist

## What To Do If Errors Occur
- Verify sudo/root privileges
- Ensure wheel group exists
- Check for duplicate username

## Test Results
- Successfully creates backup admin
- Successfully grants wheel privileges
- Successfully disables password expiration

---

# aide.sh

## What Systems It's For
- Rocky Linux
- RHEL-based Linux systems

## How to Run It
    sudo ./aide.sh

## What It Does
- Installs AIDE
- Configures integrity monitoring rules
- Initializes AIDE database baseline

## How to Interpret the Output
- `AIDE database initialized` = Success
- `AIDE install failed` = Installation issue
- `AIDE database not found` = Initialization issue

## What To Do If Errors Occur
- Verify internet/package repository access
- Ensure dnf works properly
- Confirm AIDE package exists in repos

## Test Results
- Successfully installs AIDE
- Successfully initializes database
- Successfully configures monitoring rules

---

# setup.sh

## What Systems It's For
- Ubuntu/Debian
- Rocky/RHEL/CentOS
- Fedora
- Arch/Manjaro
- SUSE

## How to Run It
    sudo ./setup.sh

## What It Does
- Detects operating system automatically
- Installs Ansible/dependencies
- Installs required collections
- Verifies installation

## How to Interpret the Output
- `Setup complete` = Success
- `Unsupported distro` = Unsupported OS detected
- `Ansible install failed` = Installation failure

## What To Do If Errors Occur
- Verify supported operating system
- Confirm repository/internet access
- Ensure sudo/root privileges

## Test Results
- Successfully installs Ansible
- Successfully installs dependencies
- Successfully verifies installation
