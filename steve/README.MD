# Blue Team Scripts

## Overview

This script set is meant for **Linux systems**, mainly **Rocky Linux**, during early Blue Team triage. The tools focus on quickly checking service availability, reviewing user activity, auditing accounts, rotating passwords, creating an emergency admin account, and setting up file integrity monitoring with AIDE.

## What Systems It Is For

These scripts are primarily intended for:

- Rocky Linux systems
- Other Linux systems with similar tools and paths
- Competition or lab environments where SSH, OpenVPN, user auditing, and rapid triage are required

Some scripts are specifically written around Rocky Linux behavior, including `dnf`, `systemctl`, `ss`, and AIDE setup paths. The `setup.sh` script is broader and supports multiple Linux distributions for installing Ansible. 

## Included Scripts

### `service_check.sh`
Checks whether important services are active, confirms expected ports are listening, shows active network connections, running services, and top CPU processes. It is mainly used to confirm system availability and spot suspicious changes fast. 
### `ssh_session.sh`
Reviews active SSH sessions using `who`, records the source IP for each session, and flags connections from unapproved IP addresses. 
### `user_audit.sh`
Audits login-capable users, flags unknown accounts, checks for unexpected UID 0 users, reviews wheel group membership, and checks home directory permissions.

### `password_change.sh`
Generates one random password and applies it to login-capable users while skipping protected accounts such as `GREYTEAM` and `sud0`. It is meant for rapid credential reset during triage.

### `breakglass_account.sh`
Creates a backup admin account named `sud0`, adds it to the `wheel` group, and sets it to avoid forced password expiration. This is intended as emergency recovery access. 

### `aide.sh`
Installs and configures AIDE, adds monitoring rules for key system files and directories, ignores noisy temporary paths, and initializes the AIDE database for later integrity checks.

### `setup.sh`
Installs Ansible and common supporting packages across several Linux distributions. This is more of an environment setup script than a triage script.

## How To Run It

Make the scripts executable first:

```bash
chmod +x service_check.sh ssh_session.sh user_audit.sh password_change.sh breakglass_account.sh aide.sh setup.sh
