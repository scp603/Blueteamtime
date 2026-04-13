# Odessa

Blue team toolkit for CDT competitions.

## Tools

| Tool | What it does | Usage |
|------|-------------|-------|
| `shell-jail/jail.sh` | Jails an SSH user into a locked Alpine container | `sudo ./shell-jail/jail.sh <user>` |
| `shell-jail/trap.sh` | Interactive picker to jail multiple users | `sudo ./shell-jail/trap.sh` |
| `triage/triage.sh` | Hardens an Ubuntu 24.04 box and runs baseline scans | `sudo ./triage/triage.sh [interface]` |
| `triage/stop-revshells.sh` | Detects (and optionally kills) active reverse shells | `sudo ./triage/stop-revshells.sh -k -v` |
| `triage/fix-ssh.sh` | Restores SSH scoring (users, sshd_config, persistence cleanup) | `sudo ./triage/fix-ssh.sh` |
| `triage/fix-openvpn.sh` | Restores OpenVPN scoring (service, PKI, management, sshd) | `sudo ./triage/fix-openvpn.sh` |
| `triage/fix-apache.sh` | Restores Apache scoring (index.php, vhost, PHP module) | `sudo ./triage/fix-apache.sh` |
| `triage/fix-mysql.sh` | Restores MySQL scoring (service, SCORER_GREYTEAM, foundation_db) | `sudo ./triage/fix-mysql.sh` |
