## Overview

This package contains two Bash scripts designed for rapid execution during the first 5 minutes of Blue Team competition on a Rocky Linux OpenVPN server. They are meant to be run in sequence: harden the system first, then deploy flag decoys.

## Scripts

### 1. `openvpn-harden.sh` — OpenVPN Hardening

Secures the scored OpenVPN service (SCP-OPENVPN-01) by locking down file permissions, configuring Firewalld rules for scoring ports, and restarting the VPN to verify functionality.

**What it does:**
- Sets private keys (`*.key`) to root read-only (`chmod 400`)
- Sets certificates (`*.crt`) to world-readable (`chmod 644`)
- Opens ports `1194/udp` and `1194/tcp` for standard OpenVPN traffic
- Restricts the OpenVPN Management Port (`7505/tcp`) and Telnet (`23/tcp`) to the Overseer subnet (`10.10.10.200/24`) only
- Removes global access to ports 7505 and 23
- Reloads Firewalld and restarts OpenVPN
- Prints the active service status for verification

**What it does NOT touch:**
- `/etc/openvpn/server/mgmt-pass` — intentionally excluded to avoid breaking scoring

**Requirements:**
- Must be run as `root`
- Requires `firewalld` to be active
- Requires `systemd` (Rocky Linux 10 default)

**How to run:**
```bash
chmod +x openvpn-harden.sh
sudo ./openvpn-harden.sh
```

**Expected output:**
```
[+] Securing OpenVPN sensitive files (excluding mgmt-pass)...
[+] Hardening Firewalld for Scoring Ports...
[+] Firewall rules applied.
[+] Restarting OpenVPN to verify functionality...
   Active: active (running) since ...
[+] OpenVPN hardening complete.
```

**How to verify it worked:**
```bash
systemctl status openvpn*         # Should show active (running)
firewall-cmd --list-all           # Should show 1194 open, 7505/23 as rich rules only
ls -la /etc/openvpn/server/*.key  # Should show -r-------- (400)
```

### 2. `fakeflags.sh` — Flag Hunter & Decoy Generator

Locates real `CONFIDENTIAL{...}` flag files on the system and floods each flag directory with 100 randomized decoy flag files to slow down Red Team analysis.

**What it does:**
- Searches `/root`, `/home`, `/var/www`, `/opt`, `/etc`, `/tmp`, and `/usr/local` for files containing `CONFIDENTIAL{`
- Prints the path of every real flag file found
- For each flag directory, generates 100 decoy files with:
  - Random 12-character alphanumeric strings
  - Valid-looking `CONFIDENTIAL{f4k3_..._s3cr3t}` format
  - Tempting filenames like `creds_42.txt`, `admin_pass_7.txt`, etc.
- Sets decoy file permissions to `644` (readable by Red Team)

**What it does NOT do:**
- Modify, move, or delete the original flag file (Rule #10 compliance)

**Search directories (configurable):**
```bash
SEARCH_DIRS="/root /home /var/www /opt /etc /tmp /usr/local"
```
To search the entire filesystem, change this to `"/"` — but expect it to take significantly longer.

**Requirements:**
- Must be run as `root` (needed to read protected directories)
- Requires `/dev/urandom` (standard on all Linux systems)

**How to run:**
```bash
chmod +x fakeflags.sh
sudo ./fakeflags.sh
```

**Expected output:**
```
=== Nine-Tailed Fox: Flag Decoy Operation ===
[+] Starting hunt for 'CONFIDENTIAL{' flags...
[!] Flags discovered:
  -> Found real flag file: /root/flag.txt
  [+] Deploying 100 decoy flags in /root...
  [+] 100 decoys successfully deployed in /root.

[+] Operation complete.
[!] REMINDER: DO NOT move or edit the original flag file! (Rule #10)
```

**How to verify it worked:**
```bash
ls /root/*.txt | wc -l        # Should be 101 (100 decoys + 1 real)
cat /root/flag.txt             # Real flag should be unchanged
```