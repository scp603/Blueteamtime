#!/usr/bin/env bash
# =============================================================================
# triage-rocky.sh — Nine-Tailed Fox CDT Competition
# Rocky Linux monitoring & auditing setup
# Run as root or with sudo
# =============================================================================

set -euo pipefail

IFACE="${1:-$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/{print $5; exit}')}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="$SCRIPT_DIR/triage_$(hostname)_$(date +%Y%m%d_%H%M%S).log"

log()  { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
ok()   { echo "[$(date +%H:%M:%S)] ✓ $*" | tee -a "$LOG"; }
warn() { echo "[$(date +%H:%M:%S)] ! $*" | tee -a "$LOG"; }

# --- must be root ---
if [[ $EUID -ne 0 ]]; then
    echo "Run as root" >&2
    exit 1
fi

log "Starting triage on $(hostname) — interface: $IFACE"
log "Logging to $LOG"

# =============================================================================
# PACKAGE INSTALLATION
# =============================================================================
log "=== Installing packages ==="

# Enable EPEL + CRB repos
dnf install -y epel-release 2>&1 | tee -a "$LOG" || warn "EPEL install failed — some packages may be unavailable"
# dnf5 (Rocky 10+) changed config-manager syntax; try both
dnf config-manager setopt crb.enabled=1 2>&1 | tee -a "$LOG" \
    || dnf config-manager --set-enabled crb 2>&1 | tee -a "$LOG" \
    || warn "CRB repo enable failed"

dnf makecache -q

# Packages available in Rocky 10 + EPEL 10 + CRB repos
PACKAGES=(
    audit            # kernel audit framework (includes audispd-plugins on Rocky 10)
    aide             # file integrity monitoring
    fail2ban         # brute-force mitigation via log parsing (EPEL)
    net-tools        # netstat
    lsof             # open file / socket listing
    sysstat          # sar, iostat, pidstat
    psacct           # process accounting — lastcomm, sa (Rocky name for acct)
    inotify-tools    # inotifywait for real-time file watch (EPEL)
    curl wget        # needed by some detections / clones
    clang llvm       # needed if building XDP firewall
    libbpf-devel     # XDP dependency (CRB repo)
    kernel-devel     # XDP / module build dep
    bpftool          # inspect loaded BPF programs
    git gcc make     # build deps for source installs below
    perl             # required by rkhunter & psad
    glibc-static     # required by chkrootkit build
)

dnf install -y "${PACKAGES[@]}" 2>&1 | tee -a "$LOG" || warn "Some packages failed — check log"
ok "Repo package install done"

# =============================================================================
# SOURCE INSTALLS — not packaged in Rocky 10 / EPEL 10
# =============================================================================
log "=== Installing tools from source ==="

# --- unhide (hidden process detection) ---
if ! command -v unhide &>/dev/null; then
    log "Building unhide from source..."
    cd /tmp
    git clone --depth 1 https://github.com/YJesus/Unhide.git 2>&1 | tee -a "$LOG"
    cd /tmp/Unhide
    gcc -Wall -O2 -o unhide \
        unhide-linux.c unhide-linux-bruteforce.c unhide-linux-compound.c \
        unhide-linux-procfs.c unhide-linux-syscall.c unhide-output.c -lpthread 2>&1 | tee -a "$LOG"
    gcc -Wall -O2 -o unhide-tcp \
        unhide-tcp.c unhide-tcp-fast.c unhide-output.c -lpthread 2>&1 | tee -a "$LOG"
    cp unhide unhide-tcp /usr/local/bin/
    ok "unhide installed from source"
    cd "$SCRIPT_DIR"
else
    ok "unhide already installed"
fi

# --- chkrootkit (rootkit scanner) ---
if ! command -v chkrootkit &>/dev/null; then
    log "Building chkrootkit from source..."
    cd /tmp
    git clone --depth 1 https://github.com/Magentron/chkrootkit.git 2>&1 | tee -a "$LOG"
    cd /tmp/chkrootkit
    make sense 2>&1 | tee -a "$LOG"
    cp chkrootkit /usr/local/sbin/
    ok "chkrootkit installed from source"
    cd "$SCRIPT_DIR"
else
    ok "chkrootkit already installed"
fi

# --- rkhunter (rootkit / backdoor scanner) ---
if ! command -v rkhunter &>/dev/null; then
    log "Installing rkhunter from source..."
    cd /tmp
    curl -sL "https://downloads.sourceforge.net/project/rkhunter/rkhunter/1.4.6/rkhunter-1.4.6.tar.gz" -o rkhunter.tar.gz
    tar xzf rkhunter.tar.gz
    cd rkhunter-1.4.6
    ./installer.sh --install --layout default 2>&1 | tee -a "$LOG"
    ok "rkhunter installed from source"
    cd "$SCRIPT_DIR"
else
    ok "rkhunter already installed"
fi

# --- lynis (security auditing & hardening advisor) ---
if ! command -v lynis &>/dev/null; then
    log "Installing lynis from git..."
    git clone --depth 1 https://github.com/CISOfy/lynis.git /opt/lynis 2>&1 | tee -a "$LOG"
    cat > /usr/local/bin/lynis <<'WRAPPER'
#!/bin/bash
cd /opt/lynis && ./lynis "$@"
WRAPPER
    chmod +x /usr/local/bin/lynis
    ok "lynis installed to /opt/lynis"
else
    ok "lynis already installed"
fi

# --- psad (port scan detection) ---
if ! command -v psad &>/dev/null; then
    log "Installing psad from source..."
    dnf install -y iptables perl-NetAddr-IP perl-Bit-Vector perl-Date-Calc perl-Unix-Syslog whois procps-ng 2>&1 | tee -a "$LOG" || true
    cd /tmp
    git clone --depth 1 https://github.com/mrash/psad.git 2>&1 | tee -a "$LOG"
    cd /tmp/psad
    # Non-interactive install: feed scripted answers
    printf 'n\ny\ny\ny\ny\ny\ny\ny\nroot@localhost\nn\ny\nn\nn\ny\n' \
        | perl install.pl 2>&1 | tee -a "$LOG" || warn "psad install had warnings — check log"
    ok "psad installed from source"
    cd "$SCRIPT_DIR"
else
    ok "psad already installed"
fi

ok "All tool installs done"

# =============================================================================
# AUDITD
# =============================================================================
log "=== Configuring auditd ==="

# Back up original rules
cp /etc/audit/rules.d/audit.rules /etc/audit/rules.d/audit.rules.bak 2>/dev/null || true

# Drop our ruleset if it exists next to this script
if [[ -f "$SCRIPT_DIR/audit.rules" ]]; then
    cp "$SCRIPT_DIR/audit.rules" /etc/audit/rules.d/audit.rules
    ok "Copied audit.rules from script dir"
else
    warn "audit.rules not found next to triage-rocky.sh — skipping rule deploy"
fi

# Tune auditd.conf for competition use
sed -i 's/^max_log_file .*/max_log_file = 50/'          /etc/audit/auditd.conf
sed -i 's/^num_logs .*/num_logs = 10/'                  /etc/audit/auditd.conf
sed -i 's/^max_log_file_action .*/max_log_file_action = ROTATE/' /etc/audit/auditd.conf
sed -i 's/^space_left_action .*/space_left_action = SYSLOG/'     /etc/audit/auditd.conf
sed -i 's/^admin_space_left_action .*/admin_space_left_action = SUSPEND/' /etc/audit/auditd.conf

systemctl enable auditd
# auditd has RefuseManualStop=yes — must use legacy service command to restart
service auditd restart

# Load rules immediately without reboot
if command -v augenrules &>/dev/null; then
    augenrules --load 2>&1 | tee -a "$LOG"
    ok "auditd rules loaded"
fi

# =============================================================================
# PROCESS ACCOUNTING
# =============================================================================
log "=== Enabling process accounting ==="

# accton writes every exec to /var/account/pacct — lightweight exec log
if [[ -f /usr/sbin/accton ]]; then
    /usr/sbin/accton /var/account/pacct 2>/dev/null || true
    ok "Process accounting enabled (/var/account/pacct)"
fi

# Rocky uses psacct service (not acct)
systemctl enable psacct 2>/dev/null && systemctl start psacct 2>/dev/null || true

# =============================================================================
# SYSSTAT
# =============================================================================
log "=== Enabling sysstat ==="

# Rocky stores sysstat config in /etc/sysconfig/sysstat (not /etc/default/)
sed -i 's/^ENABLED=.*/ENABLED="true"/' /etc/sysconfig/sysstat 2>/dev/null || true
systemctl enable sysstat
systemctl start sysstat
ok "sysstat enabled"

# =============================================================================
# FAIL2BAN
# =============================================================================
log "=== Configuring fail2ban ==="

cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime  = 1h
findtime = 5m
maxretry = 3
backend  = systemd

[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
maxretry = 3
bantime  = 2h

# Apache jails intentionally omitted — Rocky hosts (SCP-OPENSSH-01, SCP-OPENVPN-01)
# do not run Apache. Enabling them would cause fail2ban to fail on missing log paths.
EOF

systemctl enable fail2ban
systemctl restart fail2ban
ok "fail2ban configured and started"

# =============================================================================
# RKHUNTER
# =============================================================================
log "=== Configuring rkhunter ==="

# Update signature database
rkhunter --update --nocolors 2>&1 | tee -a "$LOG" || warn "rkhunter update failed (no internet?)"

# Build baseline of current file properties
rkhunter --propupd --nocolors 2>&1 | tee -a "$LOG"
ok "rkhunter baseline written"

# Run initial scan and log results
rkhunter --check --sk --nocolors 2>&1 | tee -a "$LOG" || warn "rkhunter found warnings — review log"

# =============================================================================
# CHKROOTKIT
# =============================================================================
log "=== Running chkrootkit ==="

chkrootkit 2>&1 | tee -a "$LOG" | grep -v "^not infected" || true
ok "chkrootkit scan done"

# =============================================================================
# UNHIDE
# =============================================================================
log "=== Running unhide ==="

unhide proc  2>&1 | tee -a "$LOG" || true
unhide sys   2>&1 | tee -a "$LOG" || true
ok "unhide scans done (results in log)"

# =============================================================================
# AIDE — File Integrity Monitoring
# =============================================================================
log "=== Initialising AIDE database ==="

# Rocky ships a single /etc/aide.conf — append competition rules rather than
# using aide.conf.d (which may not be included by default)
AIDE_COMP_CONF="/etc/aide.conf.d/99-competition.conf"
mkdir -p /etc/aide.conf.d
cat > "$AIDE_COMP_CONF" <<'EOF'
# Watch these paths for any change
/etc                Full
/bin                Full
/sbin               Full
/usr/bin            Full
/usr/sbin           Full
/lib                Full
/lib64              Full
/var/www            Full
/var/lib            Full
/root               Full
/home               Full
/tmp                L
/var/tmp            L

# Explicitly ignore noisy runtime paths
!/var/lib/aide
!/var/log
!/proc
!/sys
!/run
!/dev
EOF

# Ensure /etc/aide.conf includes the conf.d directory (idempotent)
if ! grep -q '@@include /etc/aide.conf.d/99-competition.conf' /etc/aide.conf 2>/dev/null; then
    echo '@@include /etc/aide.conf.d/99-competition.conf' >> /etc/aide.conf
    ok "Added @@include /etc/aide.conf.d/99-competition.conf to /etc/aide.conf"
fi

# Build initial database — takes a minute, run in background
aide --init 2>&1 | tee -a "$LOG" &
AIDE_PID=$!
log "AIDE database init running in background (PID $AIDE_PID)"
log "After it completes, promote with: mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
log "Check with: aide --check"

# =============================================================================
# LYNIS — Audit & Recommendations
# =============================================================================
log "=== Running lynis audit ==="

lynis audit system --quick --no-colors 2>&1 | tee "$SCRIPT_DIR/lynis_$(hostname).log" || true
ok "lynis done — results in lynis_$(hostname).log"

# =============================================================================
# LD_PRELOAD & LINKER CHECK
# =============================================================================
log "=== Checking for LD_PRELOAD hooks ==="

if [[ -s /etc/ld.so.preload ]]; then
    warn "NON-EMPTY /etc/ld.so.preload:"
    cat /etc/ld.so.preload | tee -a "$LOG"
else
    ok "/etc/ld.so.preload is clean"
fi

# Rocky uses /etc/bashrc instead of /etc/bash.bashrc
grep -rn "LD_PRELOAD" /etc/environment /etc/profile /etc/profile.d/ \
    /etc/bashrc /root/.bashrc /root/.bash_profile 2>/dev/null | tee -a "$LOG" \
    && warn "LD_PRELOAD found in environment files — review above" \
    || ok "No LD_PRELOAD in environment files"

# =============================================================================
# /PROC vs PS HIDDEN PROCESS CHECK
# =============================================================================
log "=== Checking for hidden processes (/proc vs ps) ==="

comm -23 \
    <(ls /proc | grep -E '^[0-9]+$' | sort -n) \
    <(ps aux | awk 'NR>1{print $2}' | sort -n) \
| while read -r pid; do
    warn "PID $pid in /proc but not in ps — possible hidden process"
    ls -la /proc/"$pid"/exe 2>&1 | tee -a "$LOG" || true
done
ok "Hidden process scan done"

# =============================================================================
# FILELESS / MEMFD CHECK
# =============================================================================
log "=== Checking for memfd/anonymous memory exec ==="

grep -l "memfd:\|/dev/shm\|/tmp" /proc/[0-9]*/maps 2>/dev/null | while read -r m; do
    pid="${m//[^0-9]/}"
    warn "Suspicious memory mapping in PID $pid:"
    grep "memfd:\|/dev/shm\|/tmp" "$m" | tee -a "$LOG"
done || ok "No suspicious memfd mappings found"

# =============================================================================
# CRON BACKDOOR CHECK
# =============================================================================
log "=== Checking cron for unexpected entries ==="

for f in /etc/crontab /etc/cron.d/* /var/spool/cron/*; do
    [[ -f "$f" ]] || continue
    log "--- $f ---"
    cat "$f" | tee -a "$LOG"
done

# =============================================================================
# SUID/SGID BINARY AUDIT
# =============================================================================
log "=== Enumerating SUID/SGID binaries ==="

find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null \
    | tee "$SCRIPT_DIR/suid_$(hostname).txt" \
    | tee -a "$LOG"
ok "SUID/SGID list saved to suid_$(hostname).txt"

# =============================================================================
# LISTENING SERVICES SNAPSHOT
# =============================================================================
log "=== Snapshot of listening ports ==="

ss -tlnpu 2>/dev/null | tee "$SCRIPT_DIR/ports_$(hostname).txt" | tee -a "$LOG"
ok "Port snapshot saved to ports_$(hostname).txt"

# =============================================================================
# ACTIVE CONNECTIONS SNAPSHOT
# =============================================================================
log "=== Active connections ==="

ss -tnpu 2>/dev/null | grep ESTAB | tee -a "$LOG" || ok "No established connections"

# =============================================================================
# AUTHORIZED_KEYS AUDIT
# =============================================================================
log "=== Checking authorized_keys ==="

for home in /root /home/*; do
    keyfile="$home/.ssh/authorized_keys"
    [[ -f "$keyfile" ]] || continue
    log "--- $keyfile ---"
    cat "$keyfile" | tee -a "$LOG"
done

# =============================================================================
# WORLD-WRITABLE FILE AUDIT
# =============================================================================
log "=== Finding world-writable files outside /proc /sys /dev ==="

find / -xdev -not \( -path "/proc/*" -o -path "/sys/*" -o -path "/dev/*" \) \
    -perm -0002 -type f 2>/dev/null \
    | tee "$SCRIPT_DIR/world_writable_$(hostname).txt"
ok "World-writable list saved"

# =============================================================================
# IMMUTABLE FILE FLAGS
# =============================================================================
log "=== Setting immutable flag on critical auth files ==="

# Rocky hosts (SCP-OPENSSH-01 and SCP-OPENVPN-01) both need PasswordAuthentication yes:
#   SCP-OPENSSH-01: SSH scoring checks scp073/scp343 via password auth
#   SCP-OPENVPN-01: scorer SSHes in to query the management interface
# Ensure "yes" is set before locking, so an attacker-set "no" can't get frozen in.
if [[ -f /etc/ssh/sshd_config ]]; then
    chattr -i /etc/ssh/sshd_config 2>/dev/null || true
    if grep -q "^PasswordAuthentication" /etc/ssh/sshd_config; then
        sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
    else
        echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
    fi
    ok "Ensured PasswordAuthentication yes in sshd_config (required for scoring on Rocky hosts)"
fi

for f in /etc/passwd /etc/shadow /etc/gshadow /etc/group \
         /etc/sudoers /etc/ssh/sshd_config /etc/ld.so.preload; do
    [[ -f "$f" ]] || continue
    chattr +i "$f" 2>/dev/null && ok "chattr +i $f" || warn "chattr failed on $f"
done

# To undo before making legitimate changes:
# chattr -i /etc/passwd  (etc.)

# =============================================================================
# /tmp AND /dev/shm HARDENING — noexec, nosuid, nodev
# Wagon stages binaries in /tmp/.cache, beacon.py stages in /tmp/.sys/,
# Vanini's sshbeacon stages through /tmp. Blocking execution here kills
# all three staging paths.
# =============================================================================
log "=== Hardening /tmp and /dev/shm ==="

# Remount /tmp with noexec if it's a separate mount or tmpfs
if mountpoint -q /tmp 2>/dev/null; then
    mount -o remount,noexec,nosuid,nodev /tmp 2>/dev/null \
        && ok "/tmp remounted noexec,nosuid,nodev" \
        || warn "/tmp remount failed"
else
    if ! grep -q '/tmp.*noexec' /etc/fstab; then
        echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=512M 0 0" >> /etc/fstab
        mount -o remount /tmp 2>/dev/null || mount /tmp 2>/dev/null || true
        ok "Added /tmp as tmpfs with noexec to fstab"
    fi
fi

# Remount /dev/shm with noexec (fileless malware staging)
if mountpoint -q /dev/shm 2>/dev/null; then
    mount -o remount,noexec,nosuid,nodev /dev/shm 2>/dev/null \
        && ok "/dev/shm remounted noexec,nosuid,nodev" \
        || warn "/dev/shm remount failed"
fi
if ! grep -q '/dev/shm.*noexec' /etc/fstab; then
    echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
    ok "Added /dev/shm noexec to fstab"
fi

# Remount /var/tmp with noexec
if mountpoint -q /var/tmp 2>/dev/null; then
    mount -o remount,noexec,nosuid,nodev /var/tmp 2>/dev/null \
        && ok "/var/tmp remounted noexec,nosuid,nodev" \
        || warn "/var/tmp remount failed"
fi

# Clean out known Red Team staging directories
for d in /tmp/.cache /tmp/.sys /tmp/.X11-unix/.hidden /dev/shm/.tmp; do
    if [[ -d "$d" ]]; then
        rm -rf "$d"
        warn "Removed suspicious directory: $d"
    fi
done

# =============================================================================
# LOCK DOWN DNF — exclude firewall packages from reinstall
# =============================================================================
log "=== Excluding firewall packages from dnf to prevent reinstall ==="

# Rocky/DNF equivalent of apt pinning: add to excludepkgs in dnf.conf
# dnf5 (Rocky 10) uses 'excludepkgs', older dnf uses 'exclude' — both are accepted
if ! grep -qE '^exclude(pkgs)?=.*iptables' /etc/dnf/dnf.conf; then
    if grep -q '^excludepkgs=' /etc/dnf/dnf.conf; then
        sed -i 's/^excludepkgs=\(.*\)/excludepkgs=\1 iptables nftables firewalld/' /etc/dnf/dnf.conf
    elif grep -q '^exclude=' /etc/dnf/dnf.conf; then
        sed -i 's/^exclude=\(.*\)/exclude=\1 iptables nftables firewalld/' /etc/dnf/dnf.conf
    else
        echo 'excludepkgs=iptables,nftables,firewalld' >> /etc/dnf/dnf.conf
    fi
fi

ok "iptables / nftables / firewalld excluded from dnf"

# Wait for AIDE if still running
if kill -0 "$AIDE_PID" 2>/dev/null; then
    log "Waiting for AIDE init to finish..."
    wait "$AIDE_PID"
    mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz 2>/dev/null \
        && ok "AIDE database promoted" \
        || warn "AIDE db promotion failed — check manually"
fi

log ""
log "=== Triage complete on $(hostname) ==="
log "Artifacts in $SCRIPT_DIR:"
ls -1 "$SCRIPT_DIR"/*.{log,txt} 2>/dev/null | tee -a "$LOG" || true
log ""
log "Manual follow-ups:"
log "  - Copy audit.rules from repo and run: augenrules --load"
log "  - Review lynis_$(hostname).log for hardening recommendations"
log "  - Review suid_$(hostname).txt for unexpected SUID binaries"
log "  - Review world_writable_$(hostname).txt"
log "  - To check AIDE later: aide --check"
log "  - To unfreeze a file before editing: chattr -i <file>"
log "  - To watch a directory live: inotifywait -m -r /var/www"
log "  - Useful auditd queries:"
log "      ausearch -k priv_esc -ts recent"
log "      ausearch -k webroot_write -ts recent"
log "      ausearch -k exec -ts today | grep -v auid=0"
log "      ausearch -k flag_access -ts recent"
