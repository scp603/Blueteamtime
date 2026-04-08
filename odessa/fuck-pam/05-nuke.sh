#!/usr/bin/env bash
# =============================================================================
# 05-nuke.sh  [LEVEL 5 — SCORCHED EARTH]
# Nuclear PAM reset. Assumes the entire PAM stack may be compromised.
#
# Actions (in order):
#   1. Unfreeze all PAM files
#   2. Preserve evidence
#   3. Kill ALL non-distro .so files in PAM security dirs (anything not owned
#      by an installed package is treated as hostile)
#   4. Reinstall PAM from the distro package manager (Ubuntu or Rocky)
#   5. Force-regenerate PAM configs from scratch
#   6. Lock EVERYTHING immutable
#   7. Add a canary inotifywait watcher for the PAM dirs
#
# WARNING: If your sshd_config uses PAM and you nuke PAM incorrectly,
# you CAN lock yourself out. Keep a second session open while running this.
# Run as root.
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
YLW='\033[1;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

[[ $EUID -ne 0 ]] && { echo "Run as root" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="$SCRIPT_DIR/nuke_$(hostname)_$(date +%Y%m%d_%H%M%S).log"
EVIDENCE_DIR="$SCRIPT_DIR/nuke_evidence_$(date +%Y%m%d_%H%M%S)"

log()  { echo -e "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
ok()   { echo -e "${GRN}[OK]${RST}  $*" | tee -a "$LOG"; }
warn() { echo -e "${YLW}[WARN]${RST} $*" | tee -a "$LOG"; }
hit()  { echo -e "${RED}[NUKE]${RST} $*" | tee -a "$LOG"; }

log "${BLD}=== PAM SCORCHED EARTH — $(hostname) ===${RST}"
log "WARNING: Keep a second session open in case auth breaks mid-run"
mkdir -p "$EVIDENCE_DIR"

# =============================================================================
# 1. Unfreeze everything so we can modify it
# =============================================================================
log "\n--- [1/7] Unfreezing PAM files ---"
find /etc/pam.d/ -type f -exec chattr -i {} \; 2>/dev/null || true

PAM_DIRS=(/lib/security /lib64/security /usr/lib/security
          /usr/lib64/security /usr/lib/x86_64-linux-gnu/security)

for dir in "${PAM_DIRS[@]}"; do
    [[ -d "$dir" ]] || continue
    chattr -i "$dir" 2>/dev/null || true
    find "$dir" -type f -exec chattr -i {} \; 2>/dev/null || true
done
ok "All PAM files unfrozen"

# =============================================================================
# 2. Snapshot everything before touching it
# =============================================================================
log "\n--- [2/7] Preserving evidence ---"
cp -rp /etc/pam.d/ "$EVIDENCE_DIR/pam.d"
for dir in "${PAM_DIRS[@]}"; do
    [[ -d "$dir" ]] && cp -rp "$dir" "$EVIDENCE_DIR/$(basename $dir)_$(dirname $dir | tr / _)" || true
done
for lf in /etc/logcheck/pam_auth.log /etc/logcheck/pam.log \
          /var/log/pam_backdoor_alerts.log; do
    [[ -f "$lf" ]] && cp "$lf" "$EVIDENCE_DIR/" || true
done
ok "Evidence in $EVIDENCE_DIR"

# =============================================================================
# 3. Detect OS for package manager commands
# =============================================================================
log "\n--- [3/7] Detecting OS ---"

if [[ -f /etc/debian_version ]]; then
    OS="ubuntu"
    log "Detected: Debian/Ubuntu"
elif [[ -f /etc/rocky-release ]] || [[ -f /etc/redhat-release ]]; then
    OS="rocky"
    log "Detected: Rocky/RHEL"
else
    OS="unknown"
    warn "OS not detected — package reinstall step will be skipped"
fi

# =============================================================================
# 4. Purge ALL non-package-owned .so files from PAM security dirs
#    Anything not owned by an installed package is hostile
# =============================================================================
log "\n--- [4/7] Purging non-distro .so files from PAM dirs ---"

for dir in "${PAM_DIRS[@]}"; do
    [[ -d "$dir" ]] || continue
    for so in "$dir"/*.so; do
        [[ -f "$so" ]] || continue

        is_owned=0
        if [[ "$OS" == "ubuntu" ]]; then
            dpkg -S "$so" &>/dev/null 2>&1 && is_owned=1 || true
        elif [[ "$OS" == "rocky" ]]; then
            rpm -qf "$so" &>/dev/null 2>&1 && is_owned=1 || true
        fi

        if [[ $is_owned -eq 0 ]]; then
            cp -p "$so" "$EVIDENCE_DIR/"
            rm -f "$so"
            hit "Removed unowned module: $so"
        else
            ok "Package-owned (kept): $so"
        fi
    done
done

# Also sweep for anything outside PAM dirs entirely
find / -xdev -name "pam_error_mod*.so" -o -name "pam_auth_mod*.so" 2>/dev/null \
| while read -r f; do
    cp -p "$f" "$EVIDENCE_DIR/" 2>/dev/null || true
    rm -f "$f"
    hit "Removed stray copy: $f"
done

# =============================================================================
# 5. Reinstall PAM packages from distro — restores any .so files that were
#    replaced and regenerates distro-default configs
# =============================================================================
log "\n--- [5/7] Reinstalling PAM from distro packages ---"

if [[ "$OS" == "ubuntu" ]]; then
    # Unfreeze apt
    sed -i '/pam\|libpam/d' /etc/apt/preferences.d/no-firewall 2>/dev/null || true
    apt-get update -qq
    apt-get install --reinstall -y \
        libpam-runtime libpam-modules libpam-modules-bin \
        libpam0g libpam-systemd \
        2>&1 | tee -a "$LOG"
    ok "Ubuntu PAM packages reinstalled"

    # Regenerate configs from debconf/ucf selections
    DEBIAN_FRONTEND=noninteractive pam-auth-update --force 2>&1 | tee -a "$LOG" || true
    ok "pam-auth-update completed"

elif [[ "$OS" == "rocky" ]]; then
    dnf reinstall -y pam 2>&1 | tee -a "$LOG"
    ok "Rocky pam package reinstalled"

    # authselect regenerates configs on Rocky
    if command -v authselect &>/dev/null; then
        authselect select sssd --force 2>&1 | tee -a "$LOG" || \
        authselect select minimal --force 2>&1 | tee -a "$LOG" || true
        ok "authselect config regenerated"
    fi
else
    warn "Skipping package reinstall — unknown OS (do it manually)"
fi

# =============================================================================
# 6. Remove dropped artifacts
# =============================================================================
log "\n--- [6/7] Removing dropped scripts and logs ---"

for f in /usr/local/bin/pam_auth_logger.sh \
         /tmp/pam_auth_logger.sh \
         /etc/logcheck/pam_auth.log \
         /etc/logcheck/pam.log; do
    if [[ -f "$f" ]]; then
        cp "$f" "$EVIDENCE_DIR/" 2>/dev/null || true
        rm -f "$f"
        hit "Removed: $f"
    fi
done

# Clean /etc/environment
sed -i '/^PAM_DEBUG=/d' /etc/environment 2>/dev/null || true
ok "/etc/environment cleaned"

# Stop watcher service if running
systemctl stop pam-backdoor-watch.service 2>/dev/null || true
systemctl disable pam-backdoor-watch.service 2>/dev/null || true
rm -f /etc/systemd/system/pam-backdoor-watch.service
systemctl daemon-reload

# =============================================================================
# 7. Lock everything immutable + add inotify canary for future tampering
# =============================================================================
log "\n--- [7/7] Locking PAM and installing canary ---"

# Lock all PAM config files
find /etc/pam.d/ -type f | while read -r f; do
    chattr +i "$f" 2>/dev/null && ok "chattr +i $f" || warn "chattr failed: $f"
done

# Lock PAM security dirs (prevents adding new .so files)
for dir in "${PAM_DIRS[@]}"; do
    [[ -d "$dir" ]] || continue
    # Lock individual files, not the dir itself (dir lock breaks package manager)
    find "$dir" -type f | while read -r f; do
        chattr +i "$f" 2>/dev/null || true
    done
    ok "All .so files in $dir locked immutable"
done

# Install inotifywait canary to alert on any PAM dir modification
if command -v inotifywait &>/dev/null; then
    CANARY="/usr/local/bin/pam_canary.sh"
    cat > "$CANARY" <<'CANEOF'
#!/usr/bin/env bash
# PAM directory tampering canary — alerts on any write to PAM dirs
ALERT_LOG="/var/log/pam_tamper_alerts.log"

inotifywait -m -r -e create,modify,delete,moved_to \
    /etc/pam.d/ /lib/security /lib64/security \
    /usr/lib/x86_64-linux-gnu/security 2>/dev/null \
| while read -r dir event file; do
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    msg="[$ts] PAM_TAMPER event=$event path=${dir}${file}"
    echo "$msg" | tee -a "$ALERT_LOG"
    echo "$msg" > /dev/kmsg 2>/dev/null || true
done
CANEOF
    chmod +x "$CANARY"

    cat > /etc/systemd/system/pam-canary.service <<'SVCEOF'
[Unit]
Description=PAM directory tampering canary
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/pam_canary.sh
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable pam-canary.service
    systemctl restart pam-canary.service
    ok "PAM tamper canary running — alerts → /var/log/pam_tamper_alerts.log"
else
    warn "inotifywait not installed — install inotify-tools for the canary"
fi

# =============================================================================
# FINAL REPORT
# =============================================================================
log ""
log "${BLD}=== Nuke complete — $(hostname) ===${RST}"
log "Evidence: $EVIDENCE_DIR"
log ""
log "Verify auth still works:"
log "  ${CYN}ssh -o ConnectTimeout=5 $(hostname) 'echo auth ok'${RST}"
log ""
log "Monitor for future tampering:"
log "  ${CYN}tail -F /var/log/pam_tamper_alerts.log${RST}"
log "  ${CYN}journalctl -kf | grep PAM_TAMPER${RST}"
log ""
log "To undo immutable locks before legitimate PAM changes:"
log "  ${CYN}find /etc/pam.d/ -type f -exec chattr -i {} \\;${RST}"
