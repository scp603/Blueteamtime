#!/usr/bin/env bash
# =============================================================================
# 04-evict.sh  [LEVEL 4 — HARD REMOVAL]
# Surgically removes pam_error_mod.so and cleans every PAM config that
# references it. Restores distro backups where available.
# Does NOT nuke the entire PAM stack — see 05-nuke.sh for that.
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
LOG="$SCRIPT_DIR/evict_$(hostname)_$(date +%Y%m%d_%H%M%S).log"
EVIDENCE_DIR="$SCRIPT_DIR/evidence_$(date +%Y%m%d_%H%M%S)"

log()  { echo -e "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
ok()   { echo -e "${GRN}[OK]${RST}  $*" | tee -a "$LOG"; }
warn() { echo -e "${YLW}[WARN]${RST} $*" | tee -a "$LOG"; }
hit()  { echo -e "${RED}[RM]${RST}  $*" | tee -a "$LOG"; }

log "${BLD}=== PAM eviction — $(hostname) ===${RST}"
mkdir -p "$EVIDENCE_DIR"
log "Evidence preserved in: $EVIDENCE_DIR"

# =============================================================================
# 1. Unfreeze PAM files that may have been chattr +i'd (our own lockdown or theirs)
# =============================================================================
log "\n--- Unfreezing PAM files for editing ---"
find /etc/pam.d/ -type f -exec chattr -i {} \; 2>/dev/null || true

# =============================================================================
# 2. Collect evidence before touching anything
# =============================================================================
log "\n--- Collecting evidence ---"
cp -r /etc/pam.d/ "$EVIDENCE_DIR/pam.d_backup"
ok "PAM config snapshot saved"

for lf in /etc/logcheck/pam_auth.log /etc/logcheck/pam.log \
           /var/log/pam_backdoor_alerts.log; do
    [[ -f "$lf" ]] && cp "$lf" "$EVIDENCE_DIR/" && ok "Copied $lf"
done

# =============================================================================
# 3. Remove all instances of pam_error_mod.so / pam_auth_mod.so
# =============================================================================
log "\n--- Removing malicious .so files ---"

PAM_DIRS=(/lib/security /lib64/security /usr/lib/security
          /usr/lib64/security /usr/lib/x86_64-linux-gnu/security)

for dir in "${PAM_DIRS[@]}"; do
    [[ -d "$dir" ]] || continue
    for name in pam_error_mod.so pam_auth_mod.so; do
        if [[ -f "$dir/$name" ]]; then
            cp -p "$dir/$name" "$EVIDENCE_DIR/${name}_$(basename $dir)"
            rm -f "$dir/$name"
            hit "Removed $dir/$name (copy in evidence dir)"
        fi
    done
done

# Catch any copies outside standard PAM dirs
find / -xdev -name "pam_error_mod*.so" -o -name "pam_auth_mod*.so" 2>/dev/null \
| while read -r f; do
    cp -p "$f" "$EVIDENCE_DIR/"
    rm -f "$f"
    hit "Removed non-standard copy: $f"
done

# =============================================================================
# 4. Clean PAM configs — remove lines referencing the backdoor modules
# =============================================================================
log "\n--- Cleaning /etc/pam.d/ entries ---"

PATTERNS=(
    "pam_error_mod"
    "pam_auth_mod"
    "pam_auth_logger"    # installer.py drops this script name
)

for cfg in /etc/pam.d/*; do
    [[ -f "$cfg" ]] || continue
    changed=0
    for pat in "${PATTERNS[@]}"; do
        if grep -q "$pat" "$cfg" 2>/dev/null; then
            cp "$cfg" "${cfg}.pre_evict_$(date +%Y%m%d_%H%M%S)"
            sed -i "/$pat/d" "$cfg"
            hit "Removed '$pat' lines from $cfg"
            changed=1
        fi
    done
    # Also remove pam_exec.so lines pointing at pam_auth_logger.sh
    if grep -qE "pam_exec\.so.*pam_auth_logger" "$cfg" 2>/dev/null; then
        sed -i '/pam_exec\.so.*pam_auth_logger/d' "$cfg"
        hit "Removed pam_exec auth hook from $cfg"
        changed=1
    fi
done

# =============================================================================
# 5. Remove the dropped logger script
# =============================================================================
log "\n--- Removing dropped logger script ---"

for lp in /usr/local/bin/pam_auth_logger.sh /tmp/pam_auth_logger.sh; do
    if [[ -f "$lp" ]]; then
        cp "$lp" "$EVIDENCE_DIR/"
        rm -f "$lp"
        hit "Removed $lp"
    fi
done

# =============================================================================
# 6. Remove PAM_DEBUG from /etc/environment (set by 02-expose.sh)
# =============================================================================
log "\n--- Cleaning /etc/environment ---"
sed -i '/^PAM_DEBUG=/d' /etc/environment 2>/dev/null || true
ok "/etc/environment cleaned"

# =============================================================================
# 7. Stop and remove the watcher service (from 02-expose.sh)
# =============================================================================
log "\n--- Removing pam-backdoor-watch service ---"
systemctl stop pam-backdoor-watch.service  2>/dev/null || true
systemctl disable pam-backdoor-watch.service 2>/dev/null || true
rm -f /etc/systemd/system/pam-backdoor-watch.service \
      /usr/local/bin/pam_backdoor_watch.sh
systemctl daemon-reload
ok "Watch service removed"

# =============================================================================
# 8. Lock down the cleaned PAM configs with chattr +i
# =============================================================================
log "\n--- Locking PAM configs immutable ---"
for cfg in /etc/pam.d/sshd /etc/pam.d/login /etc/pam.d/sudo \
           /etc/pam.d/su   /etc/pam.d/common-auth; do
    [[ -f "$cfg" ]] || continue
    chattr +i "$cfg" 2>/dev/null && ok "chattr +i $cfg" || warn "chattr failed on $cfg"
done

# Lock the entire PAM security dirs to prevent new .so injection
for dir in "${PAM_DIRS[@]}"; do
    [[ -d "$dir" ]] || continue
    chattr +i "$dir" 2>/dev/null && ok "chattr +i $dir (directory)" || warn "chattr failed on $dir"
done

# =============================================================================
# 9. Quick verification — confirm no references remain
# =============================================================================
log "\n--- Verification pass ---"
remaining=$(grep -rl "pam_error_mod\|pam_auth_mod\|pam_auth_logger" \
    /etc/pam.d/ 2>/dev/null || true)
if [[ -n "$remaining" ]]; then
    warn "Some references still present — review manually:"
    echo "$remaining" | tee -a "$LOG"
else
    ok "No remaining references in /etc/pam.d/"
fi

log ""
log "${BLD}=== Eviction complete ===${RST}"
log "Evidence preserved in: $EVIDENCE_DIR"
log ""
log "IMPORTANT — test auth before closing your session:"
log "  Open a NEW SSH session to verify login still works before exiting this one"
log "  If login fails: chattr -i /etc/pam.d/sshd and check the config manually"
