#!/usr/bin/env bash
# =============================================================================
# 03-poison.sh  [LEVEL 3 — SWAP THE MODULE WITH A TRAP]
# Compiles pam_trap_mod.c and hot-swaps it for the real pam_error_mod.so.
# The red team's backdoor stays in place — same filename, same log path —
# but every bypass attempt now returns PAM_AUTH_ERR and fires an alert.
# They won't know until they try it and get denied.
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
LOG="$SCRIPT_DIR/poison_$(hostname)_$(date +%Y%m%d_%H%M%S).log"
TRAP_SRC="$SCRIPT_DIR/pam_trap_mod.c"

log()  { echo -e "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
ok()   { echo -e "${GRN}[OK]${RST}  $*" | tee -a "$LOG"; }
warn() { echo -e "${YLW}[WARN]${RST} $*" | tee -a "$LOG"; }
die()  { echo -e "${RED}[FAIL]${RST} $*" | tee -a "$LOG"; exit 1; }

log "${BLD}=== Poison module swap — $(hostname) ===${RST}"

# =============================================================================
# 0. Sanity checks
# =============================================================================
[[ -f "$TRAP_SRC" ]] || die "pam_trap_mod.c not found at $TRAP_SRC"
command -v gcc &>/dev/null || die "gcc not installed — install build-essential / gcc"

# =============================================================================
# 1. Detect OS and set PAM security dir + compiler flags
# =============================================================================
if [[ -f /etc/debian_version ]]; then
    PAM_DIR="/usr/lib/x86_64-linux-gnu/security"
    [[ -d "$PAM_DIR" ]] || PAM_DIR="/lib/security"
    CFLAGS="-fPIC -shared -lpam -Wno-format-security"
    DEV_PKG="libpam0g-dev"
else
    PAM_DIR="/lib64/security"
    [[ -d "$PAM_DIR" ]] || PAM_DIR="/lib/security"
    CFLAGS="-fPIC -shared -lpam -ldl -Wno-format-security"
    DEV_PKG="pam-devel"
fi

# Check PAM dev headers
if ! find /usr/include -name "pam_modules.h" &>/dev/null; then
    warn "PAM dev headers not found — attempting install of $DEV_PKG"
    if command -v apt-get &>/dev/null; then
        apt-get install -y "$DEV_PKG" 2>&1 | tee -a "$LOG"
    elif command -v dnf &>/dev/null; then
        dnf install -y "$DEV_PKG" 2>&1 | tee -a "$LOG"
    fi
fi

# =============================================================================
# 2. Find the installed malicious module
# =============================================================================
TARGET_SO=""
for candidate in "$PAM_DIR/pam_error_mod.so" \
                 "/lib/security/pam_error_mod.so" \
                 "/lib64/security/pam_error_mod.so"; do
    if [[ -f "$candidate" ]]; then
        TARGET_SO="$candidate"
        break
    fi
done

if [[ -z "$TARGET_SO" ]]; then
    warn "pam_error_mod.so not found in standard PAM dirs — searching wider..."
    TARGET_SO=$(find / -xdev -name "pam_error_mod.so" 2>/dev/null | head -1) || true
fi

[[ -n "$TARGET_SO" ]] || die "Could not locate pam_error_mod.so — run 01-detect.sh first"

log "Target module: $TARGET_SO"
log "SHA256 (before): $(sha256sum "$TARGET_SO")"

# =============================================================================
# 3. Back up the original
# =============================================================================
BACKUP="${TARGET_SO}.original_$(date +%Y%m%d_%H%M%S)"
cp -p "$TARGET_SO" "$BACKUP"
ok "Original backed up to $BACKUP"

# =============================================================================
# 4. Compile the trap module
# =============================================================================
TRAP_SO="$SCRIPT_DIR/pam_error_mod.so"
log "Compiling trap module..."
gcc $CFLAGS -o "$TRAP_SO" "$TRAP_SRC" 2>&1 | tee -a "$LOG"
ok "Compiled: $TRAP_SO"

# =============================================================================
# 5. Atomic hot-swap — copy over the existing .so in place
#    PAM loads modules at auth time, so the next auth attempt uses the new .so
# =============================================================================
cp -f "$TRAP_SO" "$TARGET_SO"
chmod 644 "$TARGET_SO"
ok "Hot-swapped: $TARGET_SO now contains the trap module"
log "SHA256 (after):  $(sha256sum "$TARGET_SO")"

# =============================================================================
# 6. Ensure alert log exists and is writable
# =============================================================================
mkdir -p /var/log /etc/logcheck
touch /var/log/pam_backdoor_alerts.log
touch /etc/logcheck/pam_auth.log
ok "Alert logs ready"

log ""
log "${BLD}=== Swap complete ===${RST}"
log "The trap is armed. Red team's backdoor is now a tripwire."
log ""
log "Monitor for attempts:"
log "  ${CYN}tail -F /var/log/pam_backdoor_alerts.log${RST}"
log "  ${CYN}journalctl -kf | grep PAM_TRAP${RST}"
log ""
log "When you see 'BACKDOOR_ATTEMPT' → cross-reference PID with ssh-kill.sh"
log "Original module preserved at: $BACKUP (evidence — do not delete)"
