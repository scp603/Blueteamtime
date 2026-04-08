#!/usr/bin/env bash
# =============================================================================
# build-and-install.sh
# Compiles pam_trap_mod.c → pam_error_mod.so and drops it exactly where
# the red team's module lives, on both Ubuntu and Rocky.
# Run as root.
# =============================================================================

set -euo pipefail

[[ $EUID -ne 0 ]] && { echo "Run as root" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SCRIPT_DIR/pam_trap_mod.c"
OUT="$SCRIPT_DIR/pam_error_mod.so"

[[ -f "$SRC" ]] || { echo "pam_trap_mod.c not found at $SRC" >&2; exit 1; }

# --- detect PAM security dir and set compiler flags ---
if [[ -f /etc/debian_version ]]; then
    PAM_DIR="/usr/lib/x86_64-linux-gnu/security"
    [[ -d "$PAM_DIR" ]] || PAM_DIR="/lib/security"
    EXTRA_FLAGS=""
    DEV_PKG="libpam0g-dev"
else
    PAM_DIR="/lib64/security"
    [[ -d "$PAM_DIR" ]] || PAM_DIR="/lib/security"
    EXTRA_FLAGS="-ldl"
    DEV_PKG="pam-devel"
fi

# --- ensure PAM dev headers are present ---
if ! find /usr/include -name "pam_modules.h" 2>/dev/null | grep -q .; then
    echo "PAM headers missing — installing $DEV_PKG..."
    if command -v apt-get &>/dev/null; then
        apt-get install -y "$DEV_PKG"
    else
        dnf install -y "$DEV_PKG"
    fi
fi

# --- compile ---
echo "Compiling $SRC..."
gcc -fPIC -shared -Wno-format-security \
    -o "$OUT" "$SRC" \
    -lpam $EXTRA_FLAGS

echo "Built: $OUT"
echo "SHA256: $(sha256sum "$OUT")"

# --- back up whatever is already there ---
TARGET="$PAM_DIR/pam_error_mod.so"
if [[ -f "$TARGET" ]]; then
    BACKUP="${TARGET}.bak_$(date +%Y%m%d_%H%M%S)"
    cp -p "$TARGET" "$BACKUP"
    echo "Backed up original → $BACKUP"
fi

# --- install ---
cp -f "$OUT" "$TARGET"
chmod 644 "$TARGET"
echo "Installed → $TARGET"
echo "SHA256: $(sha256sum "$TARGET")"
echo ""
echo "Trap is live. Monitor with:"
echo "  tail -F /var/log/pam_backdoor_alerts.log"
echo "  journalctl -kf | grep PAM_TRAP"
