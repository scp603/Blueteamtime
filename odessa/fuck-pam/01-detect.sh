#!/usr/bin/env bash
# =============================================================================
# 01-detect.sh  [LEVEL 1 — FORENSIC SCAN]
# Finds every trace of pam_error_mod on this machine.
# Source of truth: filesystem + /proc. Does NOT trust package managers.
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
OUT="$SCRIPT_DIR/detect_$(hostname)_$(date +%Y%m%d_%H%M%S).txt"

log()  { echo -e "$*" | tee -a "$OUT"; }
hit()  { echo -e "${RED}[HIT]${RST} $*" | tee -a "$OUT"; }
ok()   { echo -e "${GRN}[OK]${RST}  $*" | tee -a "$OUT"; }
info() { echo -e "${CYN}[INFO]${RST} $*" | tee -a "$OUT"; }

log "\n${BLD}=== pam_error_mod Detection Report — $(hostname) — $(date) ===${RST}\n"

# =============================================================================
# 1. KNOWN FILENAMES — search all PAM security dirs + common drop locations
# =============================================================================
log "${BLD}--- 1. Known filename search ---${RST}"

PAM_DIRS=(/lib/security /lib64/security /usr/lib/security
          /usr/lib64/security /usr/lib/x86_64-linux-gnu/security)
KNOWN_NAMES=(pam_error_mod.so pam_error_mod pam_auth_mod.so pam_auth_mod)

for dir in "${PAM_DIRS[@]}"; do
    [[ -d "$dir" ]] || continue
    for name in "${KNOWN_NAMES[@]}"; do
        if [[ -f "$dir/$name" ]]; then
            hit "Found: $dir/$name"
            ls -la "$dir/$name" | tee -a "$OUT"
            sha256sum "$dir/$name" | tee -a "$OUT"
        fi
    done
done

# Broader filesystem search (catches relocated copies)
info "Scanning filesystem for pam_error_mod.so (may take a moment)..."
find / -xdev -name "pam_error_mod*.so" -o -name "pam_auth_mod*.so" 2>/dev/null \
    | tee -a "$OUT" | while read -r f; do hit "Non-standard location: $f"; done

# =============================================================================
# 2. SIGNATURE STRINGS — scan all .so files in PAM dirs for backdoor strings
#    Even if the file was renamed, these strings survive
# =============================================================================
log "\n${BLD}--- 2. Signature string scan (renamed .so detection) ---${RST}"

SIGNATURES=(
    "PAM_SETAUTH"          # env-var bypass name
    "password123"          # hardcoded credential
    "cyberrange"           # hardcoded username
    "pam_auth.log"         # module's log file path
    "PAM_DEBUG"            # module's debug switch
    "Hardcoded password"   # log message string
)

for dir in "${PAM_DIRS[@]}"; do
    [[ -d "$dir" ]] || continue
    for so in "$dir"/*.so; do
        [[ -f "$so" ]] || continue
        for sig in "${SIGNATURES[@]}"; do
            if strings "$so" 2>/dev/null | grep -q "$sig"; then
                hit "Signature '$sig' found in: $so"
            fi
        done
    done
done

# =============================================================================
# 3. PAM CONFIG AUDIT — find any reference to the module in /etc/pam.d/
# =============================================================================
log "\n${BLD}--- 3. PAM configuration audit (/etc/pam.d/) ---${RST}"

TRIGGER=0
for cfg in /etc/pam.d/*; do
    [[ -f "$cfg" ]] || continue
    matches=$(grep -nE "pam_error_mod|pam_auth_mod" "$cfg" 2>/dev/null || true)
    if [[ -n "$matches" ]]; then
        hit "PAM config references backdoor module: $cfg"
        echo "$matches" | tee -a "$OUT"
        TRIGGER=1
    fi
done
[[ $TRIGGER -eq 0 ]] && ok "No PAM configs reference the backdoor module by name"

# Also look for pam_exec.so entries (installer.py uses this)
log ""
info "Checking for pam_exec.so auth hooks (installer.py method):"
grep -rn "pam_exec.so" /etc/pam.d/ 2>/dev/null | tee -a "$OUT" \
    | while read -r line; do hit "pam_exec hook: $line"; done || ok "No pam_exec.so auth hooks found"

# =============================================================================
# 4. LOG FILE CHECK — did the module already run and capture credentials?
# =============================================================================
log "\n${BLD}--- 4. Backdoor log file check ---${RST}"

LOG_PATHS=(/etc/logcheck/pam_auth.log /etc/logcheck/pam.log)

for lf in "${LOG_PATHS[@]}"; do
    if [[ -f "$lf" ]]; then
        hit "Backdoor log file exists: $lf"
        info "  Size: $(wc -l < "$lf") lines | $(du -sh "$lf" | cut -f1)"
        info "  Last 20 entries:"
        tail -20 "$lf" | tee -a "$OUT"
    else
        ok "Log file not present: $lf"
    fi
done

# =============================================================================
# 5. LOGGER SCRIPT CHECK — installer.py drops a bash auth logger
# =============================================================================
log "\n${BLD}--- 5. Dropped logger script check ---${RST}"

LOGGER_PATHS=(/usr/local/bin/pam_auth_logger.sh /tmp/pam_auth_logger.sh)
for lp in "${LOGGER_PATHS[@]}"; do
    if [[ -f "$lp" ]]; then
        hit "Dropped logger script found: $lp"
        cat "$lp" | tee -a "$OUT"
    fi
done

# =============================================================================
# 6. PAM PROCESS CHECK — look for suspicious child processes of sshd/login
# =============================================================================
log "\n${BLD}--- 6. Suspicious PAM exec processes ---${RST}"

ps auxf 2>/dev/null | grep -E "pam_auth_logger|pam_exec|pam_error" \
    | grep -v grep | tee -a "$OUT" \
    | while read -r line; do hit "Suspicious process: $line"; done || ok "No suspicious PAM processes running"

# =============================================================================
# SUMMARY
# =============================================================================
log "\n${BLD}=== Detection complete — results in $OUT ===${RST}"
log "Next steps:"
log "  If module found  → run 02-expose.sh to make it log everything, then 04-evict.sh"
log "  If log files found → credentials may have been captured — rotate ALL passwords now"
log "  If pam_exec hooks found → remove them from /etc/pam.d/ immediately"
