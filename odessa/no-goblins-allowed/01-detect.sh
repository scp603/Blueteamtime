#!/usr/bin/env bash
# =============================================================================
# 01-detect.sh  [LEVEL 1 — FORENSIC SCAN]
# Detects signs of Goblin-Wagon infection on this host.
# Sources: /proc, filesystem, network, sudo config, cron.
# Does NOT use ps/who/w — those can be spoofed.
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
hit()  { echo -e "${RED}[HIT]${RST}  $*" | tee -a "$OUT"; }
ok()   { echo -e "${GRN}[OK]${RST}   $*" | tee -a "$OUT"; }
info() { echo -e "${CYN}[INFO]${RST} $*" | tee -a "$OUT"; }
warn() { echo -e "${YLW}[WARN]${RST} $*" | tee -a "$OUT"; }

log "\n${BLD}=== Goblin-Wagon Detection — $(hostname) — $(date) ===${RST}\n"

# =============================================================================
# 1. PROOF FILE — worm's test payload writes this on successful infection
# =============================================================================
log "${BLD}--- 1. Infection proof file ---${RST}"
if [[ -f /etc/redteam_was_here.txt ]]; then
    hit "/etc/redteam_was_here.txt EXISTS — this host was successfully reached"
    ls -la /etc/redteam_was_here.txt | tee -a "$OUT"
    stat /etc/redteam_was_here.txt | tee -a "$OUT"
else
    ok "/etc/redteam_was_here.txt not present"
fi

# =============================================================================
# 2. KNOWN DROP LOCATIONS — worm drops to /tmp/.cache/ disguised as system binaries
# =============================================================================
log "\n${BLD}--- 2. Known drop locations ---${RST}"

DROP_PATHS=(
    /tmp/.cache/systemd-update
    /tmp/.cache/dbus-helper
    /tmp/.cache/wagon
    /tmp/.cache/goblin-wagon
    /tmp/systemd-update
    /tmp/dbus-helper
    /var/tmp/systemd-update
    /var/tmp/dbus-helper
)

for p in "${DROP_PATHS[@]}"; do
    if [[ -f "$p" ]]; then
        hit "Worm binary candidate: $p"
        ls -la "$p" | tee -a "$OUT"
        file "$p" | tee -a "$OUT"
        sha256sum "$p" | tee -a "$OUT"
    fi
done

# Broader sweep for ELF binaries in temp dirs
info "Scanning /tmp and /var/tmp for ELF executables..."
find /tmp /var/tmp -type f 2>/dev/null | while read -r f; do
    head -c 4 "$f" 2>/dev/null | grep -qP '^\x7fELF' || continue
    hit "ELF binary in temp dir: $f"
    ls -la "$f" | tee -a "$OUT"
    sha256sum "$f" | tee -a "$OUT"
done

# =============================================================================
# 3. RUNNING PROCESSES — walk /proc directly (not ps)
#    Look for: goblin-wagon, wagon, systemd-update, dbus-helper
# =============================================================================
log "\n${BLD}--- 3. Suspicious running processes (via /proc) ---${RST}"

WORM_NAMES=("goblin-wagon" "wagon" "systemd-update" "dbus-helper")
found_procs=0

for pid_dir in /proc/[0-9]*/; do
    pid="${pid_dir%/}"
    pid="${pid##*/}"
    cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null | xargs 2>/dev/null || true)
    [[ -z "$cmdline" ]] && continue

    for name in "${WORM_NAMES[@]}"; do
        if echo "$cmdline" | grep -qi "$name"; then
            hit "Suspicious process PID $pid: $cmdline"
            ls -la "$pid_dir/exe" 2>/dev/null | tee -a "$OUT" || true
            found_procs=$((found_procs + 1))
        fi
    done

    # Also look for: bash -c sudo -n bash -c (wagon payload execution pattern)
    if echo "$cmdline" | grep -q "sudo -n bash"; then
        hit "Wagon payload execution pattern in PID $pid: $cmdline"
        found_procs=$((found_procs + 1))
    fi
done

[[ $found_procs -eq 0 ]] && ok "No worm process names found in /proc"

# =============================================================================
# 4. NETWORK — look for outbound SSH connections to the blue team subnet
#    Worm spreads to 10.10.10.1-199 via SSH (:22) and WinRM (:5985)
# =============================================================================
log "\n${BLD}--- 4. Suspicious outbound connections (/proc/net/tcp) ---${RST}"

parse_tcp() {
    local file="$1"
    [[ -f "$file" ]] || return
    while read -r sl local rem st rest; do
        [[ "$sl" == "sl" ]] && continue
        [[ "$st" == "01" ]] || continue  # SYN_SENT
        [[ "$st" == "02" ]] || [[ "$st" == "01" ]] || continue

        rem_ip_hex="${rem%:*}"
        rem_port_hex="${rem##*:}"
        rem_port=$(printf '%d' "0x$rem_port_hex")
        rem_ip=$(printf '%d.%d.%d.%d' \
            "0x${rem_ip_hex:6:2}" "0x${rem_ip_hex:4:2}" \
            "0x${rem_ip_hex:2:2}" "0x${rem_ip_hex:0:2}")

        if [[ "$rem_port" -eq 22 || "$rem_port" -eq 5985 ]]; then
            hit "Outbound to $rem_ip:$rem_port (SSH/WinRM) — possible worm spread"
        fi
    done < "$file"
}

parse_tcp /proc/net/tcp
parse_tcp /proc/net/tcp6

# Also check for HTTP server on :8080 (worm can serve itself via python3 -m http.server)
if grep -q "1F90" /proc/net/tcp 2>/dev/null; then
    warn "Something is listening on port 8080 — worm can self-serve via HTTP on this port"
    grep "1F90" /proc/net/tcp | tee -a "$OUT"
fi

# =============================================================================
# 5. HARDCODED CREDENTIALS — check if the known worm accounts exist and have weak passwords
# =============================================================================
log "\n${BLD}--- 5. Hardcoded credential accounts ---${RST}"

for user in cyberrange sjohnson; do
    if id "$user" &>/dev/null; then
        warn "Account '$user' exists (hardcoded in worm credential list)"
        id "$user" | tee -a "$OUT"
        # Check if password is the hardcoded one (compare shadow hash)
        shadow_line=$(grep "^$user:" /etc/shadow 2>/dev/null || true)
        if [[ -n "$shadow_line" ]]; then
            info "Shadow entry: $shadow_line"
        fi
    else
        ok "Account '$user' does not exist on this host"
    fi
done

# =============================================================================
# 6. SUDO NOPASSWD — worm requires this to run payloads (sudo -n flag)
# =============================================================================
log "\n${BLD}--- 6. Sudo NOPASSWD check ---${RST}"

if grep -rn "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#"; then
    hit "NOPASSWD sudo entries found (required by worm payload executor):"
    grep -rn "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#" | tee -a "$OUT"
else
    ok "No NOPASSWD sudo entries found"
fi

# =============================================================================
# 7. FILESYSTEM DAMAGE — check target dirs for signs of disorder_file_sys.sh
#    Tells: no extensions, 12-char random alphanumeric names
# =============================================================================
log "\n${BLD}--- 7. Filesystem scrambling indicators ---${RST}"

for target in /opt /srv /var/www /home /var/log; do
    [[ -d "$target" ]] || continue
    # Count files with exactly 12-char random-looking names (no extension, alnum only)
    suspicious=$(find "$target" -maxdepth 3 -type f -name '????????????' 2>/dev/null \
        | grep -E '/[a-zA-Z0-9]{12}$' | wc -l) || suspicious=0
    if [[ "$suspicious" -gt 10 ]]; then
        hit "$target: $suspicious files with 12-char random names — filesystem may be scrambled"
    elif [[ "$suspicious" -gt 0 ]]; then
        warn "$target: $suspicious files with 12-char random names (low count, monitor)"
    else
        ok "$target: no obvious scrambling detected"
    fi
done

# =============================================================================
# 8. CRON / SYSTEMD TIMER INJECTION — junk_cron_n_timers.sh payload
# =============================================================================
log "\n${BLD}--- 8. Cron and systemd timer audit ---${RST}"

info "Checking crontabs..."
for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
    [[ -f "$f" ]] || continue
    # Look for entries with random-looking names or /tmp/ execution
    if grep -qE '/tmp/|/var/tmp/|[a-zA-Z0-9]{12}' "$f" 2>/dev/null; then
        hit "Suspicious cron entry in $f:"
        grep -E '/tmp/|/var/tmp/|[a-zA-Z0-9]{12}' "$f" | tee -a "$OUT"
    fi
done

info "Checking systemd timers for non-distro units..."
systemctl list-timers --no-legend 2>/dev/null | while read -r next _ _ _ unit _; do
    unit_file=$(systemctl show "$unit" --property=FragmentPath 2>/dev/null | cut -d= -f2)
    if [[ -n "$unit_file" ]] && ! dpkg -S "$unit_file" &>/dev/null 2>&1 \
       && ! rpm -qf "$unit_file" &>/dev/null 2>&1; then
        warn "Non-package-owned timer: $unit ($unit_file)"
    fi
done || true

# =============================================================================
# SUMMARY
# =============================================================================
log "\n${BLD}=== Detection complete — $(hostname) ===${RST}"
log "Report saved: $OUT"
log ""
log "If infected:"
log "  02-hunt.sh    — find all active worm processes and network spread"
log "  03-lockout.sh — change hardcoded creds, revoke sudo NOPASSWD, block SSH"
log "  04-inoculate.sh — harden against reinfection"
log "  05-nuke.sh    — kill everything and restore what we can"
