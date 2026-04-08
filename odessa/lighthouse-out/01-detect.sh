#!/usr/bin/env bash
# =============================================================================
# 01-detect.sh  [LEVEL 1 — FORENSIC SCAN]
# Detects signs of Phantasm C2 (CDT-RedTeam-HTTPBeaconTool) infection.
#
# Tool: beacon.py — polls a Flask C2 server over HTTP every ~30s,
#        executes arbitrary shell commands via subprocess.Popen(shell=True),
#        sends output back Base64-encoded.
#
# Detection vectors:
#   - Python processes masquerading as system names (systemd-service.py,
#     udev-worker.py, apt-check.py)
#   - Any python3 process with outbound HTTP connections to port 5000
#   - .py files in /tmp/.sys/, /tmp/ hidden dirs, /dev/shm
#   - Outbound connections to port 5000 in /proc/net/tcp
#   - HTTP traffic with python-requests User-Agent (proxy/pcap analysis)
#   - Beacon ID strings in memory (GRV-01, SRC-01)
#   - HISTFILE unset in active shells (anti-forensics evasion)
#   - /tmp/.sys/ directory existence
#
# Does NOT use ps/who/w.
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

hex_to_ipv4() {
    printf '%d.%d.%d.%d' \
        "0x${1:6:2}" "0x${1:4:2}" "0x${1:2:2}" "0x${1:0:2}"
}
hex_to_port() { printf '%d' "0x$1"; }

log "\n${BLD}=== Phantasm C2 Detection — $(hostname) — $(date) ===${RST}\n"

TOTAL_HITS=0
hit_count() { TOTAL_HITS=$((TOTAL_HITS + 1)); }

# =============================================================================
# 1. PROCESS SCAN — masquerade names + any python3 with outbound :5000
#    Beacon is renamed to: systemd-service.py, udev-worker.py, apt-check.py
#    (plus any other name the operator chose)
#    All use /proc directly — no ps.
# =============================================================================
log "${BLD}--- 1. Suspicious Python processes (/proc) ---${RST}"

MASQUERADE_PATTERNS=("systemd-service.py" "udev-worker.py" "apt-check.py"
                     "sys-update.py" ".sys-update" "beacon.py")
BEACON_ID_PATTERNS=("GRV-01" "SRC-01" "checkin" "phantasm")

declare -A SUSPECT_PIDS

for pid_dir in /proc/[0-9]*/; do
    pid="${pid_dir%/}"
    pid="${pid##*/}"
    cmdline=$(tr '\0' ' ' < "${pid_dir}cmdline" 2>/dev/null | xargs 2>/dev/null || true)
    [[ -z "$cmdline" ]] && continue

    # Must be a python process
    echo "$cmdline" | grep -qi "python" || continue

    matched_reason=""

    # Check for masquerade names
    for pat in "${MASQUERADE_PATTERNS[@]}"; do
        if echo "$cmdline" | grep -qi "$pat"; then
            matched_reason="masquerade name: $pat"
            break
        fi
    done

    # Check for beacon ID strings in cmdline
    if [[ -z "$matched_reason" ]]; then
        for pat in "${BEACON_ID_PATTERNS[@]}"; do
            if echo "$cmdline" | grep -qi "$pat"; then
                matched_reason="beacon string: $pat"
                break
            fi
        done
    fi

    [[ -z "$matched_reason" ]] && continue

    SUSPECT_PIDS["$pid"]=1
    ppid=$(awk '/^PPid:/{print $2}' "${pid_dir}status" 2>/dev/null || echo "?")
    uid=$(awk '/^Uid:/{print $2}' "${pid_dir}status" 2>/dev/null || echo "?")
    user=$(awk -F: -v u="$uid" '$3==u{print $1;exit}' /etc/passwd 2>/dev/null || echo "uid:$uid")
    exe=$(readlink "${pid_dir}exe" 2>/dev/null || echo "unknown")

    hit "BEACON CANDIDATE — PID $pid | User: $user | Reason: $matched_reason"
    log "    Cmdline: $cmdline"
    log "    Exe: $exe"
    log "    ${RED}kill -9 $pid${RST}   # kill this beacon"
    log ""
    hit_count
done

[[ ${#SUSPECT_PIDS[@]} -eq 0 ]] && ok "No masquerade-named Python processes found"

# =============================================================================
# 2. NETWORK SCAN — outbound connections to port 5000
#    Beacon makes: GET /checkin/<id> and POST /results/<id>
#    C2 server binds 0.0.0.0:5000 by default (also may use :80 or :443)
# =============================================================================
log "\n${BLD}--- 2. Outbound C2 connections (/proc/net/tcp) ---${RST}"

declare -A C2_IPS

while read -r sl local_addr rem_addr st rest; do
    [[ "$sl" == "sl" ]] && continue
    # 01=ESTABLISHED, 02=SYN_SENT
    [[ "$st" == "01" || "$st" == "02" ]] || continue

    rem_ip_hex="${rem_addr%:*}"
    rem_port_hex="${rem_addr##*:}"
    rem_port=$(hex_to_port "$rem_port_hex")

    # Port 5000 (0x1388) — default Flask C2 port
    [[ "$rem_port" -eq 5000 ]] || continue

    rem_ip=$(hex_to_ipv4 "$rem_ip_hex")
    C2_IPS["$rem_ip"]=1

    # Find which PID owns this connection
    rem_inode=$(awk -v ra="$rem_addr" -v la="$local_addr" \
        '$3==ra && $2==la {print $10}' /proc/net/tcp 2>/dev/null | head -1 || true)

    conn_pid="unknown"
    if [[ -n "$rem_inode" ]]; then
        for pid_dir in /proc/[0-9]*/; do
            pid="${pid_dir%/}"
            pid="${pid##*/}"
            if ls -la "${pid_dir}fd/" 2>/dev/null \
               | grep -q "socket:\[$rem_inode\]" 2>/dev/null; then
                conn_pid="$pid"
                break
            fi
        done
    fi

    hit "Outbound connection to C2 candidate: $rem_ip:$rem_port (PID: $conn_pid)"
    hit_count

done < /proc/net/tcp 2>/dev/null || true

if [[ ${#C2_IPS[@]} -gt 0 ]]; then
    log ""
    log "  ${RED}Potential C2 server IPs (zero-auth — you can kill beacons remotely):${RST}"
    for ip in "${!C2_IPS[@]}"; do
        log "  ${CYN}curl -s -X POST http://$ip:5000/issue \\${RST}"
        log "  ${CYN}  -H 'Content-Type: application/json' \\${RST}"
        log "  ${CYN}  -d '{\"id\":\"GRV-01\",\"cmd\":\"exit\"}'${RST}"
        log "  (Try beacon IDs: GRV-01, SRC-01)"
    done
else
    ok "No outbound port-5000 connections detected"
fi

# =============================================================================
# 3. FILESYSTEM SCAN — beacon drop locations
#    /tmp/.sys/ (documented in README as staging dir)
#    /dev/shm   (volatile RAM-backed, suggested in README)
#    Hidden .py files in /tmp/
# =============================================================================
log "\n${BLD}--- 3. Beacon drop locations ---${RST}"

# Known staging directory
if [[ -d /tmp/.sys ]]; then
    hit "/tmp/.sys directory exists — documented Phantasm staging dir"
    ls -la /tmp/.sys/ | tee -a "$OUT"
    hit_count
fi

# Scan /tmp, /dev/shm for .py files
for scandir in /tmp /dev/shm /tmp/.sys /var/tmp; do
    [[ -d "$scandir" ]] || continue
    find "$scandir" -maxdepth 3 -name "*.py" -type f 2>/dev/null | while read -r f; do
        hit "Python file in temp/volatile storage: $f"
        ls -la "$f" | tee -a "$OUT"

        # Check for beacon signature strings
        if grep -qE "send_heartbeat|BASE_INTERVAL|JITTER_PERCENT|checkin|/results/|subprocess\.Popen" "$f" 2>/dev/null; then
            hit "  BEACON CONFIRMED — Phantasm C2 signature strings found in $f"
            grep -oE "(BASE_INTERVAL|BEACON_ID|C2_URL)\s*=\s*[^\n]+" "$f" 2>/dev/null \
                | tee -a "$OUT" || true
        fi
        hit_count
    done
done

# Scan /proc/*/maps for files loaded from /dev/shm or /tmp (in-memory execution)
info "Checking /proc memory maps for temp-path Python scripts..."
for pid_dir in /proc/[0-9]*/; do
    pid="${pid_dir%/}"
    pid="${pid##*/}"
    # Only check python processes
    cmdline=$(tr '\0' ' ' < "${pid_dir}cmdline" 2>/dev/null | xargs 2>/dev/null || true)
    echo "$cmdline" | grep -qi "python" || continue

    if grep -qE "/dev/shm|/tmp/\." "${pid_dir}maps" 2>/dev/null; then
        hit "Python PID $pid has memory-mapped file from /dev/shm or hidden /tmp path"
        grep -E "/dev/shm|/tmp/\." "${pid_dir}maps" 2>/dev/null | tee -a "$OUT"
        hit_count
    fi
done

# =============================================================================
# 4. BEACON ID STRINGS IN /proc MEMORY
#    GRV-01 and SRC-01 are the hardcoded default beacon IDs
# =============================================================================
log "\n${BLD}--- 4. Beacon ID strings in process memory ---${RST}"

for pid_dir in /proc/[0-9]*/; do
    pid="${pid_dir%/}"
    pid="${pid##*/}"
    cmdline=$(tr '\0' ' ' < "${pid_dir}cmdline" 2>/dev/null | xargs 2>/dev/null || true)
    echo "$cmdline" | grep -qi "python" || continue

    # Read from /proc/<pid>/environ for HISTFILE check and any beacon config
    env_file="${pid_dir}environ"
    if [[ -r "$env_file" ]]; then
        env_content=$(tr '\0' '\n' < "$env_file" 2>/dev/null || true)

        # Check if HISTFILE is unset (anti-forensics)
        if ! echo "$env_content" | grep -q "^HISTFILE="; then
            warn "PID $pid (python): HISTFILE not set in environment — possible anti-forensics evasion"
        fi

        # Check for beacon ID in environment
        for id in "GRV-01" "SRC-01"; do
            if echo "$env_content" | grep -q "$id"; then
                hit "Beacon ID '$id' found in PID $pid environment"
                hit_count
            fi
        done
    fi
done

ok "Memory scan complete"

# =============================================================================
# 5. HISTFILE ANTI-FORENSICS CHECK
#    Phantasm README tells operators: unset HISTFILE; history -c && history -w
#    Check currently active shell environments
# =============================================================================
log "\n${BLD}--- 5. Anti-forensics: HISTFILE manipulation ---${RST}"

for pid_dir in /proc/[0-9]*/; do
    pid="${pid_dir%/}"
    pid="${pid##*/}"
    cmdline=$(tr '\0' ' ' < "${pid_dir}cmdline" 2>/dev/null | xargs 2>/dev/null || true)
    # Only check interactive shells
    echo "$cmdline" | grep -qE "^bash|^sh|^zsh|^-bash|^-sh" || continue

    env_file="${pid_dir}environ"
    [[ -r "$env_file" ]] || continue

    if ! tr '\0' '\n' < "$env_file" 2>/dev/null | grep -q "^HISTFILE="; then
        uid=$(awk '/^Uid:/{print $2}' "${pid_dir}status" 2>/dev/null || echo "?")
        user=$(awk -F: -v u="$uid" '$3==u{print $1;exit}' /etc/passwd 2>/dev/null || echo "uid:$uid")
        warn "Shell PID $pid (user: $user) has HISTFILE unset — operator may have run 'unset HISTFILE'"
    fi
done

ok "HISTFILE check complete"

# =============================================================================
# 6. C2 FLASK SERVER CHECK (if this host might be the operator machine)
#    Check if port 5000 is listening locally
# =============================================================================
log "\n${BLD}--- 6. Local C2 server check (port 5000) ---${RST}"

if grep -E "^[0-9A-F]+: [0-9A-F]+:1388 " /proc/net/tcp 2>/dev/null | head -1 | grep -q .; then
    hit "Something is LISTENING on port 5000 — possible Phantasm C2 server on this host"
    inode=$(grep -E "^[0-9A-F ]+: [0-9A-F]+:1388 " /proc/net/tcp 2>/dev/null \
        | awk '{print $10}' | head -1 || true)

    if [[ -n "$inode" ]]; then
        for pid_dir in /proc/[0-9]*/; do
            pid="${pid_dir%/}"
            pid="${pid##*/}"
            if ls -la "${pid_dir}fd/" 2>/dev/null \
               | grep -q "socket:\[$inode\]" 2>/dev/null; then
                cmdline=$(tr '\0' ' ' < "${pid_dir}cmdline" 2>/dev/null || true)
                hit "Port 5000 listener PID $pid: $cmdline"
                log "    ${RED}kill -9 $pid${RST}   # kill C2 server"
            fi
        done
    fi
    hit_count
else
    ok "Nothing listening on port 5000 — C2 server is not on this host"
fi

# =============================================================================
# SUMMARY
# =============================================================================
log ""
log "${BLD}=== Detection complete — $(hostname) ===${RST}"
log "Report saved: $OUT"
log ""
if [[ $TOTAL_HITS -gt 0 ]]; then
    log "${RED}${BLD}BEACON DETECTED — $TOTAL_HITS indicators found.${RST}"
    log ""
    log "Response playbook:"
    log "  02-hunt.sh     — map all active beacons, attempt remote kill via C2 API"
    log "  03-lockout.sh  — kill processes, block egress :5000, remove files"
    log "  04-inoculate.sh — inotify monitors, firewall rules, temp dir locks"
    log "  05-nuke.sh     — full scorched-earth cleanup"
else
    log "${GRN}No Phantasm C2 indicators found.${RST}"
    log "Run 04-inoculate.sh to harden proactively."
fi
