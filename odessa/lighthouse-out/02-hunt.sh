#!/usr/bin/env bash
# =============================================================================
# 02-hunt.sh  [LEVEL 2 — ACTIVE THREAT HUNT + REMOTE BEACON RECALL]
#
# Phantasm C2 has ZERO authentication on its Flask server.
# This means: if we find the C2 IP from network connections, we can issue
# the "exit" command to every known beacon ID — terminating the beacon
# remotely using the attacker's own API against them.
#
# Actions:
#   1.  Find all live beacon processes via /proc (by name + network activity)
#   2.  Extract C2 server IP from /proc/net/tcp (active :5000 connections)
#   3.  Attempt to recall all beacons via unauthenticated POST /issue exit
#   4.  Identify beacon files on disk
#   5.  Generate kill commands
#
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
OUT="$SCRIPT_DIR/hunt_$(hostname)_$(date +%Y%m%d_%H%M%S).txt"

log()  { echo -e "$*" | tee -a "$OUT"; }
hit()  { echo -e "${RED}[HIT]${RST}  $*" | tee -a "$OUT"; }
ok()   { echo -e "${GRN}[OK]${RST}   $*" | tee -a "$OUT"; }
info() { echo -e "${CYN}[INFO]${RST} $*" | tee -a "$OUT"; }
warn() { echo -e "${YLW}[WARN]${RST} $*" | tee -a "$OUT"; }

hex_to_ipv4() {
    printf '%d.%d.%d.%d' \
        "0x${1:6:2}" "0x${1:4:2}" "0x${1:2:2}" "0x${1:0:2}"
}

log "\n${BLD}=== Phantasm C2 Active Hunt — $(hostname) — $(date) ===${RST}\n"

# =============================================================================
# 1. FIND ALL LIVE BEACON PROCESSES
# =============================================================================
log "${BLD}--- 1. Live beacon process scan (/proc) ---${RST}"

declare -a BEACON_PIDS=()
MASQUERADE_NAMES=("systemd-service.py" "udev-worker.py" "apt-check.py"
                  "sys-update.py" ".sys-update" "beacon.py" "phantasm")

for pid_dir in /proc/[0-9]*/; do
    pid="${pid_dir%/}"
    pid="${pid##*/}"
    cmdline=$(tr '\0' ' ' < "${pid_dir}cmdline" 2>/dev/null | xargs 2>/dev/null || true)
    [[ -z "$cmdline" ]] && continue
    echo "$cmdline" | grep -qi "python" || continue

    matched=""
    for name in "${MASQUERADE_NAMES[@]}"; do
        echo "$cmdline" | grep -qi "$name" && matched="$name" && break
    done

    # Also catch: any python3 process with a network socket on port 5000
    if [[ -z "$matched" ]]; then
        for fd_link in "${pid_dir}fd/"*; do
            target=$(readlink "$fd_link" 2>/dev/null || true)
            [[ "$target" =~ ^socket: ]] || continue
            inode="${target#socket:[}"
            inode="${inode%]}"
            if grep -q " $inode " /proc/net/tcp 2>/dev/null; then
                port_line=$(grep " $inode " /proc/net/tcp 2>/dev/null | head -1)
                rem_port=$(printf '%d' "0x${port_line:46:4}" 2>/dev/null || true)
                [[ "$rem_port" -eq 5000 ]] 2>/dev/null && matched="port-5000 connection" && break
            fi
        done
    fi

    [[ -z "$matched" ]] && continue

    BEACON_PIDS+=("$pid")
    ppid=$(awk '/^PPid:/{print $2}' "${pid_dir}status" 2>/dev/null || echo "?")
    uid=$(awk '/^Uid:/{print $2}' "${pid_dir}status" 2>/dev/null || echo "?")
    user=$(awk -F: -v u="$uid" '$3==u{print $1;exit}' /etc/passwd 2>/dev/null || echo "uid:$uid")
    exe=$(readlink "${pid_dir}exe" 2>/dev/null || echo "deleted/hidden")
    cwd=$(readlink "${pid_dir}cwd" 2>/dev/null || echo "unknown")

    hit "BEACON PID $pid | User: $user | Match: $matched"
    log "    Cmdline: $cmdline"
    log "    Exe: $exe"
    log "    CWD: $cwd"
    log "    ${RED}kill -9 $pid${RST}"
    log ""
done

[[ ${#BEACON_PIDS[@]} -eq 0 ]] && ok "No live beacon processes found"

# =============================================================================
# 2. EXTRACT C2 SERVER IP FROM NETWORK CONNECTIONS
#    Beacon makes GET /checkin/<id> every ~30s — there will be a recent
#    established or SYN_SENT connection to the C2 server on port 5000.
# =============================================================================
log "${BLD}--- 2. C2 server extraction (/proc/net/tcp) ---${RST}"

declare -A C2_SERVERS=()

while read -r sl local_addr rem_addr st rest; do
    [[ "$sl" == "sl" ]] && continue
    [[ "$st" == "01" || "$st" == "02" ]] || continue

    rem_ip_hex="${rem_addr%:*}"
    rem_port_hex="${rem_addr##*:}"
    rem_port=$(printf '%d' "0x$rem_port_hex" 2>/dev/null || true)

    [[ "$rem_port" -eq 5000 ]] || continue

    rem_ip=$(hex_to_ipv4 "$rem_ip_hex")
    C2_SERVERS["$rem_ip"]=1
    hit "Active connection to C2 server: ${rem_ip}:5000"

done < /proc/net/tcp 2>/dev/null || true

# Also try TIME_WAIT and CLOSE_WAIT connections (recent connections)
while read -r sl local_addr rem_addr st rest; do
    [[ "$sl" == "sl" ]] && continue
    # 06=TIME_WAIT, 08=CLOSE_WAIT — recently used connections
    [[ "$st" == "06" || "$st" == "08" ]] || continue

    rem_ip_hex="${rem_addr%:*}"
    rem_port_hex="${rem_addr##*:}"
    rem_port=$(printf '%d' "0x$rem_port_hex" 2>/dev/null || true)
    [[ "$rem_port" -eq 5000 ]] || continue

    rem_ip=$(hex_to_ipv4 "$rem_ip_hex")
    C2_SERVERS["$rem_ip"]=1
    warn "Recent (TIME_WAIT/CLOSE_WAIT) connection to ${rem_ip}:5000 — C2 candidate"

done < /proc/net/tcp 2>/dev/null || true

if [[ ${#C2_SERVERS[@]} -eq 0 ]]; then
    ok "No port-5000 connections found — beacon may be dormant (check-in interval up to 5 min)"
    warn "Try again during beacon check-in window, or check /proc/net/tcp in a loop:"
    warn "  watch -n5 'grep \":1388\" /proc/net/tcp'"
fi

# =============================================================================
# 3. REMOTE BEACON RECALL — exploit zero-auth C2 API to kill beacons
#    Phantasm C2 has no authentication on POST /issue
#    Send exit command for all known beacon IDs to every discovered C2 IP
# =============================================================================
log "\n${BLD}--- 3. Remote beacon recall (zero-auth exploit) ---${RST}"

# Known beacon IDs from source code and README
BEACON_IDS=("GRV-01" "SRC-01")

if [[ ${#C2_SERVERS[@]} -eq 0 ]]; then
    warn "No C2 servers identified — cannot perform remote recall"
    warn "If you know the C2 IP, run manually:"
    log "  ${CYN}curl -s -X POST http://<C2_IP>:5000/issue \\${RST}"
    log "  ${CYN}  -H 'Content-Type: application/json' \\${RST}"
    log "  ${CYN}  -d '{\"id\":\"GRV-01\",\"cmd\":\"exit\"}'${RST}"
elif command -v curl &>/dev/null; then
    for c2_ip in "${!C2_SERVERS[@]}"; do
        log "  Attempting recall against C2: $c2_ip:5000"

        for beacon_id in "${BEACON_IDS[@]}"; do
            result=$(curl -s -m 5 -X POST "http://$c2_ip:5000/issue" \
                -H "Content-Type: application/json" \
                -d "{\"id\":\"$beacon_id\",\"cmd\":\"exit\"}" 2>/dev/null || echo "FAILED")

            if echo "$result" | grep -qi "queued\|ok\|success\|issued\|command" 2>/dev/null; then
                hit "RECALL SENT — beacon $beacon_id exit command accepted by C2 at $c2_ip"
                log "    Response: $result"
            else
                info "Recall for $beacon_id: response=$result"
            fi
        done

        # Try to enumerate what other beacon IDs are registered (no auth needed)
        log "  Trying to enumerate beacon results from C2..."
        for beacon_id in "${BEACON_IDS[@]}"; do
            result=$(curl -s -m 5 "http://$c2_ip:5000/results/$beacon_id" 2>/dev/null || true)
            if [[ -n "$result" ]] && echo "$result" | grep -qv "^\s*$"; then
                hit "C2 results endpoint responsive for $beacon_id:"
                # Decode if base64
                echo "$result" | base64 -d 2>/dev/null | head -20 | tee -a "$OUT" || \
                    echo "$result" | head -5 | tee -a "$OUT"
            fi
        done

        # Attempt to issue a harmless command to confirm access
        log "  Issuing harmless probe command to verify C2 access..."
        probe_result=$(curl -s -m 5 -X POST "http://$c2_ip:5000/issue" \
            -H "Content-Type: application/json" \
            -d '{"id":"GRV-01","cmd":"echo lighthouse_probe"}' 2>/dev/null || echo "no response")
        log "  Probe response: $probe_result"
    done
else
    warn "curl not available — cannot perform remote recall"
    warn "Install curl: apt-get install -y curl"
fi

# =============================================================================
# 4. BEACON FILES ON DISK
# =============================================================================
log "\n${BLD}--- 4. Beacon files on disk ---${RST}"

found_files=0
for scandir in /tmp /dev/shm /var/tmp /tmp/.sys; do
    [[ -d "$scandir" ]] || continue
    find "$scandir" -name "*.py" -type f 2>/dev/null | while read -r f; do
        if grep -qE "send_heartbeat|BASE_INTERVAL|/checkin/|subprocess\.Popen|JITTER_PERCENT" "$f" 2>/dev/null; then
            hit "CONFIRMED BEACON FILE: $f"
            log "    Size: $(wc -c < "$f") bytes"
            sha256sum "$f" | tee -a "$OUT"
            # Extract config values
            log "    Config:"
            grep -E "(C2_URL|BEACON_ID|BASE_INTERVAL)\s*=" "$f" 2>/dev/null \
                | sed 's/^/      /' | tee -a "$OUT" || true
            found_files=1
        else
            warn "Unconfirmed .py file in temp dir: $f — manual review needed"
        fi
    done
done

[[ $found_files -eq 0 ]] && ok "No confirmed beacon files found on disk"
ok "Note: beacon may run from /dev/shm (volatile, disappears on reboot)"

# =============================================================================
# 5. CONSOLIDATED KILL COMMANDS
# =============================================================================
log "\n${BLD}--- 5. Kill commands ---${RST}"

if [[ ${#BEACON_PIDS[@]} -gt 0 ]]; then
    log "Kill all identified beacon PIDs:"
    log "  ${RED}kill -9 ${BEACON_PIDS[*]}${RST}"
    log ""
fi

log "Kill all Python processes matching beacon names:"
log "  ${RED}pkill -9 -f 'systemd-service\.py|udev-worker\.py|apt-check\.py|beacon\.py'${RST}"
log ""
log "Kill any Python making outbound :5000 connections:"
log "  ${RED}for pid in \$(ls /proc/[0-9]*/net/tcp 2>/dev/null | awk -F/ '{print \$3}'); do"
log "    cat /proc/\$pid/net/tcp 2>/dev/null | grep ':1388' && kill -9 \$pid 2>/dev/null; done${RST}"
log ""
log "Next: run 03-lockout.sh to block egress and remove beacon files"
