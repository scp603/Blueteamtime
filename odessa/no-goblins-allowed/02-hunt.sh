#!/usr/bin/env bash
# =============================================================================
# 02-hunt.sh  [LEVEL 2 — ACTIVE THREAT HUNT]
# Finds live worm processes, maps spread via /proc/net, identifies which
# hosts on the subnet have already been hit, and prints kill commands.
# All checks go direct to kernel — no ps/ss/who/netstat.
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

log "\n${BLD}=== Goblin-Wagon Active Hunt — $(hostname) — $(date) ===${RST}\n"

# =============================================================================
# 1. FIND ALL WORM PROCESSES via /proc — walk cmdline and exe symlinks
# =============================================================================
log "${BLD}--- 1. Live worm process scan (/proc) ---${RST}"

declare -a WORM_PIDS=()
WORM_PATTERNS=("goblin-wagon" "wagon" "systemd-update" "dbus-helper" "sudo -n bash")

for pid_dir in /proc/[0-9]*/; do
    pid="${pid_dir%/}"
    pid="${pid##*/}"

    cmdline=$(tr '\0' ' ' < "${pid_dir}cmdline" 2>/dev/null | xargs 2>/dev/null || true)
    [[ -z "$cmdline" ]] && continue

    matched=0
    for pat in "${WORM_PATTERNS[@]}"; do
        echo "$cmdline" | grep -qi "$pat" && matched=1 && break
    done
    [[ $matched -eq 0 ]] && continue

    WORM_PIDS+=("$pid")
    ppid=$(awk '/^PPid:/{print $2}' "${pid_dir}status" 2>/dev/null || echo "?")
    uid=$(awk '/^Uid:/{print $2}' "${pid_dir}status" 2>/dev/null || echo "?")
    user=$(awk -F: -v u="$uid" '$3==u{print $1;exit}' /etc/passwd 2>/dev/null || echo "uid:$uid")
    exe=$(readlink "${pid_dir}exe" 2>/dev/null || echo "deleted/hidden")

    hit "PID $pid | PPID $ppid | User: $user | Exe: $exe"
    log "    Cmdline: $cmdline"
    log "    ${RED}kill -9 $pid${RST}    # kill this process"
    log "    ${RED}kill -9 $ppid${RST}   # kill parent"
    log ""
done

[[ ${#WORM_PIDS[@]} -eq 0 ]] && ok "No live worm processes found in /proc"

# =============================================================================
# 2. NETWORK SPREAD MAP — parse /proc/net/tcp for active SSH/WinRM connections
#    These are the hosts the worm is currently trying to spread to
# =============================================================================
log "${BLD}--- 2. Active spread connections (/proc/net/tcp) ---${RST}"

declare -A spread_targets=()

parse_connections() {
    local file="$1"
    [[ -f "$file" ]] || return

    while read -r sl local_addr rem_addr st rest; do
        [[ "$sl" == "sl" ]] && continue
        # 01=ESTABLISHED, 02=SYN_SENT — both are interesting
        [[ "$st" == "01" || "$st" == "02" ]] || continue

        rem_ip_hex="${rem_addr%:*}"
        rem_port_hex="${rem_addr##*:}"
        rem_port=$(printf '%d' "0x$rem_port_hex")

        [[ "$rem_port" -eq 22 || "$rem_port" -eq 5985 ]] || continue

        rem_ip=$(hex_to_ipv4 "$rem_ip_hex")
        spread_targets["$rem_ip:$rem_port"]=1

        proto="SSH"
        [[ "$rem_port" -eq 5985 ]] && proto="WinRM"
        hit "Active $proto connection → $rem_ip:$rem_port"
    done < "$file"
}

parse_connections /proc/net/tcp

if [[ ${#spread_targets[@]} -eq 0 ]]; then
    ok "No active SSH/WinRM spread connections detected"
fi

# =============================================================================
# 3. DETECT WORM HTTP SERVER — red team docs say they can serve the binary
#    via python3 -m http.server 8080, look for anything on :8080
# =============================================================================
log "\n${BLD}--- 3. HTTP server on :8080 (worm self-serve) ---${RST}"

if grep -qE ": 1F90 " /proc/net/tcp 2>/dev/null; then
    hit "Something is listening on port 8080 — possible worm HTTP server"
    grep -E ": 1F90 " /proc/net/tcp | while read -r sl local rem st rest; do
        local_ip=$(hex_to_ipv4 "${local%:*}")
        log "  Listener: $local_ip:8080"
    done

    # Find which PID owns the :8080 socket
    inode=$(grep -E ": 1F90 " /proc/net/tcp | awk '{print $10}' | head -1)
    if [[ -n "$inode" ]]; then
        for pid_dir in /proc/[0-9]*/; do
            pid="${pid_dir%/}"
            pid="${pid##*/}"
            if ls "$pid_dir/fd" 2>/dev/null | xargs -I{} readlink "$pid_dir/fd/{}" 2>/dev/null \
               | grep -q "socket:\[$inode\]"; then
                cmdline=$(tr '\0' ' ' < "${pid_dir}cmdline" 2>/dev/null || true)
                hit "HTTP server PID $pid: $cmdline"
                log "    ${RED}kill -9 $pid${RST}"
            fi
        done
    fi
else
    ok "Nothing listening on :8080"
fi

# =============================================================================
# 4. CHECK WHICH HOSTS ON THE SUBNET WERE ALREADY HIT
#    SSH to each live host and check for /etc/redteam_was_here.txt
#    Uses the worm's own credential: cyberrange:Cyberrange123!
#    (If we can get in with it, so could the worm)
# =============================================================================
log "\n${BLD}--- 4. Subnet infection sweep (10.10.10.1-199) ---${RST}"
log "Checking for /etc/redteam_was_here.txt on reachable hosts..."
log "(Uses the worm's hardcoded SSH cred — if we can log in, so could the worm)\n"

if ! command -v sshpass &>/dev/null; then
    warn "sshpass not installed — skipping remote infection check"
    warn "Install with: apt-get install -y sshpass  OR  dnf install -y sshpass"
else
    INFECTED_HOSTS=()
    for i in $(seq 1 199); do
        ip="10.10.10.$i"
        # Skip grey team range
        [[ $i -ge 200 ]] && continue
        # Quick ping to skip unreachable hosts
        ping -c1 -W1 "$ip" &>/dev/null 2>&1 || continue

        result=$(sshpass -p 'Cyberrange123!' \
            ssh -o StrictHostKeyChecking=no \
                -o ConnectTimeout=3 \
                -o BatchMode=no \
                cyberrange@"$ip" \
                'test -f /etc/redteam_was_here.txt && echo INFECTED || echo clean' \
                2>/dev/null || echo "no_access")

        if [[ "$result" == "INFECTED" ]]; then
            hit "INFECTED: $ip (proof file found)"
            INFECTED_HOSTS+=("$ip")
        elif [[ "$result" == "no_access" ]]; then
            ok "No access (cred rejected or SSH down): $ip — likely not vulnerable"
        else
            info "clean: $ip (reachable with worm cred but no proof file)"
        fi
    done

    log ""
    log "Infected hosts (${#INFECTED_HOSTS[@]}):"
    for h in "${INFECTED_HOSTS[@]}"; do
        log "  ${RED}$h${RST}"
    done
fi

# =============================================================================
# 5. CONSOLIDATED KILL COMMANDS
# =============================================================================
log "\n${BLD}--- 5. Kill commands ---${RST}"

if [[ ${#WORM_PIDS[@]} -gt 0 ]]; then
    log "Kill all identified worm PIDs:"
    log "  ${RED}kill -9 ${WORM_PIDS[*]}${RST}"
    log ""
fi

log "Kill by name (catches anything still running):"
log "  ${RED}pkill -9 -f 'goblin-wagon|wagon|systemd-update|dbus-helper'${RST}"
log ""
log "Kill any process running bash from /tmp or /var/tmp:"
log "  ${RED}grep -rl '/tmp\|/var/tmp' /proc/[0-9]*/exe 2>/dev/null | awk -F/ '{print \$3}' | xargs kill -9${RST}"
log ""
log "Next: run 03-lockout.sh to change hardcoded creds and block reinfection"
