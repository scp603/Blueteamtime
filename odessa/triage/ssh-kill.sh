#!/usr/bin/env bash
# =============================================================================
# ssh-kill.sh — Active SSH connection scanner & kill command generator
# Source of truth: /proc/net/tcp[6] + /proc/<pid>/fd  (no who/w/utmp)
# Run as root for full PID visibility
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
YLW='\033[1;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo "Run as root for full /proc visibility" >&2
    exit 1
fi

# =============================================================================
# HELPERS
# =============================================================================

# Decode a little-endian hex IPv4 address from /proc/net/tcp
# e.g. "0101A8C0" → "192.168.1.1"
hex_to_ipv4() {
    local h="$1"
    printf '%d.%d.%d.%d' \
        "0x${h:6:2}" "0x${h:4:2}" "0x${h:2:2}" "0x${h:0:2}"
}

# Decode a little-endian hex IPv6 address from /proc/net/tcp6
# 32 hex chars = 4 groups of 8, each group byte-reversed
hex_to_ipv6() {
    local h="$1"
    local out=""
    for i in 0 8 16 24; do
        seg="${h:$i:8}"
        out+="${seg:6:2}${seg:4:2}${seg:2:2}${seg:0:2}"
        [[ $i -lt 24 ]] && out+=":"
    done
    # Collapse to compressed notation via printf if possible
    printf '%s' "$out"
}

# Decode hex port
hex_to_port() { printf '%d' "0x$1"; }

# Resolve UID → username without `id` (reads /etc/passwd directly)
uid_to_user() {
    local uid="$1"
    awk -F: -v u="$uid" '$3==u{print $1; exit}' /etc/passwd 2>/dev/null || echo "uid:$uid"
}

# =============================================================================
# STEP 1: Parse /proc/net/tcp and /proc/net/tcp6
# Find ESTABLISHED (state 0x0A) connections where local port = 22 (0x0016)
# Format: inode → "remote_ip:remote_port uid"
# =============================================================================

declare -A inode_remote   # inode → remote_addr:port
declare -A inode_uid      # inode → uid

parse_tcp_table() {
    local file="$1"
    local ipver="$2"   # 4 or 6

    [[ -f "$file" ]] || return

    while read -r sl local_addr rem_addr st _ _ _ _ _ uid _ inode _rest; do
        [[ "$sl" == "sl" ]] && continue       # header line
        [[ "$st" != "0A" ]] && continue       # only ESTABLISHED

        local_port_hex="${local_addr##*:}"
        local_port=$(hex_to_port "$local_port_hex")
        [[ "$local_port" -eq 22 ]] || continue

        rem_ip_hex="${rem_addr%:*}"
        rem_port_hex="${rem_addr##*:}"
        rem_port=$(hex_to_port "$rem_port_hex")

        if [[ "$ipver" == "4" ]]; then
            rem_ip=$(hex_to_ipv4 "$rem_ip_hex")
        else
            rem_ip=$(hex_to_ipv6 "$rem_ip_hex")
        fi

        inode_remote["$inode"]="$rem_ip:$rem_port"
        inode_uid["$inode"]="$uid"
    done < "$file"
}

parse_tcp_table /proc/net/tcp  4
parse_tcp_table /proc/net/tcp6 6

if [[ ${#inode_remote[@]} -eq 0 ]]; then
    echo -e "\n${GRN}No established inbound SSH connections found in /proc/net/tcp.${RST}\n"
    exit 0
fi

# =============================================================================
# STEP 2: Walk /proc/<pid>/fd to find which PID owns each socket inode
# socket:[inode] symlinks in fd/ identify the owning process
# =============================================================================

declare -A inode_pid      # inode → pid
declare -A inode_cmdline  # inode → cmdline

for pid_dir in /proc/[0-9]*/; do
    pid="${pid_dir%/}"
    pid="${pid##*/}"
    fd_dir="$pid_dir/fd"
    [[ -d "$fd_dir" ]] || continue

    for fd_link in "$fd_dir"/[0-9]*; do
        target=$(readlink "$fd_link" 2>/dev/null) || continue
        [[ "$target" =~ ^socket:\[([0-9]+)\]$ ]] || continue
        inode="${BASH_REMATCH[1]}"
        [[ -v inode_remote["$inode"] ]] || continue

        inode_pid["$inode"]="$pid"
        inode_cmdline["$inode"]=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null | cut -c1-60)
        break  # one pid per inode is enough
    done
done

# =============================================================================
# STEP 3: Print results and kill commands
# =============================================================================

echo -e "\n${BLD}=== Active SSH Sessions (source: /proc/net/tcp + /proc/<pid>/fd) ===${RST}\n"

count=0
for inode in "${!inode_remote[@]}"; do
    count=$((count + 1))
    remote="${inode_remote[$inode]}"
    uid="${inode_uid[$inode]}"
    username=$(uid_to_user "$uid")
    pid="${inode_pid[$inode]:-UNKNOWN}"
    cmdline="${inode_cmdline[$inode]:-n/a}"

    remote_ip="${remote%:*}"
    remote_port="${remote##*:}"

    echo -e "${YLW}[Session $count]${RST}"
    echo -e "  Remote IP  : ${CYN}$remote_ip${RST}  (port $remote_port)"
    echo -e "  Socket UID : $uid  ($username)"
    echo -e "  PID        : ${BLD}$pid${RST}"
    echo -e "  Cmdline    : $cmdline"
    echo -e "  Inode      : $inode"

    echo -e "\n  ${BLD}Kill commands:${RST}"

    if [[ "$pid" != "UNKNOWN" ]]; then
        echo -e "  ${RED}kill -9 $pid${RST}                         # kill this session's sshd child"

        # Find the parent PID too — sshd session children have a parent sshd
        ppid=$(awk '/^PPid:/{print $2}' "/proc/$pid/status" 2>/dev/null || true)
        if [[ -n "$ppid" && "$ppid" != "1" ]]; then
            parent_cmd=$(tr '\0' ' ' < "/proc/$ppid/cmdline" 2>/dev/null | cut -c1-40 || true)
            echo -e "  ${RED}kill -9 $ppid${RST}                         # kill parent ($parent_cmd)"
        fi
    fi

    echo -e "  ${RED}pkill -SIGKILL -u $username${RST}               # kill ALL processes by $username"
    echo ""
done

# =============================================================================
# STEP 4: Nuclear options
# =============================================================================
echo -e "${BLD}=== Nuclear options ===${RST}\n"
echo -e "  Kill only established session children (sshd: user@...) — not the listener:"
echo -e "  ${RED}grep -l 'sshd' /proc/[0-9]*/cmdline | awk -F/ '{print \$3}' | xargs -I{} sh -c 'grep -q \"0A\" /proc/{}/net/tcp 2>/dev/null && kill -9 {}'${RST}"
echo ""
echo -e "  Simpler — kill all sshd children (processes named 'sshd' that are NOT the listener PID):"
LISTENER_PID=$(awk '/^ListenAddress/{found=1} found' /etc/ssh/sshd_config 2>/dev/null; \
    grep -l '^sshd$' /proc/[0-9]*/comm 2>/dev/null | awk -F'/' '{print $3}' | \
    while read p; do
        [[ $(cat /proc/$p/status 2>/dev/null | awk '/^PPid:/{print $2}') == "1" ]] && echo $p
    done | head -1 || true)
if [[ -n "$LISTENER_PID" ]]; then
    echo -e "  Listener PID: ${BLD}$LISTENER_PID${RST} — DO NOT kill this one or you lock yourself out"
    echo -e "  ${RED}grep -rl '^sshd$' /proc/[0-9]*/comm 2>/dev/null | awk -F/ '{print \$3}' | grep -v '^${LISTENER_PID}$' | xargs kill -9${RST}"
else
    echo -e "  ${RED}grep -rl '^sshd$' /proc/[0-9]*/comm 2>/dev/null | awk -F/ '{print \$3}' | xargs kill -9${RST}"
    echo -e "  ${YLW}(Could not detect listener PID — identify it manually before running)${RST}"
fi
echo ""
