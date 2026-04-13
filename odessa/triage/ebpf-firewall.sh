#!/usr/bin/env bash
# =============================================================================
# ebpf-firewall.sh — Nine-Tailed Fox CDT Competition
#
# Installs a custom XDP/eBPF packet filter at the network driver level,
# then removes iptables, nftables, and ufw so Red Team cannot reconfigure
# our firewall even if they get root.
#
# Architecture:
#   - XDP program attached to the primary NIC (runs before the kernel stack)
#   - BPF map: blocked_ips    — source IPs to drop (you manage this)
#   - BPF map: protected_ips  — Overseer IPs, never blocked (Rule #8)
#   - BPF map: safe_ports     — scored service ports, always allow (Rule #6)
#   - Companion scripts installed to /usr/local/bin/:
#       fw-block   <IP>   — add IP to blocklist
#       fw-unblock <IP>   — remove IP from blocklist
#       fw-list           — show current blocklist
#       fw-protect <IP>   — add IP to protected list (Overseers, scoring checks)
#       fw-whitelist <PORT> — add port to safe_ports (if scored service changes)
#
# After loading, iptables/nftables/ufw userspace binaries are removed.
# The XDP program persists across interface resets (reloads via systemd unit).
# To unload manually: ip link set dev <IFACE> xdp off
#
# Run as root. Requires: clang, libbpf-dev, linux-headers, bpftool
# (triage.sh installs these — run triage.sh first if not done.)
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
LOG="$SCRIPT_DIR/ebpf_fw_$(hostname)_$(date +%Y%m%d_%H%M%S).log"
FW_DIR="/opt/ntf-fw"

log()  { echo -e "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
ok()   { echo -e "${GRN}[OK]${RST}   $*" | tee -a "$LOG"; }
warn() { echo -e "${YLW}[WARN]${RST} $*" | tee -a "$LOG"; }
die()  { echo -e "${RED}[ERR]${RST}  $*" | tee -a "$LOG"; exit 1; }

log "${BLD}=== Nine-Tailed Fox eBPF Firewall — $(hostname) ===${RST}"

# =============================================================================
# DETECT INTERFACE
# =============================================================================
IFACE="${1:-$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/{print $5; exit}')}"
[[ -n "$IFACE" ]] || die "Could not detect network interface — pass it as \$1"
log "Primary interface: ${CYN}$IFACE${RST}"

# =============================================================================
# CHECK DEPENDENCIES
# =============================================================================
log "\n--- Checking dependencies ---"

missing=()
for cmd in clang llc bpftool; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
done

# Kernel headers: Debian/Ubuntu uses /usr/src/linux-headers-*, Rocky uses /usr/src/kernels/*
KHEADERS="/usr/src/linux-headers-$(uname -r)"
if [[ ! -d "$KHEADERS" ]]; then
    KHEADERS="/usr/src/kernels/$(uname -r)"
fi
[[ -d "$KHEADERS" ]] || missing+=("kernel-headers-$(uname -r)")

if [[ ${#missing[@]} -gt 0 ]]; then
    warn "Missing: ${missing[*]}"
    log "Installing missing dependencies..."
    if command -v apt-get &>/dev/null; then
        apt-get install -y clang llvm libbpf-dev bpftool \
            "linux-headers-$(uname -r)" 2>&1 | tee -a "$LOG" \
            || die "Dependency install failed — run triage.sh first"
    elif command -v dnf &>/dev/null; then
        dnf install -y clang llvm libbpf-devel bpftool \
            kernel-devel 2>&1 | tee -a "$LOG" \
            || die "Dependency install failed — run triage-rocky.sh first"
    else
        die "No supported package manager found (need apt-get or dnf)"
    fi
fi
ok "All dependencies present"

# =============================================================================
# WRITE XDP BPF PROGRAM
# =============================================================================
log "\n--- Writing XDP source ---"

mkdir -p "$FW_DIR"

cat > "$FW_DIR/xdp_fw.c" <<'BPFEOF'
// xdp_fw.c — Nine-Tailed Fox competition XDP firewall
// Compiled with: clang -O2 -target bpf -c xdp_fw.c -o xdp_fw.o
//
// Three BPF maps:
//   blocked_ips   — src IPs to DROP (u32 → u8, value=1 means blocked)
//   protected_ips — src IPs to always PASS (Overseers, scoring infra)
//   safe_ports    — dst ports to always PASS regardless of src IP

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Source IPs that are blocked
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} blocked_ips SEC(".maps");

// Source IPs that are never blocked (Overseers, scoring checks)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u8);
} protected_ips SEC(".maps");

// Destination ports that are always allowed (scored services)
// Even if the source IP is blocked, traffic to these ports passes.
// This prevents Rule #6 violations from misblocking scoring traffic.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __u16);
    __type(value, __u8);
} safe_ports SEC(".maps");

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // --- Ethernet header ---
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only process IPv4; pass everything else (ARP, IPv6, etc.)
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // --- IPv4 header ---
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // Reject malformed headers (ihl < 5 means < 20 bytes)
    if (iph->ihl < 5)
        return XDP_DROP;

    __u32 src = iph->saddr;
    __u8  val = 1;

    // Protected IPs always pass (Overseers — Rule #8)
    if (bpf_map_lookup_elem(&protected_ips, &src))
        return XDP_PASS;

    // If source is not blocked, pass immediately
    if (!bpf_map_lookup_elem(&blocked_ips, &src))
        return XDP_PASS;

    // Source IS blocked — check if destination port is a safe service port
    // Standard header only (no IP options): iph->ihl must equal 5
    // If there are IP options, conservatively pass (rare in practice)
    if (iph->ihl != 5)
        return XDP_PASS;

    __u8 proto = iph->protocol;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(iph + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;
        __u16 dport = bpf_ntohs(tcp->dest);
        if (bpf_map_lookup_elem(&safe_ports, &dport))
            return XDP_PASS;

    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(iph + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_DROP;
        __u16 dport = bpf_ntohs(udp->dest);
        if (bpf_map_lookup_elem(&safe_ports, &dport))
            return XDP_PASS;

    } else if (proto == IPPROTO_ICMP) {
        // Allow ICMP from blocked IPs? No — block it too.
        // Overseers can still ping because they're in protected_ips.
        return XDP_DROP;
    }

    // Blocked source, non-safe port → drop
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
BPFEOF

ok "XDP source written to $FW_DIR/xdp_fw.c"

# =============================================================================
# COMPILE THE XDP PROGRAM
# =============================================================================
log "\n--- Compiling XDP program ---"

clang -O2 -target bpf \
    -I"$KHEADERS/include" \
    -I/usr/include \
    -c "$FW_DIR/xdp_fw.c" \
    -o "$FW_DIR/xdp_fw.o" 2>&1 | tee -a "$LOG" \
    || die "Compilation failed — check $LOG"

ok "Compiled: $FW_DIR/xdp_fw.o"

# =============================================================================
# UNLOAD ANY EXISTING XDP PROGRAM ON THIS INTERFACE
# =============================================================================
ip link set dev "$IFACE" xdp off 2>/dev/null || true

# =============================================================================
# LOAD THE XDP PROGRAM (native mode, fall back to generic)
# =============================================================================
log "\n--- Loading XDP program on $IFACE ---"

if ip link set dev "$IFACE" xdp obj "$FW_DIR/xdp_fw.o" sec xdp 2>/dev/null; then
    ok "XDP loaded in NATIVE mode on $IFACE"
    XDP_MODE="xdp"
else
    warn "Native XDP not supported on $IFACE — loading in GENERIC (software) mode"
    ip link set dev "$IFACE" xdpgeneric obj "$FW_DIR/xdp_fw.o" sec xdp 2>/dev/null \
        || die "XDP generic mode also failed — check driver support"
    ok "XDP loaded in GENERIC mode on $IFACE"
    XDP_MODE="xdpgeneric"
fi

# Verify load
if ip link show "$IFACE" | grep -q "xdp"; then
    ok "XDP program confirmed on $IFACE:"
    ip link show "$IFACE" | grep xdp | tee -a "$LOG"
else
    die "XDP did not attach — check: ip link show $IFACE"
fi

# =============================================================================
# POPULATE BPF MAPS — PROTECTED IPs AND SAFE SERVICE PORTS
# =============================================================================
log "\n--- Populating BPF maps ---"

# Helper: resolve a map name to its BPF ID so bpftool can operate on it
map_id_for() {
    bpftool map list 2>/dev/null | awk -v name="$1" '$0 ~ name {print $1; exit}' | tr -d ':'
}

# Give the maps a moment to appear in bpftool's list
sleep 1

BLOCKED_ID=$(map_id_for "blocked_ips")
PROTECTED_ID=$(map_id_for "protected_ips")
SAFE_ID=$(map_id_for "safe_ports")

[[ -n "$BLOCKED_ID" && -n "$PROTECTED_ID" && -n "$SAFE_ID" ]] \
    || die "Could not resolve BPF map IDs — bpftool: $(bpftool map list 2>&1 | head -5)"

# Save map IDs for companion scripts to reuse
echo "BLOCKED_MAP_ID=$BLOCKED_ID"   > "$FW_DIR/map_ids"
echo "PROTECTED_MAP_ID=$PROTECTED_ID" >> "$FW_DIR/map_ids"
echo "SAFE_MAP_ID=$SAFE_ID"         >> "$FW_DIR/map_ids"
echo "IFACE=$IFACE"                 >> "$FW_DIR/map_ids"
echo "XDP_MODE=$XDP_MODE"           >> "$FW_DIR/map_ids"
ok "Map IDs saved to $FW_DIR/map_ids"

# --- Overseer / protected IPs (Rules #6, #7 — never block these) ---
# Full Overseer range per Blue Team Packet: 10.10.10.200-210
# Ansible-Server: 10.10.10.255  Scoring-Server: 10.10.10.210
ip_to_hex() {
    # Convert dotted-quad to little-endian hex for bpftool
    IFS=. read -r a b c d <<< "$1"
    printf '%02x %02x %02x %02x' "$d" "$c" "$b" "$a"
}

OVERSEER_IPS=(
    "10.10.10.200"
    "10.10.10.201"
    "10.10.10.202"
    "10.10.10.203"
    "10.10.10.204"
    "10.10.10.205"
    "10.10.10.206"
    "10.10.10.207"
    "10.10.10.208"
    "10.10.10.209"
    "10.10.10.210"
    "10.10.10.255"
)
# Add your team workstation IPs here if they have a fixed IP

for ip in "${OVERSEER_IPS[@]}"; do
    hex=$(ip_to_hex "$ip")
    bpftool map update id "$PROTECTED_ID" key hex $hex value hex 01 2>/dev/null \
        && ok "Protected: $ip" \
        || warn "Could not protect $ip — add manually with: fw-protect $ip"
done

# --- Scored service ports — always allow traffic to these ports (Rule #6) ---
# Source: Blue Team Packet scored services
# 22   SSH
# 25   SMTP
# 53   DNS
# 80   HTTP (Apache)
# 88   Kerberos
# 139  SMB (NetBIOS)
# 389  LDAP
# 443  HTTPS
# 445  SMB
# 465  SMTPS
# 587  SMTP submission
# 636  LDAPS
# 1194 OpenVPN
# 3306 MySQL
# 3389 RDP
# 5432 PostgreSQL

port_to_hex() {
    # Ports are stored as big-endian u16 in the map (network byte order)
    printf '%02x %02x' $(( ($1 >> 8) & 0xff )) $(( $1 & 0xff ))
}

SAFE_PORTS=(22 25 53 80 88 139 389 443 445 465 587 636 1194 3306 3389 5432)

for port in "${SAFE_PORTS[@]}"; do
    hex=$(port_to_hex "$port")
    bpftool map update id "$SAFE_ID" key hex $hex value hex 01 2>/dev/null \
        && ok "Safe port: $port" \
        || warn "Could not whitelist port $port"
done

# =============================================================================
# INSTALL COMPANION MANAGEMENT SCRIPTS
# =============================================================================
log "\n--- Installing companion scripts ---"

# ---- fw-block ----
cat > /usr/local/bin/fw-block <<'FBEOF'
#!/usr/bin/env bash
# fw-block <IP> — add an IP to the XDP blocklist
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root" >&2; exit 1; }
[[ -n "${1:-}" ]] || { echo "Usage: fw-block <IP>" >&2; exit 1; }
source /opt/ntf-fw/map_ids

ip_to_hex() {
    IFS=. read -r a b c d <<< "$1"
    printf '%02x %02x %02x %02x' "$d" "$c" "$b" "$a"
}

IP="$1"
# Validate rough IP format
[[ "$IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] \
    || { echo "Invalid IP: $IP" >&2; exit 1; }

# Safety: refuse to block Overseer IPs (full range 200-210 + 255 per packet)
# Rule #7: get Overseer approval before calling this command for any IP.
OVERSEER_IPS=("10.10.10.200" "10.10.10.201" "10.10.10.202" "10.10.10.203" "10.10.10.204" "10.10.10.205" "10.10.10.206" "10.10.10.207" "10.10.10.208" "10.10.10.209" "10.10.10.210" "10.10.10.255")
for o in "${OVERSEER_IPS[@]}"; do
    [[ "$IP" == "$o" ]] && { echo "Refusing to block Overseer IP: $IP (Rule #8)" >&2; exit 1; }
done

hex=$(ip_to_hex "$IP")
bpftool map update id "$BLOCKED_MAP_ID" key hex $hex value hex 01
echo "[BLOCKED] $IP added to XDP blocklist"
echo "[$( date '+%Y-%m-%d %H:%M:%S')] BLOCKED: $IP" >> /var/log/ntf_fw.log
FBEOF

# ---- fw-unblock ----
cat > /usr/local/bin/fw-unblock <<'FUEOF'
#!/usr/bin/env bash
# fw-unblock <IP> — remove an IP from the XDP blocklist
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root" >&2; exit 1; }
[[ -n "${1:-}" ]] || { echo "Usage: fw-unblock <IP>" >&2; exit 1; }
source /opt/ntf-fw/map_ids

ip_to_hex() {
    IFS=. read -r a b c d <<< "$1"
    printf '%02x %02x %02x %02x' "$d" "$c" "$b" "$a"
}

IP="$1"
hex=$(ip_to_hex "$IP")
bpftool map delete id "$BLOCKED_MAP_ID" key hex $hex 2>/dev/null \
    && echo "[UNBLOCKED] $IP removed from XDP blocklist" \
    || echo "[INFO] $IP was not in the blocklist"
echo "[$( date '+%Y-%m-%d %H:%M:%S')] UNBLOCKED: $IP" >> /var/log/ntf_fw.log
FUEOF

# ---- fw-list ----
cat > /usr/local/bin/fw-list <<'FLEOF'
#!/usr/bin/env bash
# fw-list — show all blocked and protected IPs, and safe ports
set -euo pipefail
source /opt/ntf-fw/map_ids

hex_to_ip() {
    # bpftool dumps map keys as space-separated hex bytes (little-endian for IPs)
    echo "$@" | awk '{printf "%d.%d.%d.%d\n", strtonum("0x"$4), strtonum("0x"$3), strtonum("0x"$2), strtonum("0x"$1)}'
}

echo "=== BLOCKED IPs ==="
bpftool map dump id "$BLOCKED_MAP_ID" 2>/dev/null | awk '
/key:/ {
    d=strtonum("0x"$5); c=strtonum("0x"$4); b=strtonum("0x"$3); a=strtonum("0x"$2)
    printf "  %d.%d.%d.%d\n", a, b, c, d
}' || echo "  (empty)"

echo ""
echo "=== PROTECTED IPs (never blocked) ==="
bpftool map dump id "$PROTECTED_MAP_ID" 2>/dev/null | awk '
/key:/ {
    d=strtonum("0x"$5); c=strtonum("0x"$4); b=strtonum("0x"$3); a=strtonum("0x"$2)
    printf "  %d.%d.%d.%d\n", a, b, c, d
}' || echo "  (empty)"

echo ""
echo "=== SAFE PORTS (always allowed) ==="
bpftool map dump id "$SAFE_MAP_ID" 2>/dev/null | awk '
/key:/ {
    port=strtonum("0x"$2)*256 + strtonum("0x"$3)
    printf "  %d\n", port
}' || echo "  (empty)"
FLEOF

# ---- fw-protect ----
cat > /usr/local/bin/fw-protect <<'FPEOF'
#!/usr/bin/env bash
# fw-protect <IP> — add an IP to the protected list (never blocked)
# Use for Overseer IPs, scoring check IPs, your own workstation, etc.
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root" >&2; exit 1; }
[[ -n "${1:-}" ]] || { echo "Usage: fw-protect <IP>" >&2; exit 1; }
source /opt/ntf-fw/map_ids

ip_to_hex() {
    IFS=. read -r a b c d <<< "$1"
    printf '%02x %02x %02x %02x' "$d" "$c" "$b" "$a"
}

IP="$1"
hex=$(ip_to_hex "$IP")
bpftool map update id "$PROTECTED_MAP_ID" key hex $hex value hex 01
echo "[PROTECTED] $IP will never be blocked by XDP firewall"
FPEOF

# ---- fw-whitelist ----
cat > /usr/local/bin/fw-whitelist <<'FWEOF'
#!/usr/bin/env bash
# fw-whitelist <PORT> — add a port to the safe_ports map (always allowed)
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root" >&2; exit 1; }
[[ -n "${1:-}" ]] || { echo "Usage: fw-whitelist <PORT>" >&2; exit 1; }
source /opt/ntf-fw/map_ids

PORT="$1"
[[ "$PORT" =~ ^[0-9]+$ && "$PORT" -le 65535 ]] \
    || { echo "Invalid port: $PORT" >&2; exit 1; }

hex=$(printf '%02x %02x' $(( (PORT >> 8) & 0xff )) $(( PORT & 0xff )))
bpftool map update id "$SAFE_MAP_ID" key hex $hex value hex 01
echo "[SAFE PORT] $PORT added to always-allow list"
FWEOF

chmod +x /usr/local/bin/fw-block \
         /usr/local/bin/fw-unblock \
         /usr/local/bin/fw-list \
         /usr/local/bin/fw-protect \
         /usr/local/bin/fw-whitelist

ok "Companion scripts installed: fw-block, fw-unblock, fw-list, fw-protect, fw-whitelist"

# =============================================================================
# SYSTEMD UNIT — reload XDP on boot / interface reset
# =============================================================================
log "\n--- Installing XDP persistence unit ---"

cat > /etc/systemd/system/ntf-fw.service <<SVCEOF
[Unit]
Description=Nine-Tailed Fox XDP Firewall
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c 'ip link set dev ${IFACE} ${XDP_MODE} obj /opt/ntf-fw/xdp_fw.o sec xdp'
ExecStop=/bin/bash  -c 'ip link set dev ${IFACE} xdp off'
Restart=on-failure

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable ntf-fw.service
ok "ntf-fw.service enabled — XDP will reload on boot"

# =============================================================================
# REMOVE / NEUTER IPTABLES, NFTABLES, UFW USERSPACE TOOLS
# The kernel netfilter module can stay — we just want to remove the tools
# Red Team would use to add their own rules. Our XDP program runs BEFORE
# netfilter so this doesn't affect our filtering.
# =============================================================================
log "\n--- Removing iptables / nftables / ufw userspace tools ---"

for pkg in iptables nftables ufw firewalld; do
    if command -v apt-get &>/dev/null && dpkg -l "$pkg" &>/dev/null 2>&1; then
        apt-get remove -y --purge "$pkg" 2>&1 | tee -a "$LOG" \
            && hit "Removed: $pkg (apt)" \
            || warn "Could not remove $pkg via apt — renaming binaries"
    elif command -v dnf &>/dev/null && rpm -q "$pkg" &>/dev/null 2>&1; then
        dnf remove -y "$pkg" 2>&1 | tee -a "$LOG" \
            && hit "Removed: $pkg (dnf)" \
            || warn "Could not remove $pkg via dnf — renaming binaries"
    fi
done

# Rename any remaining binaries so they can't be called directly
# (in case apt remove didn't work or they were installed from source)
for bin in iptables iptables-save iptables-restore ip6tables \
           nft nftables ufw firewall-cmd; do
    path=$(command -v "$bin" 2>/dev/null || true)
    [[ -n "$path" ]] || continue
    mv "$path" "${path}.disabled" 2>/dev/null \
        && warn "Renamed $path → ${path}.disabled" \
        || warn "Could not rename $path"
done

# The apt pin from triage.sh (-1 priority) or dnf excludepkgs from
# triage-rocky.sh blocks reinstall via package manager.
# Also lock bpftool itself so Red Team can't use it to unload our program
# (they'd need to use ip link set xdp off, which we can also protect)
if command -v bpftool &>/dev/null; then
    # Don't remove bpftool — we need it for fw-block etc.
    # But prevent non-root from using it
    chmod 700 "$(command -v bpftool)"
    ok "bpftool access restricted to root only"
fi

# Lock the XDP object file and map_ids so they can't be overwritten
chattr +i "$FW_DIR/xdp_fw.o" 2>/dev/null || true
chattr +i "$FW_DIR/map_ids"  2>/dev/null || true
chattr +i /etc/apt/preferences.d/no-firewall 2>/dev/null || true

ok "Firewall tools removed. XDP is now the only packet filter."

# =============================================================================
# FINAL VERIFICATION
# =============================================================================
log "\n--- Final verification ---"

echo ""
ip link show "$IFACE" | grep --color=never xdp | tee -a "$LOG" \
    && ok "XDP attached to $IFACE" \
    || warn "XDP not showing in ip link — check: ip link show $IFACE"

echo ""
log "${BLD}=== eBPF Firewall Setup Complete — $(hostname) ===${RST}"
log ""
log "Quick reference:"
log "  Block an attacker IP:    ${CYN}fw-block 10.10.10.X${RST}"
log "  Unblock an IP:           ${CYN}fw-unblock 10.10.10.X${RST}"
log "  Show blocklist:          ${CYN}fw-list${RST}"
log "  Protect a new IP:        ${CYN}fw-protect <IP>${RST}"
log "  Whitelist a new port:    ${CYN}fw-whitelist <PORT>${RST}"
log ""
log "To find attacker IPs from active connections:"
log "  ${CYN}grep ':1' /proc/net/tcp | awk '{print \$3}' | cut -d: -f1 | while read h; do"
log "  ${CYN}  printf '%d.%d.%d.%d\n' 0x\${h:6:2} 0x\${h:4:2} 0x\${h:2:2} 0x\${h:0:2}"
log "  ${CYN}done | sort -u${RST}"
log ""
log "XDP unload (emergency — you'll lose all blocking):  ${CYN}ip link set dev $IFACE xdp off${RST}"
log "XDP reload:                                         ${CYN}systemctl restart ntf-fw${RST}"
log "View XDP prog info:                                 ${CYN}bpftool prog show${RST}"
log "View blocked IPs:                                   ${CYN}fw-list${RST}"
log ""
log "${YLW}Remember: Report all blocked IPs to Overseers per competition rules.${RST}"
