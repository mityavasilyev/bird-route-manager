#!/usr/bin/env bash
# install.sh — full zero-to-running installer for bird-route-manager
#
# Installs and configures on a fresh Ubuntu VPS:
#   • Go toolchain (if not already present)
#   • BIRD2 routing daemon with BGP split-routing (antifilter.network by default)
#   • bird-route-manager service (user-defined route lists + push API)
#
# Prerequisites (do these before running this script):
#   • Ubuntu 22.04+ VPS
#   • VPN tunnel interface already up (WireGuard, AmneziaWG, OpenVPN, etc.)
#
# Usage (from the cloned repo):
#   git clone https://github.com/mityavasilyev/bird-route-manager
#   cd bird-route-manager
#   sudo ./install.sh
#
# Re-running is safe — only what you confirm is changed.

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

ok()   { echo -e "  ${GREEN}✓${RESET} $*"; }
warn() { echo -e "  ${YELLOW}!${RESET} $*"; }
fail() { echo -e "\n  ${RED}✗ $*${RESET}\n"; exit 1; }
hdr()  { echo -e "\n${BOLD}${CYAN}[$1]${RESET} ${BOLD}$2${RESET}"; }
note() { echo -e "  ${DIM}$*${RESET}"; }

ask() {
    local prompt="$1" default="${2:-}"
    local hint; [[ -n "$default" ]] && hint=" [${CYAN}${default}${RESET}]" || hint=""
    read -r -p "$(echo -e "  $prompt$hint: ")" answer
    echo "${answer:-$default}"
}

ask_yn() {
    local prompt="$1" default="${2:-y}"
    local hint; [[ "$default" == "y" ]] && hint="${CYAN}Y${RESET}/n" || hint="y/${CYAN}N${RESET}"
    while true; do
        read -r -p "$(echo -e "  $prompt [$hint]: ")" answer
        case "${answer:-$default}" in
            y|Y|yes|YES) return 0 ;;
            n|N|no|NO)   return 1 ;;
            *) echo "  Please answer y or n." ;;
        esac
    done
}

# ── Constants ─────────────────────────────────────────────────────────────────

WORK_DIR="/opt/bird-route-manager"
BINARY="$WORK_DIR/bird-route-manager"
ENV_FILE="$WORK_DIR/env"
BIRD_EXTRA_CONF="$WORK_DIR/bird-extra.conf"
SYSTEMD_UNIT="/etc/systemd/system/bird-route-manager.service"
BIRD_CONF="/etc/bird/bird.conf"

MANAGED_BIRD_BEGIN="# ---- bird-route-manager begin ----"
MANAGED_BIRD_END="# ---- bird-route-manager end ----"

# ── Root check ────────────────────────────────────────────────────────────────

[[ $EUID -eq 0 ]] || fail "Run as root: sudo $0"

# ── Arch ─────────────────────────────────────────────────────────────────────

case "$(uname -m)" in
    x86_64)  GOARCH="amd64" ;;
    aarch64) GOARCH="arm64" ;;
    *)       fail "Unsupported architecture: $(uname -m)" ;;
esac

# ── Helpers ───────────────────────────────────────────────────────────────────

env_get() {
    local key="$1" default="${2:-}"
    [[ -f "$ENV_FILE" ]] || { echo "$default"; return; }
    local val; val=$(grep "^${key}=" "$ENV_FILE" 2>/dev/null | cut -d= -f2- | tr -d '"' || true)
    echo "${val:-$default}"
}

env_set() {
    local key="$1" value="$2"
    if [[ ! -f "$ENV_FILE" ]]; then
        echo "${key}=${value}" > "$ENV_FILE"
        return
    fi
    if grep -q "^${key}=" "$ENV_FILE"; then
        sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
    else
        echo "${key}=${value}" >> "$ENV_FILE"
    fi
}

detect_public_ip() {
    local ip
    ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)
    [[ -z "$ip" ]] && ip=$(curl -sf --max-time 5 https://api.ipify.org 2>/dev/null || true)
    [[ -z "$ip" ]] && ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    echo "$ip"
}

# Tunnel interfaces: wg*, tun*, tap*, vpn*, sing*, xray*, ovpn*
# The grep || true is intentional: grep exits 1 when nothing matches, which
# would kill the script under set -euo pipefail even though "no tunnels found"
# is a valid (if unusual) state.
list_tunnel_ifaces() {
    ip -o link show 2>/dev/null \
        | awk -F'[ :]+' '{print $2}' \
        | { grep -E '^(wg|tun|tap|vpn|sing|xray|ovpn|ipsec)' || true; } \
        | tr '\n' '  '
}

# All interfaces except loopback, docker, veth, bridges
list_other_ifaces() {
    ip -o link show 2>/dev/null \
        | awk -F'[ :]+' '{print $2}' \
        | { grep -vE '^(lo$|docker|veth|br-|virbr|dummy|wg|tun|tap|vpn|sing|xray|ovpn|ipsec)' || true; } \
        | tr '\n' '  '
}

# ── Banner ────────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  bird-route-manager setup${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo ""

REINSTALL=false
[[ -f "$ENV_FILE" ]] && REINSTALL=true

if $REINSTALL; then
    echo -e "  Existing installation found at ${CYAN}$WORK_DIR${RESET}."
    note "Re-running will only change what you explicitly confirm."
else
    echo "  Fresh install — configures BIRD2 and the bird-route-manager"
    echo "  service from scratch. Takes about 1–2 minutes."
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# [1/6] Dependencies
# ─────────────────────────────────────────────────────────────────────────────

hdr "1/6" "Dependencies"
echo ""

if ! command -v bird &>/dev/null; then
    note "bird2 not found — installing via apt..."
    apt-get update -qq
    apt-get install -y -q bird2
    ok "bird2 installed"
else
    ok "bird2 $(bird --version 2>&1 | grep -oP 'version \K[0-9.]+' | head -1)"
fi

command -v ip      &>/dev/null || fail "iproute2 not found — install it first: apt install iproute2"
command -v python3 &>/dev/null || fail "python3 not found — install it first: apt install python3"
command -v curl    &>/dev/null || fail "curl not found — install it first: apt install curl"

ok "iproute2, python3, curl present"

# ─────────────────────────────────────────────────────────────────────────────
# [2/6] Network
# ─────────────────────────────────────────────────────────────────────────────

hdr "2/6" "Network"
echo ""

# ── Router ID ──

note "BIRD2 uses a router ID as a unique identifier for this node."
note "Your public IP is the right value here."
echo ""

DETECTED_IP=$(detect_public_ip)
CURRENT_ROUTER_ID=$(env_get "ROUTER_ID" "$DETECTED_IP")
CHANGE_ROUTER_ID=true

if $REINSTALL; then
    echo -e "  Current router ID: ${CYAN}$CURRENT_ROUTER_ID${RESET}"
    ask_yn "Change it?" n && CHANGE_ROUTER_ID=true || CHANGE_ROUTER_ID=false
fi

if $CHANGE_ROUTER_ID; then
    ROUTER_ID=$(ask "Router ID" "$CURRENT_ROUTER_ID")
    [[ -n "$ROUTER_ID" ]] || fail "Router ID cannot be empty"
    ok "Router ID: $ROUTER_ID"
else
    ROUTER_ID="$CURRENT_ROUTER_ID"
fi

echo ""

# ── VPN interface ──

TUNNEL_IFACES=$(list_tunnel_ifaces)
OTHER_IFACES=$(list_other_ifaces)

note "The tunnel interface through which blocked traffic will exit."
note "This is the interface your VPN connection created — not your main eth/ens."
echo ""
if [[ -n "$TUNNEL_IFACES" ]]; then
    echo -e "  Tunnel interfaces: ${CYAN}${TUNNEL_IFACES}${RESET}"
else
    echo -e "  Tunnel interfaces: ${YELLOW}none detected${RESET} — is your VPN tunnel up?"
fi
[[ -n "$OTHER_IFACES" ]] && echo -e "  Other interfaces:  ${DIM}${OTHER_IFACES}${RESET}"
echo ""

CURRENT_IFACE=$(env_get "VPN_INTERFACE" "${TUNNEL_IFACES%% *}")  # default to first tunnel iface if any
[[ -z "$CURRENT_IFACE" ]] && CURRENT_IFACE="wg0"
CHANGE_IFACE=true

if $REINSTALL; then
    echo -e "  Current VPN interface: ${CYAN}$CURRENT_IFACE${RESET}"
    ask_yn "Change it?" n && CHANGE_IFACE=true || CHANGE_IFACE=false
fi

if $CHANGE_IFACE; then
    VPN_INTERFACE=$(ask "VPN interface" "$CURRENT_IFACE")
    [[ -n "$VPN_INTERFACE" ]] || fail "Interface name cannot be empty"
    # Warn if interface doesn't exist yet (not fatal — user may bring it up later)
    ip link show "$VPN_INTERFACE" &>/dev/null \
        && ok "VPN interface: $VPN_INTERFACE" \
        || warn "Interface '$VPN_INTERFACE' not found — make sure the VPN tunnel is up before traffic routing starts"
else
    VPN_INTERFACE="$CURRENT_IFACE"
fi

# ─────────────────────────────────────────────────────────────────────────────
# [3/6] Route feed (BGP)
# ─────────────────────────────────────────────────────────────────────────────

hdr "3/6" "Route feed (BGP)"
echo ""

note "BIRD2 connects to a BGP server to receive the list of IPs that should"
note "be routed via your VPN. For antifilter.network, keep all defaults."
echo ""

CURRENT_BGP_PEER=$(env_get "BGP_PEER_IP"  "45.148.244.55")
CURRENT_BGP_AS=$(env_get   "BGP_PEER_AS"  "65444")
CURRENT_LOCAL_AS=$(env_get "BGP_LOCAL_AS" "64999")
CURRENT_BGP_NH=$(env_get   "BGP_NEXTHOP"  "10.8.1.1")
CHANGE_BGP=false

if $REINSTALL; then
    echo -e "  Current feed: ${CYAN}${CURRENT_BGP_PEER} AS${CURRENT_BGP_AS}${RESET}"
    ask_yn "Change BGP settings?" n && CHANGE_BGP=true || CHANGE_BGP=false
else
    ask_yn "Using antifilter.network? (keep defaults)" y \
        && CHANGE_BGP=false \
        || CHANGE_BGP=true
fi

if $CHANGE_BGP; then
    echo ""
    BGP_PEER_IP=$(ask "BGP peer IP   (the route feed server)" "$CURRENT_BGP_PEER")
    BGP_PEER_AS=$(ask "BGP peer AS   (the feed server's AS number)" "$CURRENT_BGP_AS")
    BGP_LOCAL_AS=$(ask "Local AS      (any private AS, e.g. 64512–65534)" "$CURRENT_LOCAL_AS")
    echo ""
    note "Advanced: the BGP nexthop is a dummy IP that BIRD2 uses internally"
    note "to figure out which interface to send traffic through. The default"
    note "works for any standard VPN setup — change only if you know why."
    BGP_NEXTHOP=$(ask "BGP nexthop   (leave as-is unless you know why)" "$CURRENT_BGP_NH")
    ok "BGP feed: $BGP_PEER_IP AS$BGP_PEER_AS, local AS$BGP_LOCAL_AS"
else
    BGP_PEER_IP="$CURRENT_BGP_PEER"
    BGP_PEER_AS="$CURRENT_BGP_AS"
    BGP_LOCAL_AS="$CURRENT_LOCAL_AS"
    BGP_NEXTHOP="$CURRENT_BGP_NH"
    ok "Using antifilter.network defaults"
fi

# ─────────────────────────────────────────────────────────────────────────────
# [4/6] Remote updates and refresh
# ─────────────────────────────────────────────────────────────────────────────

hdr "4/6" "Remote updates and refresh"
echo ""

# ── Push API ──

CURRENT_TOKEN=$(env_get "SYNC_TOKEN" "")
ENABLE_API=false
NEW_TOKEN=""

note "The push API lets you send route updates to this VPS remotely —"
note "from a cron job, a script on another machine, or any HTTP client."
note "Requests are signed with a secret token so only you can push updates."
echo ""

if [[ -n "$CURRENT_TOKEN" ]]; then
    ok "Push API already enabled"
    if ask_yn "Rotate the token?" n; then
        ENABLE_API=true
    fi
else
    if ask_yn "Enable push API?" y; then
        ENABLE_API=true
        note "A token will be generated and shown at the end of setup."
        note "Store it wherever your push client runs and set it as the HMAC key."
    else
        note "You can enable it later by re-running install.sh."
    fi
fi

if $ENABLE_API; then
    NEW_TOKEN=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    ok "Token will be shown at the end of setup"
fi

echo ""

# ── Refresh interval ──

note "Domains like Telegram rotate their IPs frequently. bird-route-manager"
note "re-resolves all domain entries on a schedule to keep routes current."
echo ""

CURRENT_HOURS=$(env_get "REFRESH_HOURS" "6")
CHANGE_HOURS=true

if $REINSTALL; then
    echo -e "  Current refresh interval: every ${CYAN}${CURRENT_HOURS}h${RESET}"
    ask_yn "Change it?" n && CHANGE_HOURS=true || CHANGE_HOURS=false
fi

if $CHANGE_HOURS; then
    REFRESH_HOURS=$(ask "Re-resolve every N hours (0 = never)" "$CURRENT_HOURS")
    REFRESH_HOURS="${REFRESH_HOURS:-6}"
else
    REFRESH_HOURS="$CURRENT_HOURS"
fi
ok "Refresh interval: every ${REFRESH_HOURS}h"

echo ""

# ── IP-check sites routing ──

note "Resolves IP-echo service domains (ifconfig.me, ipinfo.io, etc.) and"
note "routes their IPs via ISP so they are never sent through the VPN."
note "Disable only if you intentionally want those sites to go through the VPN."
echo ""

IP_CHECK_SITES="$WORK_DIR/ip-check-sites.list"
CURRENT_IP_SITES_ENABLED=false
[[ -f "$IP_CHECK_SITES" ]] && CURRENT_IP_SITES_ENABLED=true
CHANGE_IP_SITES=true

if $REINSTALL; then
    $CURRENT_IP_SITES_ENABLED \
        && echo -e "  IP-check sites routing: ${CYAN}enabled${RESET}" \
        || echo -e "  IP-check sites routing: ${DIM}disabled${RESET}"
    ask_yn "Change it?" n && CHANGE_IP_SITES=true || CHANGE_IP_SITES=false
fi

INSTALL_IP_CHECK_SITES=$CURRENT_IP_SITES_ENABLED
if $CHANGE_IP_SITES; then
    if ask_yn "Route IP-check sites via ISP?" y; then
        INSTALL_IP_CHECK_SITES=true
        ok "IP-check sites routing: enabled"
    else
        INSTALL_IP_CHECK_SITES=false
        ok "IP-check sites routing: disabled"
    fi
fi

echo ""

# ── dnsmasq TLD routing ──

note "Route all domains under specific TLDs (e.g. .ru) via ISP automatically."
note "Uses dnsmasq + kernel ipset: resolved IPs are tagged and routed via ISP"
note "with preference 150 (lower than user lists, higher than BGP feed)."
echo ""

CURRENT_DNSMASQ_IPSET=$(env_get "DNSMASQ_IPSET" "")
CURRENT_DNSMASQ_TLDS=$(env_get "DNSMASQ_TLDS" ".ru")
CURRENT_DNSMASQ_TIMEOUT=$(env_get "DNSMASQ_IPSET_TIMEOUT" "21600")
ENABLE_DNSMASQ=false
CHANGE_DNSMASQ=true

if [[ -n "$CURRENT_DNSMASQ_IPSET" ]]; then
    echo -e "  dnsmasq TLD routing: ${CYAN}enabled${RESET} (ipset: ${CURRENT_DNSMASQ_IPSET}, TLDs: ${CURRENT_DNSMASQ_TLDS})"
    ask_yn "Change it?" n && CHANGE_DNSMASQ=true || CHANGE_DNSMASQ=false
    ENABLE_DNSMASQ=true
else
    echo -e "  dnsmasq TLD routing: ${DIM}disabled${RESET}"
fi

if $CHANGE_DNSMASQ; then
    if [[ -n "$CURRENT_DNSMASQ_IPSET" ]]; then
        _dnsmasq_default="y"
    else
        _dnsmasq_default="n"
    fi
    if ask_yn "Enable dnsmasq TLD routing?" "$_dnsmasq_default"; then
        ENABLE_DNSMASQ=true
        echo ""
        DNSMASQ_TLDS=$(ask "TLDs to route via ISP (space-separated, e.g. .ru .su)" "$CURRENT_DNSMASQ_TLDS")
        DNSMASQ_TLDS="${DNSMASQ_TLDS:-.ru}"
        DNSMASQ_IPSET_NAME=$(ask "Kernel ipset name" "${CURRENT_DNSMASQ_IPSET:-tld_isp}")
        DNSMASQ_IPSET_NAME="${DNSMASQ_IPSET_NAME:-tld_isp}"
        DNSMASQ_TIMEOUT=$(ask "IP timeout in seconds (0 = never expire)" "$CURRENT_DNSMASQ_TIMEOUT")
        DNSMASQ_TIMEOUT="${DNSMASQ_TIMEOUT:-21600}"
        ok "dnsmasq TLD routing: ${DNSMASQ_TLDS} → ipset ${DNSMASQ_IPSET_NAME} (timeout ${DNSMASQ_TIMEOUT}s)"
    else
        ENABLE_DNSMASQ=false
        ok "dnsmasq TLD routing: disabled"
    fi
else
    DNSMASQ_TLDS="$CURRENT_DNSMASQ_TLDS"
    DNSMASQ_IPSET_NAME="$CURRENT_DNSMASQ_IPSET"
    DNSMASQ_TIMEOUT="$CURRENT_DNSMASQ_TIMEOUT"
fi

# ── Full-VPN per-peer override (optional) ──

note "Temporarily route individual VPN peers through the VPN tunnel for all"
note "traffic (bypassing split routing). Requires an AmneziaWG Docker container."
echo ""

CURRENT_FULLVPN=$(env_get "FULLVPN_ENABLED" "")
CURRENT_AWG_CONTAINER=$(env_get "AWG_CONTAINER" "amnezia-awg")
CURRENT_AWG_WG_IFACE=$(env_get "AWG_WG_INTERFACE" "wg0")
CURRENT_AWG_CONT_IFACE=$(env_get "AWG_CONTAINER_IFACE" "eth1")
CURRENT_FULLVPN_SUBNET=$(env_get "FULLVPN_SUBNET" "10.8.3.0/24")
CURRENT_FULLVPN_BRIDGE=$(env_get "FULLVPN_BRIDGE" "amn0")
CURRENT_FULLVPN_BRIDGE_IP=$(env_get "FULLVPN_BRIDGE_IP" "172.29.172.2")
CURRENT_FULLVPN_DURATION=$(env_get "FULLVPN_DURATION" "900")
CURRENT_FULLVPN_CLEANUP=$(env_get "FULLVPN_CLEANUP" "180")
ENABLE_FULLVPN=false
CHANGE_FULLVPN=true

if [[ "$CURRENT_FULLVPN" == "true" ]]; then
    echo -e "  Full-VPN override: ${CYAN}enabled${RESET} (container: ${CURRENT_AWG_CONTAINER})"
    ask_yn "Change settings?" n && CHANGE_FULLVPN=true || CHANGE_FULLVPN=false
    ENABLE_FULLVPN=true
else
    echo -e "  Full-VPN override: ${DIM}disabled${RESET}"
fi

if $CHANGE_FULLVPN; then
    if [[ "$CURRENT_FULLVPN" == "true" ]]; then
        _fvpn_default="y"
    else
        _fvpn_default="n"
    fi
    if ask_yn "Enable full-VPN per-peer override?" "$_fvpn_default"; then
        ENABLE_FULLVPN=true
        echo ""

        # Try to auto-detect container settings
        _detected_container=""
        _detected_bridge=""
        _detected_bridge_ip=""
        if command -v docker &>/dev/null; then
            _detected_container=$(docker ps --format '{{.Names}}' 2>/dev/null | { grep -i amnezia || true; } | head -1)
            if [[ -n "$_detected_container" ]]; then
                # Auto-detect bridge and IP from Docker network
                _detected_bridge_ip=$(docker inspect "$_detected_container" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || true)
                # Find the bridge interface — could be br-<id> or a custom name like amn0
                _net_name=$(docker inspect "$_detected_container" --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null || true)
                _net_name=$(echo "$_net_name" | awk '{print $1}')
                if [[ -n "$_net_name" ]]; then
                    _detected_bridge=$(docker network inspect "$_net_name" --format '{{range .Options}}{{.}}{{end}}' 2>/dev/null | { grep -oP 'com\.docker\.network\.bridge\.name=\K\S+' || true; })
                    if [[ -z "$_detected_bridge" ]]; then
                        # Fallback: find bridge by network ID prefix
                        _net_id=$(docker network inspect "$_net_name" --format '{{.Id}}' 2>/dev/null | head -c 12 || true)
                        if [[ -n "$_net_id" ]]; then
                            _detected_bridge=$(ip link show 2>/dev/null | { grep -oP "br-${_net_id}\S*" || true; } | head -1)
                        fi
                    fi
                    # Last resort: look for the bridge interface that has the container IP's subnet
                    if [[ -z "$_detected_bridge" && -n "$_detected_bridge_ip" ]]; then
                        _gw=$(docker inspect "$_detected_container" --format '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' 2>/dev/null || true)
                        if [[ -n "$_gw" ]]; then
                            _detected_bridge=$(ip -o addr show 2>/dev/null | { grep "$_gw" || true; } | awk '{print $2}' | head -1)
                        fi
                    fi
                fi
            fi
        fi

        AWG_CONTAINER=$(ask "Docker container name" "${_detected_container:-$CURRENT_AWG_CONTAINER}")
        AWG_WG_IFACE=$(ask "WireGuard interface inside container" "$CURRENT_AWG_WG_IFACE")
        AWG_CONT_IFACE=$(ask "Container outgoing interface" "$CURRENT_AWG_CONT_IFACE")
        FULLVPN_SUBNET=$(ask "VPN client subnet" "$CURRENT_FULLVPN_SUBNET")
        FULLVPN_BRIDGE=$(ask "Docker bridge interface" "${_detected_bridge:-$CURRENT_FULLVPN_BRIDGE}")
        FULLVPN_BRIDGE_IP=$(ask "Container bridge IP" "${_detected_bridge_ip:-$CURRENT_FULLVPN_BRIDGE_IP}")
        FULLVPN_DURATION=$(ask "Override duration (seconds)" "$CURRENT_FULLVPN_DURATION")
        FULLVPN_CLEANUP=$(ask "Cleanup interval (seconds)" "$CURRENT_FULLVPN_CLEANUP")

        ok "Full-VPN: ${AWG_CONTAINER}, subnet ${FULLVPN_SUBNET}, duration ${FULLVPN_DURATION}s"
    else
        ENABLE_FULLVPN=false
        ok "Full-VPN override: disabled"
    fi
else
    AWG_CONTAINER="$CURRENT_AWG_CONTAINER"
    AWG_WG_IFACE="$CURRENT_AWG_WG_IFACE"
    AWG_CONT_IFACE="$CURRENT_AWG_CONT_IFACE"
    FULLVPN_SUBNET="$CURRENT_FULLVPN_SUBNET"
    FULLVPN_BRIDGE="$CURRENT_FULLVPN_BRIDGE"
    FULLVPN_BRIDGE_IP="$CURRENT_FULLVPN_BRIDGE_IP"
    FULLVPN_DURATION="$CURRENT_FULLVPN_DURATION"
    FULLVPN_CLEANUP="$CURRENT_FULLVPN_CLEANUP"
fi

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# [5/6] Applying
# ─────────────────────────────────────────────────────────────────────────────

hdr "5/6" "Applying"
echo ""

# 5a — Go toolchain + build binary from source
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_BINARY="$SCRIPT_DIR/bird-route-manager"
GO_MIN="1.24"

_go_ok() {
    command -v go &>/dev/null || return 1
    local ver; ver=$(go version 2>/dev/null | grep -oP 'go\K[0-9]+\.[0-9]+' | head -1)
    python3 -c "
v = tuple(int(x) for x in '$ver'.split('.'))
r = tuple(int(x) for x in '$GO_MIN'.split('.'))
exit(0 if v >= r else 1)" 2>/dev/null
}

if ! _go_ok; then
    GO_VERSION="1.24.2"
    echo "  Installing Go $GO_VERSION..."
    GO_TAR="go${GO_VERSION}.linux-${GOARCH}.tar.gz"
    curl -fsSL "https://dl.google.com/go/${GO_TAR}" -o "/tmp/${GO_TAR}"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "/tmp/${GO_TAR}"
    rm "/tmp/${GO_TAR}"
    export PATH="/usr/local/go/bin:$PATH"
    ok "Go $(go version | awk '{print $3}') installed"
else
    ok "Go $(go version | awk '{print $3}')"
fi

echo "  Building binary from source..."
(cd "$SCRIPT_DIR" && PATH="/usr/local/go/bin:$PATH" go build -o "$SRC_BINARY" .)
ok "Binary built"

# 5b — Install binary
mkdir -p "$WORK_DIR"
# 755 so the 'bird' user can traverse the directory to read include files.
# The env file (with the token) gets 600 — stays protected.
chmod 755 "$WORK_DIR"
install -m 755 "$SRC_BINARY" "$BINARY"
ok "Installed: $BINARY"

# 5c — Empty list files (BIRD2's include directive must not fail on first start)
touch -a "$WORK_DIR/user-vpn.list" "$WORK_DIR/user-isp.list"
chmod 644 "$WORK_DIR/user-vpn.list" "$WORK_DIR/user-isp.list"
ok "Route list files ready"

# 5c2 — IP check sites list
if $INSTALL_IP_CHECK_SITES; then
    install -m 644 "$SCRIPT_DIR/ip-check-sites.list" "$IP_CHECK_SITES"
    ok "ip-check-sites.list installed"
else
    rm -f "$IP_CHECK_SITES"
    ok "ip-check-sites.list removed"
fi

# 5c3 — dnsmasq TLD routing (dnsmasq + ipset + config)
if $ENABLE_DNSMASQ; then
    # Install dnsmasq and ipset if not present
    # Check by package (not binary) — dnsmasq-base provides the binary but not the service.
    for pkg in dnsmasq ipset; do
        if ! dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
            note "Installing $pkg..."
            apt-get install -y -q "$pkg" > /dev/null 2>&1
            ok "$pkg installed"
        else
            ok "$pkg already installed"
        fi
    done

    # Create the ipset (idempotent)
    if ! ipset list "$DNSMASQ_IPSET_NAME" &>/dev/null; then
        if [[ "$DNSMASQ_TIMEOUT" != "0" ]]; then
            ipset create "$DNSMASQ_IPSET_NAME" hash:ip timeout "$DNSMASQ_TIMEOUT"
        else
            ipset create "$DNSMASQ_IPSET_NAME" hash:ip
        fi
        ok "ipset $DNSMASQ_IPSET_NAME created (timeout ${DNSMASQ_TIMEOUT}s)"
    else
        ok "ipset $DNSMASQ_IPSET_NAME already exists"
    fi

    # Systemd unit to recreate ipset on boot (before dnsmasq starts)
    if [[ "$DNSMASQ_TIMEOUT" != "0" ]]; then
        IPSET_EXEC="ExecStart=/sbin/ipset create ${DNSMASQ_IPSET_NAME} hash:ip timeout ${DNSMASQ_TIMEOUT} -exist"
    else
        IPSET_EXEC="ExecStart=/sbin/ipset create ${DNSMASQ_IPSET_NAME} hash:ip -exist"
    fi
    cat > "/etc/systemd/system/ipset-${DNSMASQ_IPSET_NAME}.service" << IPSETEOF
[Unit]
Description=Create ${DNSMASQ_IPSET_NAME} ipset for dnsmasq TLD routing
Before=dnsmasq.service

[Service]
Type=oneshot
RemainAfterExit=yes
${IPSET_EXEC}
ExecStop=/sbin/ipset destroy ${DNSMASQ_IPSET_NAME}

[Install]
WantedBy=multi-user.target
IPSETEOF
    systemctl daemon-reload
    systemctl enable ipset-${DNSMASQ_IPSET_NAME} 2>/dev/null
    ok "ipset systemd unit installed"

    # Build dnsmasq ipset config from TLD list
    # Each TLD gets an ipset=/ directive: ipset=/.ru/.su/tld_isp
    DNSMASQ_IPSET_DIRECTIVE="ipset=/"
    for tld in $DNSMASQ_TLDS; do
        # Strip leading dot if present for consistency, then add it back
        tld="${tld#.}"
        DNSMASQ_IPSET_DIRECTIVE="${DNSMASQ_IPSET_DIRECTIVE}.${tld}/"
    done
    DNSMASQ_IPSET_DIRECTIVE="${DNSMASQ_IPSET_DIRECTIVE}${DNSMASQ_IPSET_NAME}"

    cat > /etc/dnsmasq.d/tld-ipset.conf << DNSEOF
# Auto-generated by bird-route-manager install.sh
# TLD-based ISP routing: resolved IPs for these TLDs are added to the
# ${DNSMASQ_IPSET_NAME} ipset, which bird-route-manager reads and routes via ISP.

# Upstream DNS servers
server=8.8.8.8
server=1.1.1.1

# Tag resolved IPs for configured TLDs
${DNSMASQ_IPSET_DIRECTIVE}

# Listen on localhost only
listen-address=127.0.0.1
bind-interfaces

# Don't read /etc/resolv.conf (we are the resolver)
no-resolv

# DNS cache
cache-size=1000
DNSEOF
    ok "dnsmasq config written: /etc/dnsmasq.d/tld-ipset.conf"

    # Ensure empty dnsmasq-isp.list for BIRD include
    touch -a "$WORK_DIR/dnsmasq-isp.list"
    chmod 644 "$WORK_DIR/dnsmasq-isp.list"

    # Disable systemd-resolved if active (conflicts with dnsmasq on port 53)
    if systemctl is-active --quiet systemd-resolved; then
        systemctl disable --now systemd-resolved > /dev/null 2>&1
        warn "Disabled systemd-resolved (dnsmasq takes over DNS)"
    fi

    # Start dnsmasq BEFORE updating resolv.conf — otherwise apt/DNS breaks
    systemctl enable dnsmasq 2>/dev/null
    systemctl restart dnsmasq
    ok "dnsmasq started"

    # Now point resolv.conf at dnsmasq (safe — dnsmasq is already listening)
    if ! grep -q "^nameserver 127.0.0.1" /etc/resolv.conf 2>/dev/null; then
        cp /etc/resolv.conf /etc/resolv.conf.bak-$(date +%Y%m%d%H%M%S) 2>/dev/null || true
        echo "nameserver 127.0.0.1" > /etc/resolv.conf
        ok "resolv.conf updated to use dnsmasq"
    fi
else
    # Clean up if previously enabled but now disabled
    if [[ -f /etc/dnsmasq.d/tld-ipset.conf ]]; then
        rm -f /etc/dnsmasq.d/tld-ipset.conf
        note "Removed /etc/dnsmasq.d/tld-ipset.conf"
        systemctl restart dnsmasq 2>/dev/null || true
    fi
    # Write empty file so BIRD include doesn't fail if protocol block remains
    touch -a "$WORK_DIR/dnsmasq-isp.list"
    chmod 644 "$WORK_DIR/dnsmasq-isp.list"
fi

# 5d — Env file
[[ -f "$ENV_FILE" ]] || touch "$ENV_FILE"
chmod 600 "$ENV_FILE"

env_set "ROUTER_ID"     "$ROUTER_ID"
env_set "VPN_INTERFACE" "$VPN_INTERFACE"
env_set "BGP_PEER_IP"   "$BGP_PEER_IP"
env_set "BGP_PEER_AS"   "$BGP_PEER_AS"
env_set "BGP_LOCAL_AS"  "$BGP_LOCAL_AS"
env_set "BGP_NEXTHOP"   "$BGP_NEXTHOP"
env_set "REFRESH_HOURS" "$REFRESH_HOURS"
env_set "WORK_DIR"      "$WORK_DIR"

if $ENABLE_DNSMASQ; then
    env_set "DNSMASQ_IPSET"         "$DNSMASQ_IPSET_NAME"
    env_set "DNSMASQ_TLDS"          "$DNSMASQ_TLDS"
    env_set "DNSMASQ_IPSET_TIMEOUT" "$DNSMASQ_TIMEOUT"
else
    env_set "DNSMASQ_IPSET" ""
fi

if $ENABLE_API && [[ -n "$NEW_TOKEN" ]]; then
    env_set "SYNC_TOKEN" "$NEW_TOKEN"
elif [[ -z "$CURRENT_TOKEN" ]]; then
    env_set "SYNC_TOKEN" ""
fi

if $ENABLE_FULLVPN; then
    env_set "FULLVPN_ENABLED"      "true"
    env_set "AWG_CONTAINER"        "$AWG_CONTAINER"
    env_set "AWG_WG_INTERFACE"     "$AWG_WG_IFACE"
    env_set "AWG_CONTAINER_IFACE"  "$AWG_CONT_IFACE"
    env_set "FULLVPN_SUBNET"       "$FULLVPN_SUBNET"
    env_set "FULLVPN_BRIDGE"       "$FULLVPN_BRIDGE"
    env_set "FULLVPN_BRIDGE_IP"    "$FULLVPN_BRIDGE_IP"
    env_set "FULLVPN_DURATION"     "$FULLVPN_DURATION"
    env_set "FULLVPN_CLEANUP"      "$FULLVPN_CLEANUP"
else
    env_set "FULLVPN_ENABLED" ""
fi

ok "Config written: $ENV_FILE"

# 5d2 — Full-VPN routing table (persistent across reboots)
if $ENABLE_FULLVPN; then
    if ! grep -q "^100[[:space:]]" /etc/iproute2/rt_tables; then
        echo "100 fulltunnel" >> /etc/iproute2/rt_tables
        ok "Added fulltunnel routing table to /etc/iproute2/rt_tables"
    else
        ok "fulltunnel routing table already configured"
    fi
fi

# 5e — BIRD2 extra config (static protocol blocks included by bird.conf)
{
    cat << EXTRAEOF
# bird-route-manager — auto-generated by install.sh
# Re-run install.sh to update.

# User-defined routes, preference 200 beats BGP (100).
# Files are managed by the bird-route-manager service.
protocol static user_vpn {
    ipv4 { preference 200; };
    include "$WORK_DIR/user-vpn.list";
}

protocol static user_isp {
    ipv4 { preference 200; };
    include "$WORK_DIR/user-isp.list";
}
EXTRAEOF

    if $ENABLE_DNSMASQ; then
        cat << DNSMASQEOF

# dnsmasq TLD routing — preference 150 beats BGP (100), loses to user lists (200).
# File is managed by bird-route-manager reading the ${DNSMASQ_IPSET_NAME} kernel ipset.
protocol static dnsmasq_isp {
    ipv4 { preference 150; };
    include "$WORK_DIR/dnsmasq-isp.list";
}
DNSMASQEOF
    fi
} > "$BIRD_EXTRA_CONF"
ok "BIRD2 protocol config written"

# 5f — BIRD2 main config
#
# Fresh install  → write full bird.conf
# Re-run         → replace only the delimited managed section
# Existing conf  → back it up, append managed section

BIRD_MANAGED_SECTION=$(cat << EOF

$MANAGED_BIRD_BEGIN
# Managed by bird-route-manager install.sh — re-run to update.

router id ${ROUTER_ID};

protocol device {
    scan time 10;
}

# Internal static route: makes BIRD resolve the BGP nexthop via the VPN interface.
# Intentionally not exported to the kernel.
protocol static vpn_nexthop {
    ipv4;
    route 0.0.0.0/0 via "${VPN_INTERFACE}";
}

protocol kernel {
    ipv4 {
        export filter {
            if proto = "bgp_feed"    then accept;
            if proto = "user_vpn"    then accept;
            if proto = "user_isp"    then accept;
            if proto = "dnsmasq_isp" then accept;
            reject;
        };
    };
}

protocol bgp bgp_feed {
    local as ${BGP_LOCAL_AS};
    neighbor ${BGP_PEER_IP} as ${BGP_PEER_AS};
    multihop;
    hold time 240;
    ipv4 {
        import filter {
            bgp_next_hop = ${BGP_NEXTHOP};
            accept;
        };
        export none;
    };
}

include "$BIRD_EXTRA_CONF";
$MANAGED_BIRD_END
EOF
)

if [[ ! -f "$BIRD_CONF" ]]; then
    printf "log syslog all;\n%s\n" "$BIRD_MANAGED_SECTION" > "$BIRD_CONF"
    ok "BIRD2 config created"
elif grep -qF "$MANAGED_BIRD_BEGIN" "$BIRD_CONF"; then
    python3 - "$BIRD_CONF" <<PYEOF
import sys
path = sys.argv[1]
begin = "$MANAGED_BIRD_BEGIN"
end   = "$MANAGED_BIRD_END"
new_section = """${BIRD_MANAGED_SECTION}"""
with open(path) as f:
    content = f.read()
b = content.index(begin)
e = content.index(end) + len(end)
with open(path, "w") as f:
    f.write(content[:b] + new_section.lstrip("\n") + content[e:])
PYEOF
    ok "BIRD2 config updated"
else
    cp "$BIRD_CONF" "${BIRD_CONF}.bak-$(date +%Y%m%d%H%M%S)"
    printf "log syslog all;\n%s\n" "$BIRD_MANAGED_SECTION" > "$BIRD_CONF"
    warn "Replaced existing bird.conf (backup saved)"
fi

bird -p 2>/dev/null && ok "BIRD2 config syntax OK" || warn "bird -p returned non-zero — check manually"

# 5g — Systemd unit
#
# When full-VPN is enabled, the service needs:
#   - Access to Docker socket (docker exec/inspect)
#   - nsenter into container network namespace
#   - ip rule / iptables on the host
# These require relaxing ProtectSystem and NoNewPrivileges.
if $ENABLE_FULLVPN; then
cat > "$SYSTEMD_UNIT" << EOF
[Unit]
Description=bird-route-manager — self-managing BIRD2 split-routing
Documentation=https://github.com/mityavasilyev/bird-route-manager
After=network-online.target bird.service docker.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BINARY
EnvironmentFile=$ENV_FILE
Restart=on-failure
RestartSec=10
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
else
cat > "$SYSTEMD_UNIT" << EOF
[Unit]
Description=bird-route-manager — self-managing BIRD2 split-routing
Documentation=https://github.com/mityavasilyev/bird-route-manager
After=network-online.target bird.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BINARY
EnvironmentFile=$ENV_FILE
Restart=on-failure
RestartSec=10
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$WORK_DIR /etc/bird
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
fi

systemctl daemon-reload
ok "Systemd unit installed"

# 5h — Start BIRD2
#
# bird.service may have a drop-in requiring the VPN interface service
# (common when set up manually). wg-quick@ units exit 1 if the interface is
# already up, leaving them in "failed" state. That blocks bird from starting.
# Reset all failed units first so systemd's dependency graph is clean.
#
# Also: on Ubuntu, enabling a WantedBy=multi-user.target service while the
# system is already in multi-user.target triggers an immediate start attempt —
# so reset-failed must happen before enable, not just before start.
systemctl reset-failed 2>/dev/null || true
systemctl enable bird 2>/dev/null || true

_start_bird() {
    # Attempt 1: normal start
    systemctl start bird 2>/dev/null && return 0

    # Attempt 2: some setups have a Requires= drop-in on the VPN interface
    # service (e.g. wg-quick@wg-ch). That service exits 1 if the interface
    # is already up, ending up in "failed" state and blocking bird. reset-failed
    # clears the marker but systemd re-triggers the dependency on the next start
    # and it fails again. If the interface is actually up, bypass dependency
    # tracking entirely — the Requires= is logically satisfied.
    warn "bird failed to start — resetting failed units and retrying..."
    systemctl reset-failed 2>/dev/null || true
    sleep 1
    if ip link show "$VPN_INTERFACE" &>/dev/null; then
        systemctl start --ignore-dependencies bird 2>/dev/null && return 0
    fi

    # Final attempt: let systemd surface the real error
    systemctl start bird
}

if systemctl is-active --quiet bird; then
    birdc configure > /dev/null 2>&1 \
        && ok "BIRD2 reloaded" \
        || warn "birdc configure returned non-zero — BIRD may still be starting"
else
    _start_bird
    ok "BIRD2 started"
fi

# 5i — Start bird-route-manager
systemctl enable bird-route-manager
systemctl restart bird-route-manager
sleep 1

if systemctl is-active --quiet bird-route-manager; then
    ok "bird-route-manager started and enabled"
else
    fail "Service did not start\n  Check: journalctl -u bird-route-manager --no-pager -n 30"
fi

# ─────────────────────────────────────────────────────────────────────────────
# [6/6] Verification
# ─────────────────────────────────────────────────────────────────────────────

hdr "6/6" "Verification"
echo ""

# Wait up to 30s for BGP to establish
echo "  Waiting for BGP session to establish..."
BGP_STATE=""
for i in $(seq 1 30); do
    BGP_STATE=$(birdc show protocols bgp_feed 2>/dev/null | awk '/bgp_feed/{print $6}')
    [[ "$BGP_STATE" == "Established" ]] && break
    sleep 1
done

if [[ "$BGP_STATE" == "Established" ]]; then
    ROUTE_COUNT=$(birdc show route count 2>/dev/null | grep "^[0-9]" | awk '{print $1}' | head -1)
    ok "BGP session: Established — $ROUTE_COUNT routes received"
else
    warn "BGP not yet Established (state: ${BGP_STATE:-unknown})"
    note "This is normal if the tunnel was just brought up — it may take a minute."
    note "Check later: birdc show protocols bgp_feed"
fi

# Verify bird-route-manager HTTP API
HTTP_CODE=$(curl -s --max-time 3 -o /dev/null -w "%{http_code}" \
    -X POST http://127.0.0.1:8081/api/v1/routes \
    -H "Content-Type: application/json" \
    -d '{}' 2>/dev/null || true)

if [[ "$HTTP_CODE" =~ ^(401|503)$ ]]; then
    ok "bird-route-manager API is up (HTTP $HTTP_CODE as expected)"
else
    warn "API did not respond as expected (got HTTP $HTTP_CODE)"
    note "Check: journalctl -u bird-route-manager --no-pager -n 20"
fi

# nginx reverse proxy for the push API
if command -v nginx &>/dev/null && systemctl is-active --quiet nginx; then
    NGINX_DEFAULT="/etc/nginx/sites-available/default"
    if [[ -f "$NGINX_DEFAULT" ]]; then
        if grep -q "proxy_pass.*8081" "$NGINX_DEFAULT" 2>/dev/null; then
            ok "nginx already proxies to bird-route-manager API"
        else
            echo ""
            note "nginx is running but has no proxy rule for the bird-route-manager API."
            note "Without it, the push API is only reachable on localhost:8081."
            if ask_yn "Add /api/v1/routes proxy to nginx?" y; then
                # Insert location block before the catch-all location /
                python3 - <<'PYEOF'
import re, sys

path = "/etc/nginx/sites-available/default"
with open(path) as f:
    content = f.read()

block = """
    # bird-route-manager API
    location /api/v1/ {
        proxy_pass http://127.0.0.1:8081;
        proxy_read_timeout 180s;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
"""

# Insert before the first 'location' directive
new_content = re.sub(r'(\s+location\s)', block + r'\1', content, count=1)
if new_content == content:
    print("    WARNING: could not find insertion point — add the location block manually")
    sys.exit(0)

with open(path, "w") as f:
    f.write(new_content)
print("    nginx config updated")
PYEOF
                if nginx -t 2>/dev/null; then
                    systemctl reload nginx
                    ok "nginx reloaded with API proxy"
                else
                    warn "nginx config test failed — check /etc/nginx/sites-available/default manually"
                fi
            fi
        fi
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Done${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  VPN interface:  ${CYAN}$VPN_INTERFACE${RESET}"
echo -e "  BGP feed:       ${CYAN}$BGP_PEER_IP AS$BGP_PEER_AS${RESET}"
echo -e "  Refresh:        ${CYAN}every ${REFRESH_HOURS}h${RESET}"
if $ENABLE_DNSMASQ; then
    echo -e "  TLD routing:    ${CYAN}${DNSMASQ_TLDS} → ipset ${DNSMASQ_IPSET_NAME}${RESET} (pref 150, timeout ${DNSMASQ_TIMEOUT}s)"
else
    echo -e "  TLD routing:    ${DIM}disabled${RESET}"
fi
if $ENABLE_FULLVPN; then
    echo -e "  Full-VPN:       ${CYAN}enabled${RESET} (container: ${AWG_CONTAINER}, duration: ${FULLVPN_DURATION}s)"
else
    echo -e "  Full-VPN:       ${DIM}disabled${RESET}"
fi
echo -e "  Config:         ${CYAN}$ENV_FILE${RESET}"

FINAL_TOKEN=$(env_get "SYNC_TOKEN" "")
if $ENABLE_API && [[ -n "$NEW_TOKEN" ]]; then
    echo ""
    echo -e "  ${BOLD}Push API token — save this now, it won't be shown again:${RESET}"
    echo ""
    echo -e "  ${YELLOW}${NEW_TOKEN}${RESET}"
    echo ""
    note "Store it in your push client and use it as the HMAC signing key."
    note "It's stored at $ENV_FILE (readable only by root)."
elif [[ -n "$FINAL_TOKEN" ]]; then
    echo -e "  Push API:       ${CYAN}enabled${RESET} (token unchanged)"
else
    echo -e "  Push API:       ${DIM}disabled${RESET}"
    note "Re-run install.sh to enable it."
fi

echo ""
echo "  Commands to check the status:"
echo "    journalctl -u bird-route-manager -f"
echo "    birdc show protocols"
echo "    birdc show route count"
echo "    ip route show | grep $VPN_INTERFACE | wc -l"
echo ""
