#!/usr/bin/env bash
# install.sh — full zero-to-running installer for bird-route-manager
#
# Installs and configures on a fresh Ubuntu VPS:
#   • Go toolchain (if not already present)
#   • BIRD2 routing daemon with antifilter BGP split-routing
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
note "be routed via your VPN. For antifilter.download, keep all defaults."
echo ""

CURRENT_BGP_PEER=$(env_get "BGP_PEER_IP"  "45.154.73.71")
CURRENT_BGP_AS=$(env_get   "BGP_PEER_AS"  "65432")
CURRENT_LOCAL_AS=$(env_get "BGP_LOCAL_AS" "64999")
CURRENT_BGP_NH=$(env_get   "BGP_NEXTHOP"  "10.8.1.1")
CHANGE_BGP=false

if $REINSTALL; then
    echo -e "  Current feed: ${CYAN}${CURRENT_BGP_PEER} AS${CURRENT_BGP_AS}${RESET}"
    ask_yn "Change BGP settings?" n && CHANGE_BGP=true || CHANGE_BGP=false
else
    ask_yn "Using antifilter.download? (keep defaults)" y \
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
    ok "Using antifilter.download defaults"
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

# 5c2 — IP check sites list (optional: route IP-echo domains via ISP)
IP_CHECK_SITES="$WORK_DIR/ip-check-sites.list"
if [[ -f "$IP_CHECK_SITES" ]]; then
    ok "ip-check-sites.list already present (not overwritten)"
else
    echo ""
    note "IP-check sites routing: resolves IP-echo service domains (ifconfig.me etc.)"
    note "and forces their IPs via ISP so they never route through the VPN."
    note "Disable if you intentionally want those sites to go through the VPN."
    echo ""
    if ask_yn "Route IP-check sites via ISP?" y; then
        install -m 644 "$SCRIPT_DIR/ip-check-sites.list" "$IP_CHECK_SITES"
        ok "Installed ip-check-sites.list"
    else
        ok "Skipped — IP-check sites will follow normal routing"
    fi
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

if $ENABLE_API && [[ -n "$NEW_TOKEN" ]]; then
    env_set "SYNC_TOKEN" "$NEW_TOKEN"
elif [[ -z "$CURRENT_TOKEN" ]]; then
    env_set "SYNC_TOKEN" ""
fi

ok "Config written: $ENV_FILE"

# 5e — BIRD2 extra config (static protocol blocks included by bird.conf)
cat > "$BIRD_EXTRA_CONF" << EOF
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
EOF
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
            if proto = "antifilter" then accept;
            if proto = "user_vpn"   then accept;
            if proto = "user_isp"   then accept;
            reject;
        };
    };
}

protocol bgp antifilter {
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
    printf '\n%s\n' "$BIRD_MANAGED_SECTION" >> "$BIRD_CONF"
    warn "Appended to existing bird.conf (backup saved)"
fi

bird -p 2>/dev/null && ok "BIRD2 config syntax OK" || warn "bird -p returned non-zero — check manually"

# 5g — Systemd unit
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
    BGP_STATE=$(birdc show protocols antifilter 2>/dev/null | awk '/antifilter/{print $6}')
    [[ "$BGP_STATE" == "Established" ]] && break
    sleep 1
done

if [[ "$BGP_STATE" == "Established" ]]; then
    ROUTE_COUNT=$(birdc show route count 2>/dev/null | grep "^[0-9]" | awk '{print $1}' | head -1)
    ok "BGP session: Established — $ROUTE_COUNT routes received"
else
    warn "BGP not yet Established (state: ${BGP_STATE:-unknown})"
    note "This is normal if the tunnel was just brought up — it may take a minute."
    note "Check later: birdc show protocols antifilter"
fi

# Verify bird-route-manager HTTP API
HTTP_CODE=$(curl -sf --max-time 3 -o /dev/null -w "%{http_code}" \
    -X POST http://127.0.0.1:8081/api/v1/routes \
    -H "Content-Type: application/json" \
    -d '{}' 2>/dev/null || echo "000")

if [[ "$HTTP_CODE" =~ ^(401|503)$ ]]; then
    ok "bird-route-manager API is up (HTTP $HTTP_CODE as expected)"
else
    warn "API did not respond as expected (got HTTP $HTTP_CODE)"
    note "Check: journalctl -u bird-route-manager --no-pager -n 20"
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
