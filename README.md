# bird-route-manager

Self-managing BIRD2 split-routing for Linux VPS. Install it and stop thinking about it.

You give it a list of IPs, CIDRs, domain names, and AS numbers. It resolves them, writes BIRD2 static route files, and reloads BIRD2. It remembers the lists across restarts and re-resolves them periodically so routes stay current when IPs rotate (CDNs, Telegram, etc.).

## What it does

- **Accepts** mixed lists: `1.2.3.4`, `10.0.0.0/8`, `example.com`, `AS64496`
- **Resolves** domains via DNS, ASNs via RIPE Stat API, normalises CIDRs
- **Writes** two BIRD2 static route include files:
  - `user-vpn.list` — routes via your configured VPN interface (any tunnel: WireGuard, OpenVPN, Xray TUN, etc.)
  - `user-isp.list` — routes via the default gateway (forces Russian/ISP IP even if a BGP peer would route them elsewhere)
- **Reloads** BIRD2 via `birdc configure` after every write
- **Persists** raw entry lists to `state.json` — routes survive service restarts without any external push
- **Auto-refreshes** every N hours (default: 6) so DNS changes are picked up automatically
- **Optionally exposes** an HMAC-signed HTTP push API so external tools (cron jobs, scripts) can update lists remotely
- **Optionally routes entire TLDs via ISP** (e.g. all `.ru` domains) using dnsmasq + kernel ipset integration

All application files live in `/opt/bird-route-manager/`. Nothing else is written outside that directory except one systemd unit and a managed section in `/etc/bird/bird.conf`.

## Requirements

- Ubuntu 22.04+ (amd64 or arm64)
- A VPN tunnel interface already up (WireGuard, AmneziaWG, OpenVPN, Xray TUN, …)
- That's it — everything else (BIRD2, Go toolchain) is installed by `install.sh`

## Install

```bash
git clone https://github.com/mityavasilyev/bird-route-manager
cd bird-route-manager
sudo ./install.sh
```

`install.sh` is a single interactive wizard that handles everything:

1. Installs Go and BIRD2 if not present
2. Asks which VPN interface to use (lists what's available)
3. Asks for the BGP peer (defaults to antifilter.network), plus any additional feeds
4. Optionally enables the push API and generates a token
5. Writes a full `bird.conf`, builds the binary, installs the systemd service
6. Verifies the BGP session is established before exiting

Re-run `sudo ./install.sh` at any time to reconfigure. Only what you confirm is changed.

### Multiple BGP feeds

Beyond the primary feed you can peer with any number of additional BGP route
servers. `install.sh` offers to add the re:filter
([1andrevich/Re-filter-lists](https://github.com/1andrevich/Re-filter-lists))
public feed out of the box, or set your own in the env file:

```
# env: ';'-separated  name,peer_ip,peer_as[,local_as[,nexthop]]
BGP_EXTRA_FEEDS=refilter,165.22.127.207,65412
```

Each feed becomes a `protocol bgp bgp_<name>` block; BIRD merges all feeds into one
deduplicated table that is served to both local kernel routing and, if BGP Hub is
enabled, downstream peers (feed protos are auto-added to `BGPHUB_EXPORT_PROTOS`).
UFW is opened on `179/tcp` for each feed peer.

## Managing routes

### Via the push API (recommended for automation)

```bash
SYNC_TOKEN="<your-token>"
ENDPOINT="https://<your-vps>/api/v1/routes"

BODY='{"vpn":["example.com","10.0.0.0/8","AS64496"],"isp":["192.0.2.0/24"]}'
TIMESTAMP=$(date +%s)
SIG=$(printf '%s' "$BODY" | python3 -c "
import hmac, hashlib, sys, os
key = os.environ['SYNC_TOKEN'].encode()
ts  = sys.argv[1].encode()
body = sys.stdin.buffer.read()
print(hmac.new(key, ts + b':' + body, hashlib.sha256).hexdigest())
" "$TIMESTAMP")

curl -s -X POST "$ENDPOINT" \
  -H "Authorization: Bearer $SIG" \
  -H "X-Timestamp: $TIMESTAMP" \
  -H "Content-Type: application/json" \
  -d "$BODY"
# → {"ok":true,"vpn_routes":42,"isp_routes":1}
```

Sending an empty `vpn`/`isp` array clears the corresponding route file.

### Manually on the VPS

Edit the list files directly (plain BIRD2 static route format):

```
route 1.2.3.4/32 via "wg0";
route 10.0.0.0/8 via "wg0";
```

Then reload: `birdc configure`

Or push a new list via the API — it overwrites and re-resolves.

### Entry types

| Format | Example | Resolved to |
|---|---|---|
| Bare IP | `1.2.3.4` | `1.2.3.4/32` |
| CIDR | `10.0.0.0/8` | `10.0.0.0/8` |
| Domain name | `example.com` | `/32` per A record |
| AS number | `AS64496` | All announced IPv4 prefixes |

Comments (`# ...`) and blank lines are ignored.

## Configuration

All config is read from `/opt/bird-route-manager/env` (written by `setup.sh`).

| Variable | Default | Description |
|---|---|---|
| `VPN_INTERFACE` | `wg0` | Kernel interface for VPN routes |
| `REFRESH_HOURS` | `6` | Re-resolve interval (hours). Set to `0` to disable. |
| `SYNC_TOKEN` | _(empty)_ | HMAC secret. Empty = API disabled. |
| `WORK_DIR` | `/opt/bird-route-manager` | All app files live here |
| `LISTEN_ADDR` | `127.0.0.1:8081` | HTTP listen address (nginx proxies this) |
| `TIMESTAMP_WINDOW` | `300` | Max clock skew for API auth (seconds) |
| `RATE_LIMIT_MAX` | `5` | Max API requests per 60-second window |
| `DNSMASQ_IPSET` | _(empty)_ | Kernel ipset name for TLD routing. Empty = disabled. |

## Push API

The service listens on `127.0.0.1:8081` by default. Expose it via nginx for TLS:

```nginx
# In your nginx http {} block:
limit_req_zone $binary_remote_addr zone=brm:10m rate=10r/m;

# In your server {} block:
location = /api/v1/routes {
    limit_req        zone=brm burst=3 nodelay;
    limit_except POST { deny all; }
    proxy_pass            http://127.0.0.1:8081;
    proxy_read_timeout    180s;
    proxy_hide_header     Server;
}
```

### Auth scheme

```
Authorization: Bearer <hmac_hex>
X-Timestamp:   <unix_epoch_seconds>
```

`hmac_hex = HMAC-SHA256(token, "<timestamp>:" + raw_body_bytes)`

Requests with a timestamp outside ±5 minutes are rejected (replay protection). The token never appears in logs or error responses.

### Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/routes` | Push new entry lists |
| `POST` | `/api/v1/fullvpn` | Enable/disable/list full-VPN overrides (requires `FULLVPN_ENABLED=true`) |
| `POST` | `/api/v1/peers` | Set/list peer name→pubkey mappings (requires `FULLVPN_ENABLED=true`) |
| any other | any | `404 not found` |

When `SYNC_TOKEN` is not set, all requests return `503 api not enabled`.

## BIRD2 integration

`install.sh` writes a managed section in `/etc/bird/bird.conf` (replacing any existing default config on first install):

```bird
protocol static user_vpn {
    ipv4 { preference 200; };
    include "/opt/bird-route-manager/user-vpn.list";
}

protocol static user_isp {
    ipv4 { preference 200; };
    include "/opt/bird-route-manager/user-isp.list";
}

# Only when dnsmasq TLD routing is enabled:
protocol static dnsmasq_isp {
    ipv4 { preference 150; };
    include "/opt/bird-route-manager/dnsmasq-isp.list";
}
```

The kernel export filter accepts routes from `bgp_feed`, `user_vpn`, `user_isp`, and `dnsmasq_isp`. The `include` files are in BIRD2 static route format — you can inspect them directly: `cat /opt/bird-route-manager/user-vpn.list`.

## TLD-based ISP routing (optional)

Route all domains under specific TLDs (e.g. `.ru`) via ISP automatically. Enable it during `install.sh` setup.

**How it works:**
1. dnsmasq resolves DNS queries and adds IPs for matching TLDs to a kernel ipset
2. bird-route-manager reads the ipset on every apply/refresh cycle
3. IPs are written to `dnsmasq-isp.list` as BIRD2 static routes via the ISP gateway
4. The `dnsmasq_isp` protocol has preference 150 — beats BGP (100) but loses to user lists (200)
5. Ipset entries auto-expire (default 6h), so stale IPs fall back to normal routing

`install.sh` handles everything: dnsmasq + ipset packages, config files, systemd units, and BIRD2 protocol setup. To disable later, re-run `install.sh` and answer no, or set `DNSMASQ_IPSET=` in the env file.

## Full-VPN per-peer override (optional)

Temporarily route individual VPN peers through the VPN tunnel for **all** traffic, bypassing split routing. Overrides auto-expire (default 15 minutes). Enable it during `install.sh` setup.

Designed for setups where VPN peers connect through an AmneziaWG Docker container. The service reads peer info from the container (via `docker exec`), then uses `nsenter` + `ip rule` to selectively route specific peers through the VPN tunnel.

### Managing peers

Register your VPN peers (name → WireGuard public key):

```bash
BODY='{"peers":{"alice":"NV5DpuFVhRgY/xQTxE0Ctcd9pGa2ONuLRcFPusFpqSI=","bob":"5bziAfQQu3/rvQs428oWwGMjV3v8WsWIetTxFI6Qt2U="}}'
# sign and POST to /api/v1/peers (same auth as /api/v1/routes)
```

### Toggling full VPN

```bash
# Enable (routes all traffic through VPN for 15 minutes)
BODY='{"peer":"alice"}'
# sign and POST to /api/v1/fullvpn

# Disable early
BODY='{"peer":"alice","enable":false}'
# sign and POST to /api/v1/fullvpn

# List active overrides
BODY='{}'
# sign and POST to /api/v1/fullvpn
```

### Configuration

| Variable | Default | Description |
|---|---|---|
| `FULLVPN_ENABLED` | _(empty)_ | Set to `true` to enable |
| `AWG_CONTAINER` | `amnezia-awg` | Docker container name |
| `AWG_WG_INTERFACE` | `wg0` | WireGuard interface inside container |
| `AWG_CONTAINER_IFACE` | `eth1` | Container's outgoing network interface |
| `FULLVPN_DURATION` | `900` | Override duration in seconds |
| `FULLVPN_CLEANUP` | `180` | Cleanup/re-apply interval in seconds |
| `FULLVPN_SUBNET` | `10.8.3.0/24` | VPN client subnet |
| `FULLVPN_BRIDGE` | `amn0` | Docker bridge interface |
| `FULLVPN_BRIDGE_IP` | `172.29.172.2` | Container's bridge IP |

## Uninstall

```bash
systemctl stop bird-route-manager
systemctl disable bird-route-manager
rm -f /etc/systemd/system/bird-route-manager.service
rm -rf /opt/bird-route-manager
systemctl daemon-reload
# remove the cloned repo if you don't need it anymore
```

Then remove the managed section from `/etc/bird/bird.conf` (between the `# --- bird-route-manager begin ---` and `# --- bird-route-manager end ---` markers) and reload BIRD2.

## Security

- The service listens on `127.0.0.1` only — not reachable from outside without nginx
- HMAC-SHA256 auth with timestamp-bound signatures (replay window: 5 min)
- Request body size capped at 64 KB
- Rate-limited: 5 requests per 60 seconds (configurable)
- Input validation: every entry is classified before resolution; unknown entries are dropped
- Route files are written atomically (temp file + rename) — BIRD2 never reads a partial write
- Token is stored mode 600, never appears in logs or HTTP headers
- The service sets `NoNewPrivileges=true` and `ProtectSystem=strict` in its systemd unit

## Development

```bash
go test ./...          # unit + e2e tests
go test -race ./...    # with race detector
go vet ./...
```

Tests use injectable fakes for all system calls (`birdc`, `ip route`, DNS, RIPE API) and run the full HTTP server in-process — no BIRD2 installation needed.

## License

MIT — see [LICENSE](LICENSE).
