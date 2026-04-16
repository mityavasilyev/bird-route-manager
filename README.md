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
3. Asks for the BGP peer (defaults to antifilter.network)
4. Optionally enables the push API and generates a token
5. Writes a full `bird.conf`, builds the binary, installs the systemd service
6. Verifies the BGP session is established before exiting

Re-run `sudo ./install.sh` at any time to reconfigure. Only what you confirm is changed.

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
| any other | any | `404 not found` |

When `SYNC_TOKEN` is not set, all requests return `503 api not enabled`.

## BIRD2 integration

`setup.sh` appends a managed section to `/etc/bird/bird.conf`:

```bird
protocol static user_vpn {
    ipv4;
    include "/opt/bird-route-manager/user-vpn.list";
}

protocol static user_isp {
    ipv4;
    include "/opt/bird-route-manager/user-isp.list";
}
```

And a kernel protocol that exports these routes:

```bird
protocol kernel brm_kernel {
    ipv4 {
        export filter {
            if proto = "user_vpn" then accept;
            if proto = "user_isp" then accept;
            reject;
        };
    };
}
```

If you already have a `protocol kernel` block, merge the filter clauses into it to avoid having two kernel exporters. The `include` files are in BIRD2 static route format — you can inspect them directly: `cat /opt/bird-route-manager/user-vpn.list`.

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
