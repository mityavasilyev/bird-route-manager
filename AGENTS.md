# bird-route-manager — agent context

Read this before touching anything. It covers what the project is, how it's structured, and decisions that aren't obvious from the code.

---

## What this is

A self-managing BIRD2 split-routing daemon for Linux VPS. It accepts mixed lists of IPs/CIDRs/domains/ASNs via a signed HTTP API, resolves them to IPv4 CIDRs, writes BIRD2 static route include files, and calls `birdc configure`. It also persists the raw (pre-resolution) lists and re-resolves them on a schedule so DNS changes are picked up automatically.

The intended use case: a Russian VPS running AmneziaWG/WireGuard as a VPN exit. Blocked sites go via the VPN interface; everything else via the ISP. BIRD2 handles routing. This tool manages the user-defined route lists on top of whatever BGP or other protocols BIRD2 is already running.

---

## Repo map

| File | Purpose |
|---|---|
| `main.go` | Core service — route management, HTTP dispatch, entry point |
| `fullvpn.go` | Full-VPN per-peer override module — separate executor, state, handlers |
| `main_test.go` | Unit + e2e tests for core features — all system calls faked |
| `fullvpn_test.go` | Tests for fullvpn module — fakeFullVPNExecutor |
| `bgphub.go` | BGP Hub module — route redistribution to downstream BIRD2 peers |
| `bgphub_test.go` | Tests for bgphub module |
| `bgphub` | CLI script for managing downstream BGP peers (installed to `/usr/local/bin/bgphub`) |
| `go.mod` | `go 1.25`, module `github.com/mityavasilyev/bird-route-manager` |
| `install.sh` | Interactive idempotent installer — the user-facing entry point |
| `TODO.md` | What has NOT been tested on real hardware — read before shipping |
| `README.md` | Public documentation |

---

## Architecture

```
HTTP push  ─→  Handler  ─→  Manager.Update()  ─→  resolveEntries()  ─→  atomicWrite()  ─→  BirdConfigure()
                  │              │                                                               │
                  │         saveState()                                                    Executor interface
                  │              │                                                        (real: exec birdc)
                  │        state.json                                                     (test: fakeExecutor)
                  │              │
                  │  (on startup) LoadState()
                  │  (on ticker)  Refresh()  ─→  same resolve → write → reload path
                  │
                  ├─→  FullVPNManager.HandleFullVPN()  ─→  Enable/Disable  ─→  FullVPNExecutor
                  │         │                                                   (nsenter, ip rule,
                  │    fullvpn-state.json                                        docker exec)
                  │    peers.json
                  │
                  └─→  FullVPNManager.HandlePeers()

(on startup, before LoadState)
  bgphubConfigFromEnv()  ─→  EnsureBGPHubConf()
       │                          │
  bgphub-peers.json ──→ GenerateBGPHubConf() ──→ atomicWrite(bgphub-peers.conf) ──→ BirdConfigure()
       │
  (managed by bgphub CLI script — no HTTP API)
```

Three injectable interfaces make everything testable without BIRD2 or real networking:
- `Executor` — `DefaultGW()`, `BirdConfigure()`, and `ReadIPSet()` (faked in tests)
- `Resolver` — `LookupHost()` and `LookupASN()` (faked in tests)
- `FullVPNExecutor` — `WgPeers()`, `ContainerPID()`, `NATBypass()`, `PolicyRule()`, `EnsureRouteSetup()` (faked in tests)

Tests spin up the full HTTP server with `httptest.NewServer` and make real HTTP requests against it. No mocking framework — just struct fakes in `main_test.go`.

---

## Key design decisions

**Single project space.** Everything lives in `/opt/bird-route-manager/`: binary, env file, state, and the two BIRD2 route list files. The only files written outside are `/etc/systemd/system/bird-route-manager.service` and a managed section in `/etc/bird/bird.conf`. Easy to uninstall.

**Persist raw entries, not resolved CIDRs.** `state.json` stores what the user sent (`example.com`, `AS64496`) not the resolved IPs. On each refresh the full resolution runs again — this is how DNS changes get picked up. If we stored resolved CIDRs, a domain that rotated IPs would silently route to stale addresses.

**VPN interface is a config, not a BIRD2 protocol.** The `VPN_INTERFACE` env var becomes `"wg0"` (quoted = interface name) in the BIRD2 `via` clause. This works for any tunnel type — WireGuard, OpenVPN, Xray TUN, etc. The service has no WireGuard-specific code.

**API is optional.** If `SYNC_TOKEN` is empty, the service starts normally (loads state, refreshes) but returns `503` on all API calls. This means the service is useful even without the push API — just edit `state.json` manually and restart.

**HMAC replay protection.** Auth is `HMAC-SHA256(token, "<timestamp>:<body>")`. Timestamp must be within ±5 minutes. This prevents replaying a captured request. Token is stored mode 600, never in logs.

**ISP nexthop is auto-detected.** `ip route show default` gives the gateway. No config needed. VPN nexthop is explicit config (interface name).

**`install.sh` is idempotent by design.** It reads existing config from `env` and only changes what the user explicitly confirms. Safe to re-run after binary updates, token rotation, or interface changes. On first run it installs Go (if needed), builds the binary from source, writes a full `bird.conf`, and installs the systemd service. The intended flow is: `git clone` the repo onto the VPS, then `sudo ./install.sh`.

---

## BIRD2 config managed by install.sh

`install.sh` writes a delimited section into `/etc/bird/bird.conf`:

```
# ---- bird-route-manager begin ----
router id <PUBLIC_IP>;
protocol device { scan time 10; }
protocol static vpn_nexthop { route 0.0.0.0/0 via "<VPN_INTERFACE>"; }
protocol kernel { ipv4 { export filter { antifilter + user_vpn + user_isp }; }; }
protocol bgp antifilter { ... }
include "/opt/bird-route-manager/bird-extra.conf";
# ---- bird-route-manager end ----
```

`bird-extra.conf` (also in WorkDir) contains the two `protocol static user_vpn / user_isp` blocks that include the route list files. On re-runs, `install.sh` replaces just the managed section using a Python one-liner — it never touches anything outside the delimiters.

On re-install with an existing `bird.conf` that has no managed section, `install.sh` replaces the entire file (backing up the original). This avoids duplicate protocol definitions from Ubuntu's default `bird.conf`.

---

## dnsmasq ipset layer (optional)

When `DNSMASQ_IPSET` env var is set, the service reads a kernel ipset on every apply/refresh and writes a separate BIRD2 route file (`dnsmasq-isp.list`). This enables TLD-based ISP routing — e.g. all `.ru` domains go via ISP instead of VPN.

**How it works:** dnsmasq is configured with `ipset=/.ru/tld_isp` — every DNS query for a `.ru` domain adds the resolved IPs to the `tld_isp` kernel ipset with a timeout (default 6h). bird-route-manager reads this ipset via `Executor.ReadIPSet()`, writes the IPs as BIRD2 static routes via ISP gateway, and reloads. The `dnsmasq_isp` protocol has preference 150 (beats BGP at 100, loses to user lists at 200). Ipset entries auto-expire, so stale IPs fall back to normal routing.

`install.sh` handles the full setup: dnsmasq + ipset packages, dnsmasq config, ipset boot-persistence systemd unit, BIRD2 `dnsmasq_isp` protocol block, and kernel export filter.

**Config:** `DNSMASQ_IPSET` (ipset name), `DNSMASQ_TLDS` (space-separated TLDs), `DNSMASQ_IPSET_TIMEOUT` (seconds, 0 = no expiry).

---

## Full-VPN per-peer override (optional)

When `FULLVPN_ENABLED=true`, the service can temporarily route individual VPN peers through the VPN tunnel for ALL traffic (bypassing split routing). Designed for AmneziaWG running in Docker.

**The problem:** The AmneziaWG container masquerades all peer traffic (`10.8.3.0/24 → 172.29.172.2`) before it reaches the host, so the host can't distinguish peers for routing.

**The solution:** For override-active peers, `nsenter` adds a transient NAT bypass rule in the container's network namespace (`iptables -t nat -I POSTROUTING -s <peer_ip> -o eth1 -j RETURN`), then a host `ip rule from <peer_ip> table fulltunnel` routes that peer via the VPN tunnel. These rules are ephemeral — lost on container restart — and the cleanup ticker re-applies them every 3 minutes.

**Module structure:** `fullvpn.go` is a self-contained module with its own `FullVPNExecutor` interface (separate from the main `Executor`), state management, and HTTP handlers. All container interaction is isolated in the executor, so if the container setup changes, only the executor implementation needs updating.

**State files:**
- `peers.json` — name→pubkey mapping, managed via `POST /api/v1/peers`
- `fullvpn-state.json` — active overrides with expiry times

**API endpoints** (same HMAC auth as `/api/v1/routes`):
- `POST /api/v1/fullvpn` — enable/disable/list overrides
- `POST /api/v1/peers` — set/list peer name→pubkey mappings

**Config:** `FULLVPN_ENABLED`, `AWG_CONTAINER`, `AWG_WG_INTERFACE`, `AWG_CONTAINER_IFACE`, `FULLVPN_TABLE`, `FULLVPN_DURATION` (seconds), `FULLVPN_CLEANUP` (seconds), `FULLVPN_SUBNET`, `FULLVPN_BRIDGE`, `FULLVPN_BRIDGE_IP`.

**One-time host setup** (handled by `install.sh` + service startup):
- `/etc/iproute2/rt_tables` gets `100 fulltunnel` entry (install.sh, persistent)
- Service calls `EnsureRouteSetup()` on startup to set runtime routes + MASQUERADE (idempotent)

---

## BGP Hub — route redistribution to downstream peers (optional)

When `BGPHUB_ENABLED=true`, the service generates a BIRD2 config file (`bgphub-peers.conf`) that re-exports `bgp_feed` + `user_vpn` routes to downstream BIRD2 peers. This lets a central VPS act as a BGP route hub for home routers and other clients connected via VPN.

**How it works:** On startup, the service reads `bgphub-peers.json` (managed by the `bgphub` CLI), generates `bgphub-peers.conf` with an export filter and per-peer protocol blocks, writes it atomically, and calls `birdc configure`. The generated config is included from `bird-extra.conf`.

**No HTTP API.** Peers are managed via the `bgphub` CLI on the VPS:
```bash
bgphub add home-router 10.8.3.8 64998   # register a peer
bgphub remove 10.8.3.8                   # remove by IP
bgphub list                               # show all peers
```

After add/remove, the CLI restarts bird-route-manager which regenerates the config.

**Generated BIRD2 config** (`bgphub-peers.conf`):
```bird
filter bgphub_export {
    if proto = "bgp_feed" then { bgp_next_hop = 10.8.3.0; accept; }
    if proto = "user_vpn" then { bgp_next_hop = 10.8.3.0; accept; }
    reject;
}

protocol bgp bgphub_home_router {
    local as 64999;
    neighbor 10.8.3.8 as 64998;
    hold time 240;
    ipv4 {
        import none;
        export filter bgphub_export;
    };
}
```

**Config:** `BGPHUB_ENABLED`, `BGPHUB_NEXTHOP` (sentinel IP for downstream peers, typically the VPS's VPN IP), `BGPHUB_LOCAL_AS`, `BGPHUB_EXPORT_PROTOS` (comma-separated protocol names), `BGPHUB_ALLOWED_SUBNET` (used by CLI for validation).

**Client setup:** Downstream clients use `install.sh` as-is — they just enter the hub VPS's VPN IP as the BGP peer and the hub's AS number. No client-side code changes needed.

**State files:**
- `bgphub-peers.json` — peer list (managed by CLI)
- `bgphub-peers.conf` — generated BIRD2 config (managed by service)

---

## Testing

```bash
go test -race ./...   # all 65 tests, ~1.5s
go vet ./...
```

Tests are in `main_test.go` and `fullvpn_test.go` in the same package (`package main`) so they can access unexported types.

What the tests cover: HMAC auth, entry classification, deduplication, route file format, atomic writes, state persistence across simulated restarts, background refresh, HTTP handler auth/rate-limit/error paths, concurrent pushes, interface nexthop format, server header suppression, dnsmasq ipset parsing/apply/disable/errors/refresh, fullvpn peer lookup (by name/pubkey), fullvpn enable/disable/expiry/cleanup, fullvpn state persistence, fullvpn HTTP handlers (enable/disable/list/peers/auth), rollback on partial failure.

What the tests do NOT cover: actual `birdc` execution, actual kernel routes, actual DNS, actual RIPE API, actual `ipset` commands, actual `docker exec`/`nsenter`, `install.sh`. See `TODO.md` for the full list and a smoke-test script to run on a real VPS.

---

## What to be careful about

- **Never put the BIRD2 BGP peer IP in `user-vpn.list`.** If the antifilter BGP peer (`45.154.73.71` in the known deployment) ends up in that list, BIRD routes its own TCP connection to the peer via the VPN interface. The peer closes the connection, BGP drops, all ~16k antifilter routes vanish. This is an operator concern, not something the service can prevent — but worth knowing if you're extending the API or adding auto-population features.

- **`birdc configure` must succeed before `saveState`.** The current code saves state only after a successful apply. If `birdc configure` fails, state is not updated — the previous lists remain in state. This is intentional: don't persist a broken configuration.

- **Atomic writes use same-directory temp files.** `os.CreateTemp(dir, ...)` + `os.Rename` is atomic on Linux. If `WorkDir` and the temp file end up on different filesystems this breaks. Not a realistic concern for the current layout but worth knowing.

- **`go 1.25` uses `strings.SplitSeq`** (range-over iterator, introduced in 1.23). Don't downgrade the module version without replacing that call.

- **The `Server` HTTP header is cleared** in `jsonResp`. Don't add middleware that re-sets it.

---

## Adding features

**New entry type** (e.g. IPv6): add a case to `classify()`, handle it in `resolveEntries()`, update `cleanEntries()` validation, add tests. The route file writer and state persistence need no changes.

**New API endpoint**: add a `case` to the `switch r.URL.Path` in `NewHandler`. Keep the pattern: unknown path → 404 (don't reveal path existence). Use `verifyAndReadBody()` for auth.

**Web UI**: out of scope for this tool. The service is designed to be driven by external automation (cron jobs, scripts). A UI belongs in a separate companion tool.
