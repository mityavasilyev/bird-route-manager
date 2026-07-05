# Orion's Belt (evolving from bird-route-manager)

Read this before touching anything. This file serves two purposes:
1. Agent context for the current bird-route-manager code
2. Vision and guidelines for the Orion's Belt evolution

---

## Project vision

bird-route-manager is evolving into **Orion's Belt** — a modular, self-deploying mesh
infrastructure system. The binary name will be `belt`. The current routing code becomes
one module among many. The evolution is incremental: bird-route-manager stays functional
at every step.

**Design documents:** As the project evolves, architecture docs, operational design,
and decision logs will live in this repo under `docs/`. Until then, the vision and
key decisions are captured in this file.

---

## Core principles (revised after adversarial review)

1. **Failsafe-first.** Every external dependency (DNS, BGP, Let's Encrypt, GitHub, Docker Hub,
   APT repos) can disappear tomorrow. Cache locally, degrade gracefully, run on whatever
   version is already installed. The mesh must survive a 72-hour internet partition with
   zero operator intervention. Transport can be blocked → sidecar fallback.

2. **Open-source secure (Kerckhoffs's principle).** Code is public. All security derives
   from keys, never from code secrecy. Attacker knows everything except secrets.

3. **Single binary, many modules.** One `belt` binary per node. Modules activated by config.
   No containers, no interpreters, no runtime deps beyond libc. Cross-compile to any
   architecture Go supports.

3. **Local-first.** All state lives on the node. Mesh sync is eventually-consistent
   replication, not a central database. No SPOF.

4. **Explicit over automatic.** No auto-heal, no auto-failover (at current scale). Detect,
   alert, let operator decide. Automatic actions limited to: cache refresh, cert renewal,
   health check escalation, tunnel keepalive.

5. **Idempotent everything.** Running install twice = same result. Running apply after
   config change = converge to desired state.

6. **Package relay.** Nodes that can reach distribution servers (GitHub, Docker Hub, APT)
   relay artifacts to nodes that can't (e.g., behind Russian/Chinese firewalls). No node
   should fail because it can't download a dependency.

7. **Webhook-only alerting.** The binary sends alerts to a configurable webhook URL (JSON +
   HMAC signature). The user's own system (n8n, custom handler, etc.) decides how to
   deliver notifications. No Telegram/email/Slack logic in the binary.

8. **Transport-agnostic.** WireGuard is the default but the system must support swapping
   transports (VLESS, Shadowsocks, etc.) via sidecar binaries without code changes.
   Node identity is Ed25519, not tied to any transport key.

9. **Routing groups.** Traffic routes through named groups (europe, russia, banking, etc.),
   not binary VPN/ISP. Each group has exit nodes with automatic failover.

---

## What this is right now

A self-managing BIRD2 split-routing daemon for Linux VPS. It accepts mixed lists of
IPs/CIDRs/domains/ASNs via a signed HTTP API, resolves them to IPv4 CIDRs, writes BIRD2
static route include files, and calls `birdc configure`.

**Current modules (will become Orion's Belt modules):**
- Route management → `routing` module
- Full-VPN per-peer override → `fullvpn` module
- BGP Hub redistribution → `bgphub` module

---

## Repo map

| File | Purpose |
|---|---|
| `main.go` | Core service — route management, HTTP dispatch, entry point |
| `fullvpn.go` | Full-VPN per-peer override module |
| `bgphub.go` | BGP Hub — route redistribution to downstream peers |
| `main_test.go` | Unit + e2e tests for core |
| `fullvpn_test.go` | Tests for fullvpn module |
| `bgphub_test.go` | Tests for bgphub module |
| `bgphub` | CLI script for managing BGP peers |
| `install.sh` | Interactive idempotent installer |
| `go.mod` | `go 1.25`, module `github.com/mityavasilyev/bird-route-manager` |
| `TODO.md` | What has NOT been tested on real hardware |
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
                  │         │                                                   kernel: awg show, ip rule
                  │    fullvpn-state.json                                        docker: nsenter, docker exec
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

Tests spin up the full HTTP server with `httptest.NewServer` and make real HTTP requests.
No mocking framework — just struct fakes.

---

## Key design decisions (current code)

**Single project space.** Everything in `/opt/bird-route-manager/`. Easy to uninstall.

**Persist raw entries, not resolved CIDRs.** `state.json` stores `example.com`, not the
resolved IPs. Periodic refresh picks up DNS changes.

**VPN interface is a config, not a protocol.** Works for any tunnel type.

**API is optional.** Empty `SYNC_TOKEN` = service runs without API.

**HMAC replay protection.** `HMAC-SHA256(token, "<timestamp>:<body>")`, ±5 min window.

**ISP nexthop is auto-detected.** `ip route show default`.

**`install.sh` is idempotent.** Safe to re-run.

---

## Evolution guidelines

### Go package layout (defined after adversarial review)

```
belt/
  cmd/belt/main.go              # Entry point, module registration
  internal/
    core/                       # Config (TOML + role presets), lifecycle, API, CLI, node identity (Ed25519)
      config.go                 # TOML parsing, defaults, validation, role presets
      module.go                 # Module interface, ModuleInfo, registry
      api.go                    # Unix socket + TCP API server
      identity.go               # Ed25519 node.key generation and management
    modules/
      routing/                  # Current bird-route-manager + fullvpn + bgphub (internal)
        routing.go              # Route management, groups, failover
        resolver.go             # DNS + ASN resolution
        executor.go             # Executor interface + system impl
        birdconf.go             # BIRD2 config generation
        fullvpn.go              # Per-peer VPN override (internal feature, not separate module)
        bgphub.go               # BGP hub redistribution (internal feature)
        groups.go               # Routing group management + failover logic
      monitor/
        monitor.go              # Health checks, metrics (bbolt)
        alerts.go               # Alert pipeline + webhook dispatch (HMAC-signed)
        checks.go               # Individual check implementations
      mesh/
        mesh.go                 # Peer registry, topology management
        join.go                 # Join tokens (single-use, expiry, revocation)
        announce.go             # Signed peer announcements (Ed25519)
        sync.go                 # State sync between nodes
    shared/                     # Types used across modules
      types.go                  # ModuleInfo, FirewallRule, HealthCheck, etc.
      atomicwrite.go            # Shared utilities
      store.go                  # StateStore interface (bbolt default, JSON fallback)
```

### Adding new Orion's Belt modules

1. Each module is a Go file (or package under `internal/modules/`) with a standard interface
2. Module has: `Init()`, `Start()`, `Stop()`, `Health()`, `Status()` methods
3. Module declares its config schema (TOML section)
4. Module declares its firewall rules (ports it needs open)
5. Module declares its health checks (what to monitor)
6. All system interaction goes through injectable interfaces (like existing Executor pattern)
7. Tests use struct fakes, not mocking frameworks

### Config format

TOML. File at `/etc/belt/config.toml`. One file per node.

### Backward compatibility

During evolution, these must keep working:
- `install.sh` for fresh bird-route-manager deployments
- API on `127.0.0.1:8081` for `sync-lists.sh`
- `bgphub` CLI script
- Existing state files (`state.json`, `fullvpn-state.json`, `bgphub-peers.json`)
- `awg-mode` functionality (absorbed into `belt vpn mode`)

### Testing

- **Unit tests:** Same pattern — injectable interfaces, struct fakes
- **E2E tests:** Docker containers emulating VPS nodes. Each container = one "VPS"
  with its own network namespace. Docker Compose for 3-node mesh (exit + hub + client).
- Run `go test -race ./...` before every commit
- E2E suite: `make test-e2e` (Docker Compose up, run tests, down)

### What NOT to do

- Don't break current bird-route-manager functionality while evolving
- Don't add external Go dependencies beyond the approved set (BurntSushi/toml, bbolt)
- Don't implement auto-failover until there are 2+ exit nodes
- Don't add Telegram/email/Slack to the binary — alerts go to webhook only
- Don't hardcode IPs — everything comes from config
- Don't assume internet is available — every feature must work in degraded mode
- Don't use mocking frameworks — struct fakes are the pattern here
- Don't create separate binaries — one binary, module flags (sidecar transports are exceptions)
- Don't derive security from code secrecy — code is open source, security = keys only
- Don't implement custom crypto — use standard algorithms, shell out to `age` for encryption
- Don't implement ACME — shell out to `certbot`
- Don't tie node identity to WireGuard keys — use separate Ed25519 `node.key`

---

## BIRD2 config managed by install.sh

`install.sh` writes a delimited section into `/etc/bird/bird.conf`:

```
# ---- bird-route-manager begin ----
router id <PUBLIC_IP>;
protocol device { scan time 10; }
protocol static vpn_nexthop { route 0.0.0.0/0 via "<VPN_INTERFACE>"; }
protocol kernel { ipv4 { export filter { bgp_feed + <extra feeds> + user_vpn + user_isp + dnsmasq_isp }; }; }
protocol bgp bgp_feed { ... }          # primary feed (antifilter)
protocol bgp bgp_<name> { ... }        # one per BGP_EXTRA_FEEDS entry (e.g. bgp_refilter)
include "/opt/bird-route-manager/bird-extra.conf";
# ---- bird-route-manager end ----
```

On re-runs, replaces just the managed section. Never touches anything outside delimiters.

### Multiple BGP feeds (`BGP_EXTRA_FEEDS`)

The primary feed (`BGP_PEER_IP`/`BGP_PEER_AS`/…) is `bgp_feed`. Additional feeds are
configured via `BGP_EXTRA_FEEDS` in the env file — a `;`-separated list of
`name,peer_ip,peer_as[,local_as[,nexthop]]` (local_as/nexthop default to the primary
feed's). `install.sh` renders one `protocol bgp bgp_<name>` per entry, all import-only
with the nexthop rewritten to the shared sentinel, so **BIRD merges every feed into one
deduplicated routing table**. Each feed proto is auto-added to the kernel export filter
(so this node's own VPN clients get the union) and appended to `BGPHUB_EXPORT_PROTOS`
(so downstream BGP subscribers get the union too). `install.sh` also opens `179/tcp` in
UFW for each extra feed peer. No list-merging code — BIRD's route table *is* the merge.

Example: `BGP_EXTRA_FEEDS=refilter,165.22.127.207,65412` adds the re:filter
(1andrevich/Re-filter-lists) public BGP feed alongside antifilter.

---

## dnsmasq ipset layer (optional)

When `DNSMASQ_IPSET` is set, reads kernel ipset, writes BIRD2 route file for TLD-based
ISP routing (e.g. `.ru` → ISP). See `AGENTS.md` for details.

---

## Full-VPN per-peer override (optional)

When `FULLVPN_ENABLED=true`, temporarily route individual peers through full VPN tunnel.
Dual-mode: kernel WireGuard + Docker. Auto-detected at startup. See `AGENTS.md` for details.

---

## BGP Hub (optional)

When `BGPHUB_ENABLED=true`, re-exports routes to downstream peers. Managed via `bgphub`
CLI. See `AGENTS.md` for details.

---

## Testing

```bash
go test -race ./...   # ~1.5s
go vet ./...
```

Tests cover: HMAC auth, entry classification, dedup, route file format, atomic writes,
state persistence, refresh, HTTP handlers, fullvpn, bgphub, rollback on failure.

Tests do NOT cover: actual birdc, kernel routes, real DNS/RIPE API, actual Docker/nsenter,
install.sh. See `TODO.md`.

---

## What to be careful about

- **Never put BGP peer IP in `user-vpn.list`.** Kills BGP session, drops ~27K routes.
- **`birdc configure` must succeed before `saveState`.** Don't persist broken config.
- **Atomic writes need same filesystem.** `os.CreateTemp(dir) + os.Rename`.
- **`go 1.25` uses `strings.SplitSeq`.** Don't downgrade module version.
- **`Server` HTTP header is cleared.** Don't re-set it in middleware.
