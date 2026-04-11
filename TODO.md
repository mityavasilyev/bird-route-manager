# TODO — things not yet verified on real hardware

The unit and e2e tests cover application logic with fakes for all system calls.
The items below require a real Linux VPS with BIRD2 and a tunnel interface.

---

## Known issues found during real deployment (fixed)

- **WorkDir must be mode 755, not 750.** BIRD2 runs as user `bird` and needs to
  traverse `/opt/bird-route-manager/` to read the `include` files. install.sh was
  setting 750 (no world-execute). Fixed. The `env` file inside the directory
  remains 600 (token-safe).

---

## Verified on Kemerovo VPS (migration from route-sync, Apr 2026)

Note: this was a **migration**, not a fresh install via `install.sh`. The items
below were exercised manually but confirm the service and BIRD2 integration work.

- [x] Service starts and owns port 8081
- [x] `birdc show protocols` shows `user_vpn` and `user_isp` as `up`
- [x] Push API returns `{"ok":true,"vpn_routes":N,"isp_routes":M}`
- [x] `birdc configure` is called on push (confirmed via logs)
- [x] `state.json` is created after first push
- [x] Pushed CIDRs appear in `ip route show` via `wg-ch`
- [x] VPN-routed IP confirmed: `104.16.123.33 dev wg-ch src 10.8.1.18`
- [x] Antifilter BGP stays `Established` through the migration (16 038 routes intact)
- [x] `ProtectSystem=strict` works correctly with `ReadWritePaths` set
- [x] Wrong token → 401 (verified in unit tests; auth path unchanged from route-sync)

---

## Still needs verification

### install.sh — verified on Kemerovo VPS (re-install path, Apr 2026)

- [x] Runs to completion on a VPS with existing BIRD2 config
- [x] Go installation step works (`dl.google.com` tarball, `/usr/local/go`) — installed Go 1.24.2, picked up existing Go 1.25.0
- [x] `go build` succeeds on the VPS after Go is installed
- [x] `bird2` apt install path works (already installed; skipped correctly)
- [x] Updated `bird.conf` managed section results in a working BGP session
- [x] Re-run is idempotent — prompts for each value, only changes what is confirmed
- [ ] Token change path: re-run → change token → old token rejected, new accepted (not yet tested)
- [ ] Runs to completion on a truly fresh Ubuntu 22.04/24.04 VPS with no prior config

### BIRD2 integration
- [ ] Empty push clears routes from kernel (`ip route show` confirms removal)
- [ ] BIRD2 survives `birdc configure` under active BGP load (no session drop)

### Actual routing
- [ ] A pushed **domain** resolves and the `/32` routes appear in `ip route show`
- [ ] An ISP-list entry routes via the **default gateway**, not the VPN interface
- [ ] Traffic to an ISP-list IP exits via ISP even if antifilter BGP would route it via VPN

### Persistence and refresh
- [ ] After `systemctl restart bird-route-manager`, routes are re-applied without a push
- [ ] After `REFRESH_HOURS` elapses, routes are re-resolved and files rewritten
- [ ] A domain whose IP changes between pushes gets the new IP after refresh

### API via nginx
- [ ] nginx proxy forwards to 127.0.0.1:8081 correctly
- [ ] TLS termination works (HTTPS endpoint reachable from outside)
- [ ] Rate limit (nginx `limit_req` + service-level) rejects excess requests

### Systemd
- [ ] Service restarts automatically after a crash (`Restart=on-failure`)
- [ ] Service starts correctly on boot after a full reboot (after `bird.service` is up)

### Edge cases
- [ ] RIPE Stat API timeout: ASN entry is skipped gracefully, rest of push succeeds
- [ ] DNS failure for one domain: skipped, others apply
- [ ] VPN interface in config doesn't exist: `birdc configure` fails, error is logged clearly

---

## Smoke-test sequence (run on a fresh VPS after install.sh)

```bash
# 1. Service is up
systemctl is-active bird-route-manager

# 2. Protocols visible in BIRD2
birdc show protocols | grep -E "user_vpn|user_isp|antifilter"

# 3. Push a test entry
TOKEN=$(grep SYNC_TOKEN /opt/bird-route-manager/env | cut -d= -f2)
BODY='{"vpn":["198.51.100.0/24","example.com"],"isp":["192.0.2.0/24"]}'
TS=$(date +%s)
SIG=$(python3 - "$TS" <<PYEOF
import hmac, hashlib, sys, os
key = os.environ["TOKEN"].encode()
ts  = sys.argv[1].encode()
body = os.environ["BODY"].encode()
print(hmac.new(key, ts + b":" + body, hashlib.sha256).hexdigest())
PYEOF
)
curl -sf -X POST http://127.0.0.1:8081/api/v1/routes \
  -H "Authorization: Bearer $SIG" \
  -H "X-Timestamp: $TS" \
  -H "Content-Type: application/json" \
  -d "$BODY" TOKEN="$TOKEN" BODY="$BODY"

# 4. Verify routes in kernel
ip route show 198.51.100.0/24   # → via VPN interface
ip route show 192.0.2.0/24      # → via default gateway (ISP)
# example.com should also appear as /32 routes via VPN interface

# 5. Verify route count
birdc show route count

# 6. Simulate restart — routes must survive without a new push
systemctl restart bird-route-manager
sleep 2
ip route show 198.51.100.0/24   # must still be there

# 7. Clear routes
BODY='{"vpn":[],"isp":[]}'
# re-sign and re-send (same pattern as step 3)
ip route show 198.51.100.0/24   # must be gone
```
