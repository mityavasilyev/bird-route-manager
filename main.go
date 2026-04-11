// bird-route-manager — self-managing BIRD2 split-routing for Linux VPS.
//
// Accepts lists of IPs, CIDRs, domains, and ASNs via a signed HTTP API,
// resolves them, writes BIRD2 static route include files, and reloads BIRD2.
// Persists raw entry lists so routes survive restarts and are re-resolved
// periodically without any external push.
//
// All system paths live under WorkDir (/opt/bird-route-manager by default).
// The only files touched outside WorkDir are the BIRD2 config include added
// by setup.sh and the systemd unit.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ── Interfaces ────────────────────────────────────────────────────────────────

// Executor abstracts system-level commands so tests can inject fakes.
type Executor interface {
	DefaultGW() (string, error)
	BirdConfigure() error
}

// Resolver abstracts DNS and ASN lookups.
type Resolver interface {
	LookupHost(host string) ([]string, error)
	LookupASN(asn string) ([]string, error)
}

// Checker detects the VPN exit IP by probing external IP-echo services
// through the VPN interface. The interface exists so tests can inject a fake.
type Checker interface {
	DetectExitIP(ctx context.Context, iface string) (string, error)
}

// ── VPN IP checker ────────────────────────────────────────────────────────────

// probeCheckDomains are the IP-echo service domains used by the VPN exit IP checker.
// When VPN IP check is enabled, these are auto-added to the ISP route list so they
// are always reachable via ISP (not VPN), preventing detection loops.
var probeCheckDomains = []string{
	"icanhazip.com",
	"api.ipify.org",
	"checkip.amazonaws.com",
	"ident.me",
	"ipecho.net",
	"ip.sb",
	"ip4.seeip.org",
	"myexternalip.com",
	"ifconfig.me",
}

// probeCheckURLs are the HTTP endpoints queried to detect the VPN exit IP.
// Each returns a bare IPv4 address as plain text. Tried in order; first success wins.
var probeCheckURLs = []string{
	"https://icanhazip.com",
	"https://api.ipify.org",
	"https://checkip.amazonaws.com",
	"https://ident.me",
	"https://ipecho.net/plain",
	"https://ip.sb",
	"https://ip4.seeip.org",
	"https://myexternalip.com/raw",
	"https://ifconfig.me/ip",
}

type netChecker struct{}

// bindToDevice returns a Control func that pins a TCP socket to iface via
// SO_BINDTODEVICE (Linux constant 25). This overrides the routing table,
// forcing the connection out that interface regardless of the kernel's routing
// decision for the destination. On non-Linux platforms the setsockopt call
// returns an error and the probe is skipped.
func bindToDevice(iface string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var innerErr error
		if err := c.Control(func(fd uintptr) {
			innerErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, 25 /*SO_BINDTODEVICE*/, iface)
		}); err != nil {
			return err
		}
		return innerErr
	}
}

func (netChecker) DetectExitIP(ctx context.Context, iface string) (string, error) {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: bindToDevice(iface),
	}
	client := &http.Client{
		Transport: &http.Transport{DialContext: dialer.DialContext},
		Timeout:   5 * time.Second,
	}

	var lastErr error
	for _, u := range probeCheckURLs {
		reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u, nil)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		resp, err := client.Do(req)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("%s: read: %w", u, err)
			continue
		}
		ip := strings.TrimSpace(string(body))
		if net.ParseIP(ip) != nil {
			return ip, nil
		}
		lastErr = fmt.Errorf("%s: unexpected body %q", u, ip)
	}
	if lastErr != nil {
		return "", fmt.Errorf("all probes failed: %w", lastErr)
	}
	return "", errors.New("no probes configured")
}

// ── Config ────────────────────────────────────────────────────────────────────

// Config is populated from environment variables.
type Config struct {
	// WorkDir is the single directory where all bird-route-manager state lives.
	// Default: /opt/bird-route-manager
	WorkDir string

	// ListenAddr is the HTTP listen address (proxied by nginx for TLS).
	ListenAddr string

	// Token is the HMAC-SHA256 secret for the push API.
	// If empty, the API returns 503 Service Unavailable on all requests.
	Token string

	// VPNInterface is the kernel interface name used as BIRD2 nexthop for VPN routes.
	// e.g. "wg0", "tun0", "vpn0"
	VPNInterface string

	// RefreshInterval is how often the background goroutine re-resolves and re-applies
	// the current entry lists (picks up DNS changes, rotated IPs, etc).
	RefreshInterval time.Duration

	// TimestampWindow is the maximum clock skew accepted for HMAC timestamps.
	TimestampWindow time.Duration

	// RateLimitMax is the maximum number of API requests per 60-second window.
	RateLimitMax int

	// MaxBodyBytes is the hard cap on request body size.
	MaxBodyBytes int64

	// VPNIPCheckEnabled enables periodic detection of the VPN exit IP via IP-echo
	// services. When enabled, probe domains are auto-added to the ISP route list.
	VPNIPCheckEnabled bool

	// VPNIPCheckInterval is how often the VPN exit IP is re-detected.
	VPNIPCheckInterval time.Duration
}

func configFromEnv() Config {
	return Config{
		WorkDir:         envOr("WORK_DIR", "/opt/bird-route-manager"),
		ListenAddr:      envOr("LISTEN_ADDR", "127.0.0.1:8081"),
		Token:           os.Getenv("SYNC_TOKEN"),
		VPNInterface:    envOr("VPN_INTERFACE", "wg0"),
		RefreshInterval: time.Duration(envOrInt("REFRESH_HOURS", 6)) * time.Hour,
		TimestampWindow: time.Duration(envOrInt("TIMESTAMP_WINDOW", 300)) * time.Second,
		RateLimitMax:    envOrInt("RATE_LIMIT_MAX", 5),
		MaxBodyBytes:       64 * 1024,
		VPNIPCheckEnabled:  os.Getenv("VPN_IP_CHECK_ENABLED") == "true",
		VPNIPCheckInterval: time.Duration(envOrInt("VPN_IP_CHECK_INTERVAL_HOURS", 6)) * time.Hour,
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envOrInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// ── Entry classification ──────────────────────────────────────────────────────

type entryKind int

const (
	kindUnknown entryKind = iota
	kindCIDR
	kindDomain
	kindASN
)

var (
	reCIDR   = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$`)
	reASN    = regexp.MustCompile(`(?i)^AS\d{1,10}$`)
	reDomain = regexp.MustCompile(`(?i)^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
)

func classify(s string) entryKind {
	switch {
	case reCIDR.MatchString(s):
		if strings.Contains(s, "/") {
			if _, _, err := net.ParseCIDR(s); err != nil {
				return kindUnknown
			}
		} else if net.ParseIP(s) == nil {
			return kindUnknown
		}
		return kindCIDR
	case reASN.MatchString(s):
		return kindASN
	case reDomain.MatchString(s):
		return kindDomain
	}
	return kindUnknown
}

// cleanEntries strips comments, blanks, and invalid entries; deduplicates.
func cleanEntries(raw []string) []string {
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if classify(s) == kindUnknown {
			log.Printf("warn: dropping invalid entry %q", s)
			continue
		}
		if _, dup := seen[s]; !dup {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// normalizeCIDR converts a bare IP to /32 and normalises the network bits.
func normalizeCIDR(s string) string {
	if !strings.Contains(s, "/") {
		return s + "/32"
	}
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		return s
	}
	return n.String()
}

// ── Real resolver ─────────────────────────────────────────────────────────────

type netResolver struct {
	httpClient *http.Client
}

func newNetResolver() *netResolver {
	return &netResolver{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (r *netResolver) LookupHost(host string) ([]string, error) {
	addrs, err := net.LookupHost(host)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range addrs {
		if net.ParseIP(a).To4() != nil { // IPv4 only
			out = append(out, a)
		}
	}
	return out, nil
}

type ripeResp struct {
	Data struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	} `json:"data"`
}

func (r *netResolver) LookupASN(asn string) ([]string, error) {
	url := "https://stat.ripe.net/data/announced-prefixes/data.json?resource=" + strings.ToUpper(asn)
	resp, err := r.httpClient.Get(url) //nolint:noctx
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data ripeResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&data); err != nil {
		return nil, err
	}
	var out []string
	for _, p := range data.Data.Prefixes {
		if strings.Contains(p.Prefix, ".") { // IPv4 only
			if _, _, err := net.ParseCIDR(p.Prefix); err == nil {
				out = append(out, p.Prefix)
			}
		}
	}
	return out, nil
}

// ── Resolution ────────────────────────────────────────────────────────────────

// resolveEntries converts a mixed list of CIDRs/domains/ASNs into a
// deduplicated, normalised list of IPv4 CIDRs.
func resolveEntries(entries []string, res Resolver) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(cidrs ...string) {
		for _, c := range cidrs {
			if _, ok := seen[c]; !ok {
				seen[c] = struct{}{}
				out = append(out, c)
			}
		}
	}

	for _, e := range entries {
		switch classify(e) {
		case kindCIDR:
			add(normalizeCIDR(e))
		case kindDomain:
			ips, err := res.LookupHost(e)
			if err != nil {
				log.Printf("warn: lookup(%s): %v", e, err)
				continue
			}
			for _, ip := range ips {
				add(ip + "/32")
			}
		case kindASN:
			prefixes, err := res.LookupASN(e)
			if err != nil {
				log.Printf("warn: asn(%s): %v", e, err)
				continue
			}
			add(prefixes...)
		}
	}
	return out
}

// ── Route file writer ─────────────────────────────────────────────────────────

// routeFileContent renders a BIRD2 static include file.
// nexthop is either a quoted interface name ("wg-ch") or a bare IP (10.0.0.1).
func routeFileContent(cidrs []string, nexthop string) string {
	sorted := make([]string, len(cidrs))
	copy(sorted, cidrs)
	sort.Strings(sorted)

	var sb strings.Builder
	for _, c := range sorted {
		fmt.Fprintf(&sb, "route %s via %s;\n", c, nexthop)
	}
	return sb.String()
}

// atomicWrite writes content to path via a same-directory temp file + rename.
func atomicWrite(path, content string) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.WriteString(content)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		os.Remove(tmp)
		if werr != nil {
			return werr
		}
		return cerr
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// ── Real executor ─────────────────────────────────────────────────────────────

type systemExecutor struct{}

func (systemExecutor) DefaultGW() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ip", "route", "show", "default").Output()
	if err != nil {
		return "", err
	}
	for line := range strings.SplitSeq(string(out), "\n") {
		parts := strings.Fields(line)
		// "default via <GW> dev <iface> ..."
		if len(parts) >= 3 && parts[0] == "default" && parts[1] == "via" {
			return parts[2], nil
		}
	}
	return "", errors.New("no default gateway in routing table")
}

func (systemExecutor) BirdConfigure() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "birdc", "configure").CombinedOutput()
	if err != nil {
		return fmt.Errorf("birdc configure: %w — %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ── State ─────────────────────────────────────────────────────────────────────

// State holds the raw (pre-resolution) entry lists and is persisted to disk.
// Resolution happens fresh each time so DNS changes are picked up on refresh.
type State struct {
	VPN       []string  `json:"vpn"`
	ISP       []string  `json:"isp"`
	UpdatedAt time.Time `json:"updated_at"`

	VPNExitIP    string `json:"vpn_exit_ip,omitempty"`    // detected VPN exit IP
	VPNExitIPAt  string `json:"vpn_exit_ip_at,omitempty"` // RFC3339 timestamp of last detection
	VPNRouteCount int   `json:"vpn_route_count,omitempty"`
	ISPRouteCount int   `json:"isp_route_count,omitempty"`
}

// ── Manager ───────────────────────────────────────────────────────────────────

// Manager owns the state and coordinates resolution, file writing, and reload.
type Manager struct {
	cfg     Config
	exec    Executor
	res     Resolver
	checker Checker // nil when VPN IP check is disabled

	mu    sync.Mutex
	state State
}

func NewManager(cfg Config, exec Executor, res Resolver) *Manager {
	return &Manager{cfg: cfg, exec: exec, res: res}
}

func (m *Manager) vpnListPath() string { return filepath.Join(m.cfg.WorkDir, "user-vpn.list") }
func (m *Manager) ispListPath() string { return filepath.Join(m.cfg.WorkDir, "user-isp.list") }
func (m *Manager) statePath() string   { return filepath.Join(m.cfg.WorkDir, "state.json") }

// vpnNexthop returns the BIRD2 nexthop string for the VPN interface.
// BIRD2 uses a quoted string to mean "resolve via this interface".
func (m *Manager) vpnNexthop() string { return fmt.Sprintf("%q", m.cfg.VPNInterface) }

// EnsureFiles creates empty list files if they do not exist, so BIRD2's
// `include` directive never fails on a fresh install.
func (m *Manager) EnsureFiles() error {
	for _, p := range []string{m.vpnListPath(), m.ispListPath()} {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			if err := atomicWrite(p, ""); err != nil {
				return fmt.Errorf("create %s: %w", p, err)
			}
			log.Printf("created empty %s", p)
		}
	}
	return nil
}

// LoadState reads persisted state from disk and applies it.
// Called once at startup. Non-fatal if state file doesn't exist yet.
func (m *Manager) LoadState() {
	f, err := os.Open(m.statePath())
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("warn: load state: %v", err)
		}
		return
	}
	defer f.Close()

	var s State
	if err := json.NewDecoder(f).Decode(&s); err != nil {
		log.Printf("warn: decode state: %v", err)
		return
	}

	m.mu.Lock()
	m.state = s
	m.mu.Unlock()

	log.Printf("startup: loaded state (%d vpn, %d isp entries), applying...", len(s.VPN), len(s.ISP))
	if err := m.apply(s.VPN, s.ISP); err != nil {
		log.Printf("startup apply error: %v", err)
	}
}

// Update validates, saves, and applies a new set of entry lists.
// Returns resolved route counts.
func (m *Manager) Update(vpn, isp []string) (vpnRoutes, ispRoutes int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	vpnCIDRs, ispCIDRs, applyErr := m.applyLocked(vpn, isp)
	if applyErr != nil {
		return 0, 0, applyErr
	}

	m.state = State{
		VPN:           vpn,
		ISP:           isp,
		VPNExitIP:     m.state.VPNExitIP,    // preserve detected exit IP across pushes
		VPNExitIPAt:   m.state.VPNExitIPAt,
		VPNRouteCount: len(vpnCIDRs),
		ISPRouteCount: len(ispCIDRs),
	}
	if saveErr := m.saveStateLocked(); saveErr != nil {
		// Non-fatal: routes are applied, but we log the persistence failure.
		log.Printf("warn: save state: %v", saveErr)
	}

	return len(vpnCIDRs), len(ispCIDRs), nil
}

// Refresh re-resolves the current entry lists and reloads BIRD2.
// Intended to be called periodically from a goroutine.
func (m *Manager) Refresh() {
	m.mu.Lock()
	vpn := m.state.VPN
	isp := m.state.ISP
	m.mu.Unlock()

	if len(vpn) == 0 && len(isp) == 0 {
		log.Println("refresh: no entries in state, skipping")
		return
	}

	log.Printf("refresh: re-resolving %d vpn + %d isp entries", len(vpn), len(isp))
	if err := m.apply(vpn, isp); err != nil {
		log.Printf("refresh error: %v", err)
	}
}

// apply resolves entries, writes files, and reloads BIRD2 (no lock held).
func (m *Manager) apply(vpn, isp []string) error {
	m.mu.Lock()
	vpnCIDRs, ispCIDRs, err := m.applyLocked(vpn, isp)
	if err == nil {
		m.state.VPNRouteCount = len(vpnCIDRs)
		m.state.ISPRouteCount = len(ispCIDRs)
	}
	m.mu.Unlock()
	return err
}

// applyLocked resolves, writes, and reloads. Caller must hold m.mu.
func (m *Manager) applyLocked(vpn, isp []string) (vpnCIDRs, ispCIDRs []string, err error) {
	gw, err := m.exec.DefaultGW()
	if err != nil {
		return nil, nil, fmt.Errorf("default gateway: %w", err)
	}

	ispEntries := isp
	if m.cfg.VPNIPCheckEnabled {
		// Probe domains are appended to ISP entries so their IPs are always routed
		// via ISP. SO_BINDTODEVICE in the checker overrides this for detection requests.
		ispEntries = append(append([]string(nil), isp...), probeCheckDomains...)
	}

	log.Printf("resolving %d vpn + %d isp entries", len(vpn), len(isp))
	vpnCIDRs = resolveEntries(vpn, m.res)
	ispCIDRs = resolveEntries(ispEntries, m.res)

	if err := atomicWrite(m.vpnListPath(), routeFileContent(vpnCIDRs, m.vpnNexthop())); err != nil {
		return nil, nil, fmt.Errorf("write vpn list: %w", err)
	}
	if err := atomicWrite(m.ispListPath(), routeFileContent(ispCIDRs, gw)); err != nil {
		return nil, nil, fmt.Errorf("write isp list: %w", err)
	}

	if err := m.exec.BirdConfigure(); err != nil {
		return nil, nil, err
	}

	log.Printf("applied: %d vpn routes, %d isp routes", len(vpnCIDRs), len(ispCIDRs))
	return vpnCIDRs, ispCIDRs, nil
}

func (m *Manager) saveStateLocked() error {
	s := m.state
	s.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(m.statePath(), string(data)+"\n")
}

// StartRefresher starts the periodic re-resolution goroutine.
func (m *Manager) StartRefresher(ctx context.Context) {
	if m.cfg.RefreshInterval <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(m.cfg.RefreshInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.Refresh()
			}
		}
	}()
}

// runVPNIPCheck probes an IP-echo service through the VPN interface and
// stores the detected exit IP in state.
func (m *Manager) runVPNIPCheck(ctx context.Context) {
	ip, err := m.checker.DetectExitIP(ctx, m.cfg.VPNInterface)
	if err != nil {
		log.Printf("vpn ip check: %v", err)
		return
	}
	m.mu.Lock()
	m.state.VPNExitIP = ip
	m.state.VPNExitIPAt = time.Now().UTC().Format(time.RFC3339)
	saveErr := m.saveStateLocked()
	m.mu.Unlock()
	if saveErr != nil {
		log.Printf("warn: save state after vpn ip check: %v", saveErr)
	}
	log.Printf("vpn exit ip: %s", ip)
}

// StartVPNIPChecker starts the periodic VPN exit IP detection goroutine.
func (m *Manager) StartVPNIPChecker(ctx context.Context) {
	if m.checker == nil || m.cfg.VPNIPCheckInterval <= 0 {
		return
	}
	go func() {
		m.runVPNIPCheck(ctx)
		t := time.NewTicker(m.cfg.VPNIPCheckInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.runVPNIPCheck(ctx)
			}
		}
	}()
}

// ── Rate limiter ──────────────────────────────────────────────────────────────

type rateLimiter struct {
	mu   sync.Mutex
	hits []time.Time
	max  int
}

func newRateLimiter(max int) *rateLimiter { return &rateLimiter{max: max} }

func (r *rateLimiter) Allow() bool {
	now := time.Now()
	cutoff := now.Add(-60 * time.Second)
	r.mu.Lock()
	defer r.mu.Unlock()
	j := 0
	for _, t := range r.hits {
		if t.After(cutoff) {
			r.hits[j] = t
			j++
		}
	}
	r.hits = r.hits[:j]
	if len(r.hits) >= r.max {
		return false
	}
	r.hits = append(r.hits, now)
	return true
}

// ── HMAC auth ─────────────────────────────────────────────────────────────────

// verifyHMAC checks Authorization: Bearer <hex> and X-Timestamp: <unix>.
// Signed message: "<timestamp>:" + raw body bytes.
func verifyHMAC(token, bearer, tsStr string, body []byte) bool {
	ts, err := strconv.ParseInt(strings.TrimSpace(tsStr), 10, 64)
	if err != nil {
		return false
	}
	diff := time.Since(time.Unix(ts, 0))
	if diff < 0 {
		diff = -diff
	}
	// window check is done by caller using cfg.TimestampWindow
	_ = diff

	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(tsStr))
	mac.Write([]byte(":"))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(bearer))
}

func tsInWindow(tsStr string, window time.Duration) bool {
	ts, err := strconv.ParseInt(strings.TrimSpace(tsStr), 10, 64)
	if err != nil {
		return false
	}
	diff := time.Since(time.Unix(ts, 0))
	if diff < 0 {
		diff = -diff
	}
	return diff <= window
}

// ── HTTP handler ──────────────────────────────────────────────────────────────

const (
	apiPath    = "/api/v1/routes"
	statusPath = "/api/v1/status"
)

type statusResponse struct {
	VPNExitIP   string `json:"vpn_exit_ip,omitempty"`
	VPNExitIPAt string `json:"vpn_exit_ip_at,omitempty"`
	VPNRoutes   int    `json:"vpn_routes"`
	ISPRoutes   int    `json:"isp_routes"`
}

type pushPayload struct {
	VPN []string `json:"vpn"`
	ISP []string `json:"isp"`
}

type pushResponse struct {
	OK        bool `json:"ok"`
	VPNRoutes int  `json:"vpn_routes"`
	ISPRoutes int  `json:"isp_routes"`
}

func jsonResp(w http.ResponseWriter, code int, v any) {
	data, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Server", "") // don't reveal implementation
	w.WriteHeader(code)
	w.Write(data) //nolint:errcheck
}

func errResp(w http.ResponseWriter, code int, msg string) {
	jsonResp(w, code, map[string]string{"error": msg})
}

// NewHandler returns an http.Handler for the push API.
func NewHandler(cfg Config, mgr *Manager) http.Handler {
	rl := newRateLimiter(cfg.RateLimitMax)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == statusPath && r.Method == http.MethodGet {
			mgr.mu.Lock()
			s := mgr.state
			mgr.mu.Unlock()
			jsonResp(w, http.StatusOK, statusResponse{
				VPNExitIP:   s.VPNExitIP,
				VPNExitIPAt: s.VPNExitIPAt,
				VPNRoutes:   s.VPNRouteCount,
				ISPRoutes:   s.ISPRouteCount,
			})
			return
		}

		if r.URL.Path != apiPath || r.Method != http.MethodPost {
			errResp(w, http.StatusNotFound, "not found")
			return
		}

		// API disabled
		if cfg.Token == "" {
			errResp(w, http.StatusServiceUnavailable, "api not enabled")
			return
		}

		if !rl.Allow() {
			errResp(w, http.StatusTooManyRequests, "too many requests")
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, cfg.MaxBodyBytes+1))
		if err != nil {
			errResp(w, http.StatusBadRequest, "bad request")
			return
		}
		if int64(len(body)) > cfg.MaxBodyBytes {
			errResp(w, http.StatusRequestEntityTooLarge, "payload too large")
			return
		}

		if !strings.Contains(r.Header.Get("Content-Type"), "application/json") {
			errResp(w, http.StatusUnsupportedMediaType, "unsupported media type")
			return
		}

		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			errResp(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		bearer := strings.TrimPrefix(auth, "Bearer ")
		tsStr := r.Header.Get("X-Timestamp")

		if !tsInWindow(tsStr, cfg.TimestampWindow) {
			errResp(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if !verifyHMAC(cfg.Token, bearer, tsStr, body) {
			errResp(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		var p pushPayload
		if err := json.Unmarshal(body, &p); err != nil {
			errResp(w, http.StatusBadRequest, "bad request")
			return
		}
		vpn := cleanEntries(p.VPN)
		isp := cleanEntries(p.ISP)

		vpnN, ispN, err := mgr.Update(vpn, isp)
		if err != nil {
			log.Printf("update error: %v", err)
			errResp(w, http.StatusInternalServerError, "internal error")
			return
		}

		jsonResp(w, http.StatusOK, pushResponse{OK: true, VPNRoutes: vpnN, ISPRoutes: ispN})
	})
}

// ── Entry point ───────────────────────────────────────────────────────────────

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmsgprefix)
	log.SetPrefix("bird-route-manager ")

	cfg := configFromEnv()

	if err := os.MkdirAll(cfg.WorkDir, 0o755); err != nil {
		log.Fatalf("create work dir: %v", err)
	}

	exec := systemExecutor{}
	res := newNetResolver()
	mgr := NewManager(cfg, exec, res)
	if cfg.VPNIPCheckEnabled {
		mgr.checker = netChecker{}
		log.Printf("vpn ip check enabled (interval: %v, %d probe urls)", cfg.VPNIPCheckInterval, len(probeCheckURLs))
	}

	if err := mgr.EnsureFiles(); err != nil {
		log.Fatalf("ensure files: %v", err)
	}
	mgr.LoadState()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	mgr.StartRefresher(ctx)
	mgr.StartVPNIPChecker(ctx)

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      NewHandler(cfg, mgr),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 180 * time.Second, // long: resolution can take time
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutCancel()
		srv.Shutdown(shutCtx) //nolint:errcheck
	}()

	if cfg.Token == "" {
		log.Println("SYNC_TOKEN not set — push API disabled (run setup.sh to enable)")
	}
	log.Printf("listening on %s (work dir: %s, vpn interface: %s, refresh: %v)",
		cfg.ListenAddr, cfg.WorkDir, cfg.VPNInterface, cfg.RefreshInterval)

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("listen: %v", err)
	}
	log.Println("stopped")
}
