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
	// ReadIPSet returns the IPv4 members of a kernel ipset.
	// Returns nil, nil if the ipset does not exist or is empty.
	ReadIPSet(name string) ([]string, error)
}

// Resolver abstracts DNS and ASN lookups.
type Resolver interface {
	LookupHost(host string) ([]string, error)
	LookupASN(asn string) ([]string, error)
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

	// DNSMasqIPSet is the name of a kernel ipset populated by dnsmasq for
	// TLD-based ISP routing (e.g. all .ru domains). If empty, the feature is
	// disabled. When set, bird-route-manager reads the ipset on every apply/refresh
	// and writes a separate BIRD2 route file (dnsmasq-isp.list) with preference 150.
	DNSMasqIPSet string
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
		MaxBodyBytes:    64 * 1024,
		DNSMasqIPSet:    os.Getenv("DNSMASQ_IPSET"),
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

// ReadIPSet dumps a kernel ipset and returns its IPv4 members as /32 CIDRs.
// Uses `ipset list <name> -output save` which outputs lines like:
//
//	add <name> <ip> timeout <n>
//
// Returns nil, nil if the ipset does not exist.
func (systemExecutor) ReadIPSet(name string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ipset", "list", name, "-output", "save").Output()
	if err != nil {
		// ipset exits non-zero if the set doesn't exist — treat as empty
		return nil, nil
	}
	return parseIPSetSave(string(out)), nil
}

// parseIPSetSave extracts IPv4 addresses from `ipset list -output save` output.
func parseIPSetSave(output string) []string {
	var ips []string
	seen := make(map[string]struct{})
	for line := range strings.SplitSeq(output, "\n") {
		// Lines look like: "add setname 1.2.3.4 timeout 12345"
		// or without timeout: "add setname 1.2.3.4"
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "add" {
			continue
		}
		ip := fields[2]
		if net.ParseIP(ip) == nil || net.ParseIP(ip).To4() == nil {
			continue
		}
		cidr := ip + "/32"
		if _, dup := seen[cidr]; !dup {
			seen[cidr] = struct{}{}
			ips = append(ips, cidr)
		}
	}
	return ips
}

// ── State ─────────────────────────────────────────────────────────────────────

// State holds the raw (pre-resolution) entry lists and is persisted to disk.
// Resolution happens fresh each time so DNS changes are picked up on refresh.
type State struct {
	VPN       []string  `json:"vpn"`
	ISP       []string  `json:"isp"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ── Manager ───────────────────────────────────────────────────────────────────

// Manager owns the state and coordinates resolution, file writing, and reload.
type Manager struct {
	cfg  Config
	exec Executor
	res  Resolver

	mu    sync.Mutex
	state State
}

func NewManager(cfg Config, exec Executor, res Resolver) *Manager {
	return &Manager{cfg: cfg, exec: exec, res: res}
}

func (m *Manager) vpnListPath() string       { return filepath.Join(m.cfg.WorkDir, "user-vpn.list") }
func (m *Manager) ispListPath() string       { return filepath.Join(m.cfg.WorkDir, "user-isp.list") }
func (m *Manager) dnsmasqIspListPath() string { return filepath.Join(m.cfg.WorkDir, "dnsmasq-isp.list") }
func (m *Manager) statePath() string          { return filepath.Join(m.cfg.WorkDir, "state.json") }

// vpnNexthop returns the BIRD2 nexthop string for the VPN interface.
// BIRD2 uses a quoted string to mean "resolve via this interface".
func (m *Manager) vpnNexthop() string { return fmt.Sprintf("%q", m.cfg.VPNInterface) }

// EnsureFiles creates empty list files if they do not exist, so BIRD2's
// `include` directive never fails on a fresh install.
func (m *Manager) EnsureFiles() error {
	paths := []string{m.vpnListPath(), m.ispListPath()}
	if m.cfg.DNSMasqIPSet != "" {
		paths = append(paths, m.dnsmasqIspListPath())
	}
	for _, p := range paths {
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

	m.state = State{VPN: vpn, ISP: isp}
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
	_, _, err := m.applyLocked(vpn, isp)
	m.mu.Unlock()
	return err
}

// loadIPCheckSites reads WorkDir/ip-check-sites.list and returns the domain list.
// Lines starting with # and blank lines are ignored. Returns nil if the file
// does not exist.
func loadIPCheckSites(workDir string) []string {
	data, err := os.ReadFile(filepath.Join(workDir, "ip-check-sites.list"))
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("warn: read ip-check-sites.list: %v", err)
		}
		return nil
	}
	var out []string
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// applyLocked resolves, writes, and reloads. Caller must hold m.mu.
func (m *Manager) applyLocked(vpn, isp []string) (vpnCIDRs, ispCIDRs []string, err error) {
	gw, err := m.exec.DefaultGW()
	if err != nil {
		return nil, nil, fmt.Errorf("default gateway: %w", err)
	}

	ispEntries := isp
	if sites := loadIPCheckSites(m.cfg.WorkDir); len(sites) > 0 {
		ispEntries = append(append([]string(nil), isp...), sites...)
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

	// dnsmasq ipset layer: read kernel ipset and write a separate route file.
	// This runs on every apply/refresh so the route file tracks ipset changes.
	if m.cfg.DNSMasqIPSet != "" {
		dnsmasqCIDRs, readErr := m.exec.ReadIPSet(m.cfg.DNSMasqIPSet)
		if readErr != nil {
			log.Printf("warn: read ipset %s: %v", m.cfg.DNSMasqIPSet, readErr)
		}
		if writeErr := atomicWrite(m.dnsmasqIspListPath(), routeFileContent(dnsmasqCIDRs, gw)); writeErr != nil {
			return nil, nil, fmt.Errorf("write dnsmasq isp list: %w", writeErr)
		}
		log.Printf("dnsmasq ipset: %d IPs from %s", len(dnsmasqCIDRs), m.cfg.DNSMasqIPSet)
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

const apiPath = "/api/v1/routes"

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

// readAllLimited reads up to max bytes from r.Body.
func readAllLimited(r io.Reader, max int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, max))
}

// NewHandler returns an http.Handler for all API endpoints.
// If fvpnMgr is nil, the fullvpn endpoints are disabled.
func NewHandler(cfg Config, mgr *Manager, fvpnMgr *FullVPNManager) http.Handler {
	rl := newRateLimiter(cfg.RateLimitMax)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case apiPath:
			// Routes endpoint
			body := verifyAndReadBody(cfg, rl, w, r)
			if body == nil {
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

		case fullvpnPath:
			if fvpnMgr == nil {
				errResp(w, http.StatusNotFound, "not found")
				return
			}
			body := verifyAndReadBody(cfg, rl, w, r)
			if body == nil {
				return
			}
			fvpnMgr.HandleFullVPN(cfg, w, r, body)

		case peersPath:
			if fvpnMgr == nil {
				errResp(w, http.StatusNotFound, "not found")
				return
			}
			body := verifyAndReadBody(cfg, rl, w, r)
			if body == nil {
				return
			}
			fvpnMgr.HandlePeers(cfg, w, r, body)

		default:
			errResp(w, http.StatusNotFound, "not found")
		}
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

	sysExec := systemExecutor{}
	res := newNetResolver()
	mgr := NewManager(cfg, sysExec, res)

	if err := mgr.EnsureFiles(); err != nil {
		log.Fatalf("ensure files: %v", err)
	}

	// BGP Hub — generate downstream peer config before LoadState (which
	// calls birdc configure). This ensures bgphub-peers.conf is ready
	// for the first BIRD2 reload.
	bgpHubCfg := bgphubConfigFromEnv(cfg.WorkDir)
	if bgpHubCfg.Enabled {
		if err := EnsureBGPHubConf(bgpHubCfg, sysExec.BirdConfigure); err != nil {
			log.Printf("bgphub: warning: %v", err)
		}
	}

	mgr.LoadState()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	mgr.StartRefresher(ctx)

	// Full-VPN per-peer override (optional)
	var fvpnMgr *FullVPNManager
	fvpnCfg := fullvpnConfigFromEnv(cfg.WorkDir, cfg.VPNInterface)
	if fvpnCfg.Enabled {
		fvpnMgr = NewFullVPNManager(fvpnCfg, systemFullVPNExecutor{})
		fvpnMgr.LoadPeers()
		if err := fvpnMgr.Setup(); err != nil {
			log.Printf("fullvpn: route setup warning: %v", err)
		}
		fvpnMgr.LoadState()
		fvpnMgr.StartCleanupTicker(ctx)
		log.Printf("fullvpn: enabled (container=%s, duration=%v, cleanup=%v)",
			fvpnCfg.ContainerName, fvpnCfg.OverrideDuration, fvpnCfg.CleanupInterval)
	}

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      NewHandler(cfg, mgr, fvpnMgr),
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
	if cfg.DNSMasqIPSet != "" {
		log.Printf("dnsmasq ipset layer enabled: reading from ipset %q", cfg.DNSMasqIPSet)
	}
	log.Printf("listening on %s (work dir: %s, vpn interface: %s, refresh: %v)",
		cfg.ListenAddr, cfg.WorkDir, cfg.VPNInterface, cfg.RefreshInterval)

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("listen: %v", err)
	}
	log.Println("stopped")
}
