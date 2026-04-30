package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── Fakes ─────────────────────────────────────────────────────────────────────

type fakeExecutor struct {
	mu           sync.Mutex
	gw           string
	gwErr        error
	configureErr error
	configureCnt int
	ipsetIPs     []string // IPs returned by ReadIPSet
	ipsetErr     error
}

func (f *fakeExecutor) DefaultGW() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.gwErr != nil {
		return "", f.gwErr
	}
	if f.gw == "" {
		return "10.0.0.1", nil
	}
	return f.gw, nil
}

func (f *fakeExecutor) BirdConfigure() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.configureCnt++
	return f.configureErr
}

func (f *fakeExecutor) ConfigureCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.configureCnt
}

func (f *fakeExecutor) ReadIPSet(name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ipsetErr != nil {
		return nil, f.ipsetErr
	}
	return f.ipsetIPs, nil
}

type fakeResolver struct {
	mu      sync.Mutex
	domains map[string][]string
	asns    map[string][]string
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{
		domains: map[string][]string{
			"example.com":  {"93.184.216.34"},
			"multi.example": {"1.1.1.1", "2.2.2.2"},
		},
		asns: map[string][]string{
			"AS64496": {"192.0.2.0/24", "198.51.100.0/24"},
		},
	}
}

func (r *fakeResolver) LookupHost(host string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ips, ok := r.domains[host]
	if !ok {
		return nil, fmt.Errorf("lookup %s: no such host", host)
	}
	return ips, nil
}

func (r *fakeResolver) LookupASN(asn string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pfx, ok := r.asns[strings.ToUpper(asn)]
	if !ok {
		return nil, fmt.Errorf("asn %s: not found", asn)
	}
	return pfx, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		WorkDir:         t.TempDir(),
		ListenAddr:      "127.0.0.1:0",
		Token:           "test-secret-token",
		VPNInterface:    "wg-test",
		RefreshInterval: 0, // disable auto-refresh in tests
		TimestampWindow: 5 * time.Minute,
		RateLimitMax:    5,
		MaxBodyBytes:    64 * 1024,
	}
}

func signRequest(t *testing.T, token string, body []byte) (bearer, tsStr string) {
	t.Helper()
	tsStr = strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(tsStr))
	mac.Write([]byte(":"))
	mac.Write(body)
	bearer = hex.EncodeToString(mac.Sum(nil))
	return
}

func doPost(t *testing.T, srv *httptest.Server, token string, payload any) *http.Response {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	bearer, ts := signRequest(t, token, body)
	req, err := http.NewRequest(http.MethodPost, srv.URL+apiPath, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("X-Timestamp", ts)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

// ── Classify tests ────────────────────────────────────────────────────────────

func TestClassify(t *testing.T) {
	cases := []struct {
		input string
		want  entryKind
	}{
		{"1.2.3.4", kindCIDR},
		{"1.2.3.4/24", kindCIDR},
		{"0.0.0.0/0", kindCIDR},
		{"255.255.255.255/32", kindCIDR},
		{"256.0.0.1", kindUnknown},
		{"1.2.3.4/33", kindUnknown},
		{"example.com", kindDomain},
		{"sub.example.co.uk", kindDomain},
		{"AS12345", kindASN},
		{"as64496", kindASN},
		{"AS0", kindASN},
		{"not-valid", kindUnknown},
		{"", kindUnknown},
		{"http://example.com", kindUnknown},
	}
	for _, tc := range cases {
		got := classify(tc.input)
		if got != tc.want {
			t.Errorf("classify(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

// ── Clean entries tests ───────────────────────────────────────────────────────

func TestCleanEntries(t *testing.T) {
	input := []string{
		"  1.2.3.4  ",       // bare IP, trimmed
		"# comment",         // stripped
		"",                  // blank
		"example.com",       // domain
		"example.com",       // duplicate
		"AS64496",           // ASN
		"10.0.0.0/8",        // CIDR
		"999.999.999.999",   // invalid
		"  ",                // blank after trim
	}
	got := cleanEntries(input)
	want := []string{"1.2.3.4", "example.com", "AS64496", "10.0.0.0/8"}
	if len(got) != len(want) {
		t.Fatalf("cleanEntries: got %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("cleanEntries[%d]: got %q, want %q", i, got[i], w)
		}
	}
}

// ── Normalize CIDR tests ──────────────────────────────────────────────────────

func TestNormalizeCIDR(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1.2.3.4", "1.2.3.4/32"},
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"10.1.2.3/8", "10.0.0.0/8"}, // host bits zeroed
	}
	for _, tc := range cases {
		got := normalizeCIDR(tc.in)
		if got != tc.want {
			t.Errorf("normalizeCIDR(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ── Route file content tests ──────────────────────────────────────────────────

func TestRouteFileContent(t *testing.T) {
	cidrs := []string{"10.0.0.0/8", "1.1.1.1/32", "172.16.0.0/12"}
	got := routeFileContent(cidrs, `"wg-ch"`)

	// Must be sorted
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d: %q", len(lines), got)
	}
	if lines[0] != `route 1.1.1.1/32 via "wg-ch";` {
		t.Errorf("line 0: %q", lines[0])
	}
	if lines[1] != `route 10.0.0.0/8 via "wg-ch";` {
		t.Errorf("line 1: %q", lines[1])
	}
	if lines[2] != `route 172.16.0.0/12 via "wg-ch";` {
		t.Errorf("line 2: %q", lines[2])
	}

	// Empty input = empty file (no trailing newline weirdness)
	empty := routeFileContent(nil, `"wg-ch"`)
	if empty != "" {
		t.Errorf("empty cidrs produced non-empty output: %q", empty)
	}
}

// ── HMAC auth tests ───────────────────────────────────────────────────────────

func TestVerifyHMAC(t *testing.T) {
	token := "supersecret"
	body := []byte(`{"vpn":[],"isp":[]}`)
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(ts))
	mac.Write([]byte(":"))
	mac.Write(body)
	bearer := hex.EncodeToString(mac.Sum(nil))

	if !verifyHMAC(token, bearer, ts, body) {
		t.Error("valid HMAC rejected")
	}
	if verifyHMAC(token, bearer+"x", ts, body) {
		t.Error("tampered HMAC accepted")
	}
	if verifyHMAC("wrong-token", bearer, ts, body) {
		t.Error("wrong token accepted")
	}
	if verifyHMAC(token, bearer, ts, append(body, '!')) {
		t.Error("tampered body accepted")
	}
}

func TestTsInWindow(t *testing.T) {
	window := 5 * time.Minute
	good := strconv.FormatInt(time.Now().Unix(), 10)
	if !tsInWindow(good, window) {
		t.Error("current timestamp rejected")
	}
	old := strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10)
	if tsInWindow(old, window) {
		t.Error("expired timestamp accepted")
	}
	if tsInWindow("not-a-number", window) {
		t.Error("non-numeric timestamp accepted")
	}
}

// ── Resolution tests ──────────────────────────────────────────────────────────

func TestResolveEntries(t *testing.T) {
	res := newFakeResolver()

	cidrs := resolveEntries([]string{
		"1.2.3.4",
		"10.0.0.0/8",
		"example.com",
		"AS64496",
		"invalid-entry!!",
	}, res)

	want := map[string]bool{
		"1.2.3.4/32":          true,
		"10.0.0.0/8":          true,
		"93.184.216.34/32":    true,
		"192.0.2.0/24":        true,
		"198.51.100.0/24":     true,
	}
	for _, c := range cidrs {
		if !want[c] {
			t.Errorf("unexpected CIDR %q in resolved output", c)
		}
		delete(want, c)
	}
	for missing := range want {
		t.Errorf("expected CIDR %q missing from resolved output", missing)
	}
}

func TestResolveDeduplicates(t *testing.T) {
	res := newFakeResolver()
	// Same CIDR via different entry forms
	got := resolveEntries([]string{"10.0.0.0/8", "10.0.0.0/8", "10.0.0.1"}, res)
	// 10.0.0.0/8 twice and 10.0.0.1/32 — should deduplicate the /8 and keep /32
	cidrs := make(map[string]int)
	for _, c := range got {
		cidrs[c]++
	}
	if cidrs["10.0.0.0/8"] != 1 {
		t.Errorf("10.0.0.0/8 appeared %d times, want 1", cidrs["10.0.0.0/8"])
	}
}

// ── Atomic write tests ────────────────────────────────────────────────────────

func TestAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.list")

	if err := atomicWrite(path, "hello\n"); err != nil {
		t.Fatalf("atomicWrite: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "hello\n" {
		t.Errorf("got %q, want %q", got, "hello\n")
	}

	// Second write replaces content atomically
	if err := atomicWrite(path, "world\n"); err != nil {
		t.Fatalf("second atomicWrite: %v", err)
	}
	got, _ = os.ReadFile(path)
	if string(got) != "world\n" {
		t.Errorf("after overwrite got %q, want %q", got, "world\n")
	}
}

// ── Manager tests ─────────────────────────────────────────────────────────────

func newTestManager(t *testing.T) (*Manager, *fakeExecutor, *fakeResolver) {
	t.Helper()
	cfg := testConfig(t)
	exec := &fakeExecutor{}
	res := newFakeResolver()
	mgr := NewManager(cfg, exec, res)
	if err := mgr.EnsureFiles(); err != nil {
		t.Fatalf("EnsureFiles: %v", err)
	}
	return mgr, exec, res
}

func TestEnsureFilesCreatesEmptyLists(t *testing.T) {
	mgr, _, _ := newTestManager(t)
	for _, p := range []string{mgr.vpnListPath(), mgr.ispListPath()} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("file not created: %s", p)
		}
	}
}

func TestManagerUpdate(t *testing.T) {
	mgr, exec, _ := newTestManager(t)

	vpnN, ispN, err := mgr.Update(
		[]string{"example.com", "10.0.0.0/8"},
		[]string{"192.0.2.0/24"},
	)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if vpnN == 0 {
		t.Error("expected non-zero vpn routes")
	}
	if ispN != 1 {
		t.Errorf("expected 1 isp route, got %d", ispN)
	}
	if exec.ConfigureCount() != 1 {
		t.Errorf("expected 1 birdc configure call, got %d", exec.ConfigureCount())
	}

	// VPN list should contain wg-test nexthop (quoted interface name)
	vpnContent, err := os.ReadFile(mgr.vpnListPath())
	if err != nil {
		t.Fatalf("read vpn list: %v", err)
	}
	if !strings.Contains(string(vpnContent), `"wg-test"`) {
		t.Errorf("vpn list missing interface nexthop, got:\n%s", vpnContent)
	}

	// ISP list should contain the default GW
	ispContent, err := os.ReadFile(mgr.ispListPath())
	if err != nil {
		t.Fatalf("read isp list: %v", err)
	}
	if !strings.Contains(string(ispContent), "10.0.0.1") {
		t.Errorf("isp list missing gateway nexthop, got:\n%s", ispContent)
	}
}

func TestManagerStatePersistence(t *testing.T) {
	cfg := testConfig(t)
	exec := &fakeExecutor{}
	res := newFakeResolver()

	// First manager: update and save state
	mgr1 := NewManager(cfg, exec, res)
	_ = mgr1.EnsureFiles()
	_, _, err := mgr1.Update([]string{"example.com"}, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	// State file must exist
	if _, err := os.Stat(mgr1.statePath()); err != nil {
		t.Fatalf("state file not created: %v", err)
	}

	// Second manager: load state and apply
	exec2 := &fakeExecutor{}
	mgr2 := NewManager(cfg, exec2, res)
	_ = mgr2.EnsureFiles()
	mgr2.LoadState()

	// LoadState should have called birdc configure
	if exec2.ConfigureCount() != 1 {
		t.Errorf("LoadState did not apply: configure called %d times", exec2.ConfigureCount())
	}

	// State should be preserved
	mgr2.mu.Lock()
	vpn := mgr2.state.VPN
	mgr2.mu.Unlock()
	if len(vpn) != 1 || vpn[0] != "example.com" {
		t.Errorf("loaded state VPN = %v, want [example.com]", vpn)
	}
}

func TestManagerRefresh(t *testing.T) {
	mgr, exec, _ := newTestManager(t)

	// Refresh with no state should be a no-op
	mgr.Refresh()
	if exec.ConfigureCount() != 0 {
		t.Error("empty refresh triggered birdc configure")
	}

	// Set state, then refresh
	_, _, _ = mgr.Update([]string{"example.com"}, nil)
	cnt := exec.ConfigureCount()
	mgr.Refresh()
	if exec.ConfigureCount() != cnt+1 {
		t.Error("refresh did not trigger birdc configure")
	}
}

func TestManagerBirdConfigureError(t *testing.T) {
	mgr, exec, _ := newTestManager(t)
	exec.configureErr = fmt.Errorf("birdc: not running")

	_, _, err := mgr.Update([]string{"1.2.3.4"}, nil)
	if err == nil {
		t.Error("expected error when birdc configure fails")
	}
}

// ── Rate limiter tests ────────────────────────────────────────────────────────

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(3)
	for i := range 3 {
		if !rl.Allow() {
			t.Errorf("request %d should be allowed", i+1)
		}
	}
	if rl.Allow() {
		t.Error("4th request should be rate-limited")
	}
}

// ── HTTP handler tests ────────────────────────────────────────────────────────

func newTestServer(t *testing.T) (*httptest.Server, *Manager, *fakeExecutor) {
	t.Helper()
	cfg := testConfig(t)
	exec := &fakeExecutor{}
	res := newFakeResolver()
	mgr := NewManager(cfg, exec, res)
	if err := mgr.EnsureFiles(); err != nil {
		t.Fatalf("EnsureFiles: %v", err)
	}
	srv := httptest.NewServer(NewHandler(cfg, mgr, nil))
	t.Cleanup(srv.Close)
	return srv, mgr, exec
}

func TestHandlerHappyPath(t *testing.T) {
	srv, _, exec := newTestServer(t)

	resp := doPost(t, srv, "test-secret-token", pushPayload{
		VPN: []string{"example.com", "10.0.0.0/8"},
		ISP: []string{"192.0.2.0/24"},
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var r pushResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !r.OK {
		t.Error("ok=false in response")
	}
	if r.VPNRoutes == 0 {
		t.Error("expected non-zero vpn_routes")
	}
	if r.ISPRoutes != 1 {
		t.Errorf("expected 1 isp_route, got %d", r.ISPRoutes)
	}
	if exec.ConfigureCount() != 1 {
		t.Errorf("expected 1 birdc configure, got %d", exec.ConfigureCount())
	}
}

func TestHandlerUnauthorized(t *testing.T) {
	srv, _, _ := newTestServer(t)

	body, _ := json.Marshal(pushPayload{VPN: []string{}, ISP: []string{}})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+apiPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// No Authorization header

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestHandlerWrongToken(t *testing.T) {
	srv, _, _ := newTestServer(t)

	resp := doPost(t, srv, "wrong-token", pushPayload{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestHandlerExpiredTimestamp(t *testing.T) {
	srv, _, _ := newTestServer(t)

	body, _ := json.Marshal(pushPayload{})
	// Timestamp 10 minutes in the past
	tsStr := strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10)
	mac := hmac.New(sha256.New, []byte("test-secret-token"))
	mac.Write([]byte(tsStr))
	mac.Write([]byte(":"))
	mac.Write(body)
	bearer := hex.EncodeToString(mac.Sum(nil))

	req, _ := http.NewRequest(http.MethodPost, srv.URL+apiPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("X-Timestamp", tsStr)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired timestamp, got %d", resp.StatusCode)
	}
}

func TestHandlerWrongContentType(t *testing.T) {
	srv, _, _ := newTestServer(t)

	body := []byte(`{"vpn":[],"isp":[]}`)
	bearer, ts := signRequest(t, "test-secret-token", body)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+apiPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "text/plain") // wrong
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("X-Timestamp", ts)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("expected 415, got %d", resp.StatusCode)
	}
}

func TestHandlerMalformedJSON(t *testing.T) {
	srv, _, _ := newTestServer(t)

	body := []byte(`{not valid json`)
	bearer, ts := signRequest(t, "test-secret-token", body)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+apiPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("X-Timestamp", ts)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestHandlerUnknownPath(t *testing.T) {
	srv, _, _ := newTestServer(t)
	resp, err := http.Get(srv.URL + "/not-a-real-path")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestHandlerMethodNotAllowed(t *testing.T) {
	srv, _, _ := newTestServer(t)
	// GET on the API path should 404 (we don't reveal the path exists)
	resp, err := http.Get(srv.URL + apiPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestHandlerAPIDisabled(t *testing.T) {
	cfg := testConfig(t)
	cfg.Token = "" // no token = API disabled
	exec := &fakeExecutor{}
	res := newFakeResolver()
	mgr := NewManager(cfg, exec, res)
	_ = mgr.EnsureFiles()
	srv := httptest.NewServer(NewHandler(cfg, mgr, nil))
	defer srv.Close()

	body, _ := json.Marshal(pushPayload{VPN: []string{"1.2.3.4"}, ISP: nil})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+apiPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer somesig")
	req.Header.Set("X-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when API disabled, got %d", resp.StatusCode)
	}
}

func TestHandlerRateLimit(t *testing.T) {
	cfg := testConfig(t)
	cfg.RateLimitMax = 2
	exec := &fakeExecutor{}
	res := newFakeResolver()
	mgr := NewManager(cfg, exec, res)
	_ = mgr.EnsureFiles()
	srv := httptest.NewServer(NewHandler(cfg, mgr, nil))
	defer srv.Close()

	payload := pushPayload{VPN: []string{}, ISP: []string{}}
	for i := range 2 {
		resp := doPost(t, srv, "test-secret-token", payload)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, resp.StatusCode)
		}
	}
	// 3rd request should be rate-limited
	resp := doPost(t, srv, "test-secret-token", payload)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", resp.StatusCode)
	}
}

// ── E2E: full lifecycle ───────────────────────────────────────────────────────

// TestE2ELifecycle simulates: fresh install → push routes → verify files →
// simulate restart (new manager loads state) → verify re-applied.
func TestE2ELifecycle(t *testing.T) {
	cfg := testConfig(t)
	exec1 := &fakeExecutor{}
	res := newFakeResolver()

	// Step 1: Fresh install
	mgr1 := NewManager(cfg, exec1, res)
	if err := mgr1.EnsureFiles(); err != nil {
		t.Fatalf("EnsureFiles: %v", err)
	}

	// List files must exist (empty) so BIRD doesn't fail on include
	for _, p := range []string{mgr1.vpnListPath(), mgr1.ispListPath()} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("file missing: %s", p)
		}
		if info.Size() != 0 {
			t.Errorf("expected empty file: %s", p)
		}
	}

	// No state → LoadState is a no-op, no birdc configure
	mgr1.LoadState()
	if exec1.ConfigureCount() != 0 {
		t.Error("fresh install LoadState should not call birdc configure")
	}

	// Step 2: Push routes via HTTP
	srv := httptest.NewServer(NewHandler(cfg, mgr1, nil))
	defer srv.Close()

	resp := doPost(t, srv, cfg.Token, pushPayload{
		VPN: []string{"example.com", "10.0.0.0/8"},
		ISP: []string{"192.0.2.0/24"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("push: expected 200, got %d", resp.StatusCode)
	}

	// birdc configure was called once
	if exec1.ConfigureCount() != 1 {
		t.Errorf("expected 1 birdc configure after push, got %d", exec1.ConfigureCount())
	}

	// VPN list file is non-empty and contains our nexthop
	vpnData, _ := os.ReadFile(mgr1.vpnListPath())
	if !strings.Contains(string(vpnData), `"wg-test"`) {
		t.Errorf("vpn list missing nexthop:\n%s", vpnData)
	}

	// ISP list file contains the ISP route
	ispData, _ := os.ReadFile(mgr1.ispListPath())
	if !strings.Contains(string(ispData), "192.0.2.0/24") {
		t.Errorf("isp list missing CIDR:\n%s", ispData)
	}

	// State file was written
	if _, err := os.Stat(mgr1.statePath()); err != nil {
		t.Fatalf("state file missing after push")
	}

	// Step 3: Simulate service restart
	exec2 := &fakeExecutor{}
	mgr2 := NewManager(cfg, exec2, res) // same WorkDir
	_ = mgr2.EnsureFiles()
	mgr2.LoadState()

	// LoadState must have re-applied (called birdc configure)
	if exec2.ConfigureCount() != 1 {
		t.Errorf("restart: expected 1 birdc configure from LoadState, got %d", exec2.ConfigureCount())
	}

	// The lists must still be populated
	vpnData2, _ := os.ReadFile(mgr2.vpnListPath())
	if !strings.Contains(string(vpnData2), `"wg-test"`) {
		t.Errorf("vpn list empty after restart")
	}
}

// TestE2EManualRefresh tests that Refresh() re-resolves and updates files.
func TestE2EManualRefresh(t *testing.T) {
	cfg := testConfig(t)
	exec := &fakeExecutor{}
	res := newFakeResolver()
	mgr := NewManager(cfg, exec, res)
	_ = mgr.EnsureFiles()

	// Seed state
	_, _, err := mgr.Update([]string{"example.com"}, nil)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	cnt := exec.ConfigureCount()

	// Simulate DNS change: new IP for example.com
	res.mu.Lock()
	res.domains["example.com"] = []string{"93.184.216.99"} // changed
	res.mu.Unlock()

	mgr.Refresh()
	if exec.ConfigureCount() != cnt+1 {
		t.Error("Refresh did not call birdc configure")
	}

	// File should reflect the new IP
	data, _ := os.ReadFile(mgr.vpnListPath())
	if !strings.Contains(string(data), "93.184.216.99/32") {
		t.Errorf("vpn list not updated after refresh:\n%s", data)
	}
}

// TestE2EConcurrent tests that concurrent pushes don't race or corrupt files.
func TestE2EConcurrent(t *testing.T) {
	srv, _, exec := newTestServer(t)

	const workers = 4
	var wg sync.WaitGroup
	errs := make(chan error, workers)

	for i := range workers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			body, _ := json.Marshal(pushPayload{
				VPN: []string{fmt.Sprintf("10.%d.0.0/16", id)},
				ISP: []string{},
			})
			bearer, ts := signRequest(t, "test-secret-token", body)
			req, _ := http.NewRequest(http.MethodPost, srv.URL+apiPath, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+bearer)
			req.Header.Set("X-Timestamp", ts)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				errs <- fmt.Errorf("worker %d: %v", id, err)
				return
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusTooManyRequests {
				errs <- fmt.Errorf("worker %d: unexpected status %d", id, resp.StatusCode)
			}
		}(i)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	// birdc must have been called at least once
	if exec.ConfigureCount() == 0 {
		t.Error("no birdc configure called")
	}
}

// TestE2EVPNNexthopFormat verifies the exact BIRD2 interface nexthop syntax.
func TestE2EVPNNexthopFormat(t *testing.T) {
	cfg := testConfig(t)
	cfg.VPNInterface = "tun0" // non-default interface
	exec := &fakeExecutor{}
	res := newFakeResolver()
	mgr := NewManager(cfg, exec, res)
	_ = mgr.EnsureFiles()

	_, _, err := mgr.Update([]string{"1.2.3.4"}, nil)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	data, _ := os.ReadFile(mgr.vpnListPath())
	expected := `route 1.2.3.4/32 via "tun0";`
	if !strings.Contains(string(data), expected) {
		t.Errorf("expected %q in vpn list, got:\n%s", expected, data)
	}
}

// TestE2EEmptyPayload verifies that an empty push clears the route files.
func TestE2EEmptyPayload(t *testing.T) {
	srv, mgr, _ := newTestServer(t)

	// First push with routes
	doPost(t, srv, "test-secret-token", pushPayload{
		VPN: []string{"example.com"},
		ISP: []string{"192.0.2.0/24"},
	}).Body.Close()

	// Second push: empty lists
	resp := doPost(t, srv, "test-secret-token", pushPayload{
		VPN: []string{},
		ISP: []string{},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("empty push: expected 200, got %d", resp.StatusCode)
	}

	data, _ := os.ReadFile(mgr.vpnListPath())
	if strings.Contains(string(data), "route ") {
		t.Errorf("vpn list should be empty after empty push, got:\n%s", data)
	}
}

// TestResponseDoesNotLeakServerInfo checks that the Server header is suppressed.
func TestResponseDoesNotLeakServerInfo(t *testing.T) {
	srv, _, _ := newTestServer(t)
	resp := doPost(t, srv, "test-secret-token", pushPayload{})
	defer resp.Body.Close()
	if sv := resp.Header.Get("Server"); sv != "" {
		t.Errorf("Server header leaked: %q", sv)
	}
}

// ── Network interface sanity ──────────────────────────────────────────────────

// ── dnsmasq ipset layer tests ────────────────────────────────────────────────

func TestParseIPSetSave(t *testing.T) {
	input := `create ru_domains hash:ip family inet hashsize 1024 maxelem 65536 timeout 21600
add ru_domains 93.158.134.3 timeout 18432
add ru_domains 77.88.55.88 timeout 21100
add ru_domains 5.255.255.5 timeout 3600
add ru_domains not-an-ip timeout 100
`
	got := parseIPSetSave(input)
	want := map[string]bool{
		"93.158.134.3/32": true,
		"77.88.55.88/32":  true,
		"5.255.255.5/32":  true,
	}
	if len(got) != len(want) {
		t.Fatalf("parseIPSetSave: got %d entries, want %d: %v", len(got), len(want), got)
	}
	for _, ip := range got {
		if !want[ip] {
			t.Errorf("unexpected entry %q", ip)
		}
	}
}

func TestParseIPSetSaveEmpty(t *testing.T) {
	got := parseIPSetSave("")
	if len(got) != 0 {
		t.Errorf("expected empty result, got %v", got)
	}
}

func TestParseIPSetSaveDedup(t *testing.T) {
	input := "add s 1.2.3.4 timeout 100\nadd s 1.2.3.4 timeout 200\n"
	got := parseIPSetSave(input)
	if len(got) != 1 {
		t.Errorf("expected 1 entry after dedup, got %d: %v", len(got), got)
	}
}

func TestDNSMasqIPSetApply(t *testing.T) {
	cfg := testConfig(t)
	cfg.DNSMasqIPSet = "ru_domains"
	exec := &fakeExecutor{
		ipsetIPs: []string{"93.158.134.3/32", "77.88.55.88/32"},
	}
	res := newFakeResolver()
	mgr := NewManager(cfg, exec, res)
	if err := mgr.EnsureFiles(); err != nil {
		t.Fatalf("EnsureFiles: %v", err)
	}

	_, _, err := mgr.Update([]string{}, []string{})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	// dnsmasq-isp.list should contain the ipset IPs with ISP gateway
	data, err := os.ReadFile(mgr.dnsmasqIspListPath())
	if err != nil {
		t.Fatalf("read dnsmasq isp list: %v", err)
	}
	content := string(data)
	for _, want := range []string{"93.158.134.3/32", "77.88.55.88/32"} {
		if !strings.Contains(content, want) {
			t.Errorf("dnsmasq-isp.list missing %s, got:\n%s", want, content)
		}
	}
	// Must use ISP gateway, not VPN interface
	if strings.Contains(content, `"wg-test"`) {
		t.Error("dnsmasq-isp.list should use ISP gateway, not VPN interface")
	}
	if !strings.Contains(content, "10.0.0.1") {
		t.Error("dnsmasq-isp.list missing ISP gateway 10.0.0.1")
	}
}

func TestDNSMasqIPSetDisabled(t *testing.T) {
	mgr, _, _ := newTestManager(t)
	// DNSMasqIPSet is empty by default in testConfig

	_, _, err := mgr.Update([]string{}, []string{})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	// dnsmasq-isp.list should NOT be created when feature is disabled
	if _, err := os.Stat(mgr.dnsmasqIspListPath()); !os.IsNotExist(err) {
		t.Error("dnsmasq-isp.list should not exist when feature is disabled")
	}
}

func TestDNSMasqIPSetEmptySet(t *testing.T) {
	cfg := testConfig(t)
	cfg.DNSMasqIPSet = "ru_domains"
	exec := &fakeExecutor{ipsetIPs: nil} // empty ipset
	res := newFakeResolver()
	mgr := NewManager(cfg, exec, res)
	_ = mgr.EnsureFiles()

	_, _, err := mgr.Update([]string{}, []string{})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	data, _ := os.ReadFile(mgr.dnsmasqIspListPath())
	if strings.Contains(string(data), "route ") {
		t.Errorf("dnsmasq-isp.list should be empty for empty ipset, got:\n%s", data)
	}
}

func TestDNSMasqIPSetReadError(t *testing.T) {
	cfg := testConfig(t)
	cfg.DNSMasqIPSet = "ru_domains"
	exec := &fakeExecutor{ipsetErr: fmt.Errorf("ipset: set not found")}
	res := newFakeResolver()
	mgr := NewManager(cfg, exec, res)
	_ = mgr.EnsureFiles()

	// Should not fail — ipset read errors are non-fatal (logged as warning)
	_, _, err := mgr.Update([]string{}, []string{})
	if err != nil {
		t.Fatalf("Update should not fail on ipset read error: %v", err)
	}
}

func TestDNSMasqIPSetRefresh(t *testing.T) {
	cfg := testConfig(t)
	cfg.DNSMasqIPSet = "ru_domains"
	exec := &fakeExecutor{
		ipsetIPs: []string{"1.1.1.1/32"},
	}
	res := newFakeResolver()
	mgr := NewManager(cfg, exec, res)
	_ = mgr.EnsureFiles()

	// Initial update
	_, _, _ = mgr.Update([]string{"example.com"}, nil)

	// Simulate ipset change
	exec.mu.Lock()
	exec.ipsetIPs = []string{"1.1.1.1/32", "2.2.2.2/32"}
	exec.mu.Unlock()

	// Refresh should pick up new IPs
	mgr.Refresh()

	data, _ := os.ReadFile(mgr.dnsmasqIspListPath())
	if !strings.Contains(string(data), "2.2.2.2/32") {
		t.Errorf("dnsmasq-isp.list not updated after refresh:\n%s", data)
	}
}

// TestListInterfaces verifies we can list network interfaces (used by setup.sh).
// This just checks the Go stdlib call works, not actual interface names.
func TestListInterfaces(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}
	if len(ifaces) == 0 {
		t.Error("no network interfaces found")
	}
}

// ── IP check sites tests ──────────────────────────────────────────────────────

// TestIPCheckSitesInISPList verifies that domains in ip-check-sites.list are
// resolved and appended to the ISP route file on every apply.
func TestIPCheckSitesInISPList(t *testing.T) {
	mgr, _, res := newTestManager(t)
	res.domains["probe1.example"] = []string{"10.99.0.1"}
	res.domains["probe2.example"] = []string{"10.99.0.2"}

	sitesFile := filepath.Join(mgr.cfg.WorkDir, "ip-check-sites.list")
	if err := os.WriteFile(sitesFile, []byte("# comment\nprobe1.example\nprobe2.example\n"), 0o644); err != nil {
		t.Fatalf("write sites file: %v", err)
	}

	_, _, err := mgr.Update([]string{}, []string{})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	data, _ := os.ReadFile(mgr.ispListPath())
	for _, want := range []string{"10.99.0.1/32", "10.99.0.2/32"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("expected %s in isp list, got:\n%s", want, data)
		}
	}
}

// TestIPCheckSitesMissingFileIsNoop verifies that a missing ip-check-sites.list
// does not affect behaviour.
func TestIPCheckSitesMissingFileIsNoop(t *testing.T) {
	mgr, _, _ := newTestManager(t)
	// No ip-check-sites.list written — WorkDir is a fresh temp dir.

	_, ispN, err := mgr.Update([]string{}, []string{})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if ispN != 0 {
		t.Errorf("expected 0 isp routes, got %d", ispN)
	}
}
