package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

// ── Fake executor ───────────────────────────────────────────────────────────

type fakeFullVPNExecutor struct {
	mu sync.Mutex

	// WgPeers return value
	wgPeers    map[string]string
	wgPeersErr error

	// ContainerPID return value
	pid    int
	pidErr error

	// Track calls for assertions
	natBypassCalls  []natBypassCall
	policyRuleCalls []policyRuleCall
	setupCalled     bool

	// Error injection
	natBypassErr  error
	policyRuleErr error
	setupErr      error
}

type natBypassCall struct {
	PID            int
	PeerIP         string
	ContainerIface string
	Add            bool
}

type policyRuleCall struct {
	PeerIP string
	Table  string
	Add    bool
}

func newFakeFullVPNExecutor() *fakeFullVPNExecutor {
	return &fakeFullVPNExecutor{
		wgPeers: map[string]string{
			"pubkey-alice": "10.8.3.2",
			"pubkey-bob":   "10.8.3.3",
		},
		pid: 12345,
	}
}

func (f *fakeFullVPNExecutor) WgPeers(container, iface string) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.wgPeersErr != nil {
		return nil, f.wgPeersErr
	}
	cp := make(map[string]string, len(f.wgPeers))
	for k, v := range f.wgPeers {
		cp[k] = v
	}
	return cp, nil
}

func (f *fakeFullVPNExecutor) ContainerPID(container string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pid, f.pidErr
}

func (f *fakeFullVPNExecutor) NATBypass(pid int, peerIP, containerIface string, add bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.natBypassCalls = append(f.natBypassCalls, natBypassCall{pid, peerIP, containerIface, add})
	return f.natBypassErr
}

func (f *fakeFullVPNExecutor) PolicyRule(peerIP, table string, add bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.policyRuleCalls = append(f.policyRuleCalls, policyRuleCall{peerIP, table, add})
	return f.policyRuleErr
}

func (f *fakeFullVPNExecutor) EnsureRouteSetup(table, vpnIface, subnet, bridgeName, bridgeIP string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setupCalled = true
	return f.setupErr
}

func (f *fakeFullVPNExecutor) NATBypassCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.natBypassCalls)
}

func (f *fakeFullVPNExecutor) PolicyRuleCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.policyRuleCalls)
}

func (f *fakeFullVPNExecutor) LastNATBypass() natBypassCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.natBypassCalls[len(f.natBypassCalls)-1]
}

func (f *fakeFullVPNExecutor) LastPolicyRule() policyRuleCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.policyRuleCalls[len(f.policyRuleCalls)-1]
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func testFullVPNConfig(t *testing.T) FullVPNConfig {
	t.Helper()
	return FullVPNConfig{
		Enabled:          true,
		WorkDir:          t.TempDir(),
		ContainerName:    "test-container",
		WgInterface:      "wg0",
		ContainerIface:   "eth1",
		RouteTable:       "fulltunnel",
		VPNInterface:     "wg-test",
		OverrideDuration: 15 * time.Minute,
		CleanupInterval:  0, // disable auto-cleanup in tests
		Subnet:           "10.8.3.0/24",
		BridgeName:       "amn0",
		BridgeIP:         "172.29.172.2",
	}
}

func newTestFullVPNManager(t *testing.T) (*FullVPNManager, *fakeFullVPNExecutor) {
	t.Helper()
	cfg := testFullVPNConfig(t)
	exec := newFakeFullVPNExecutor()
	mgr := NewFullVPNManager(cfg, exec)

	// Pre-populate peers
	mgr.peers = map[string]string{
		"alice": "pubkey-alice",
		"bob":   "pubkey-bob",
	}

	return mgr, exec
}

// ── parseWgAllowedIPs tests ─────────────────────────────────────────────────

func TestParseWgAllowedIPs(t *testing.T) {
	input := `pubkey-alice	10.8.3.2/32
pubkey-bob	10.8.3.3/32
pubkey-charlie	10.8.3.4/32 fd00::4/128`

	got := parseWgAllowedIPs(input)
	want := map[string]string{
		"pubkey-alice":   "10.8.3.2",
		"pubkey-bob":     "10.8.3.3",
		"pubkey-charlie": "10.8.3.4",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d peers, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("peer %s: got %q, want %q", k, got[k], v)
		}
	}
}

func TestParseWgAllowedIPsEmpty(t *testing.T) {
	got := parseWgAllowedIPs("")
	if len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}

// ── Peers management tests ──────────────────────────────────────────────────

func TestPeersLoadSave(t *testing.T) {
	mgr, _ := newTestFullVPNManager(t)

	// Save
	if err := mgr.SavePeers(); err != nil {
		t.Fatalf("SavePeers: %v", err)
	}

	// Verify file exists
	data, err := os.ReadFile(mgr.peersPath())
	if err != nil {
		t.Fatalf("read peers.json: %v", err)
	}
	if !strings.Contains(string(data), "pubkey-alice") {
		t.Errorf("peers.json missing alice: %s", data)
	}

	// Load into a new manager
	cfg := testFullVPNConfig(t)
	cfg.WorkDir = mgr.cfg.WorkDir // same dir
	exec := newFakeFullVPNExecutor()
	mgr2 := NewFullVPNManager(cfg, exec)
	mgr2.LoadPeers()

	peers := mgr2.GetPeers()
	if peers["alice"] != "pubkey-alice" {
		t.Errorf("loaded alice = %q, want pubkey-alice", peers["alice"])
	}
}

func TestSetPeers(t *testing.T) {
	mgr, _ := newTestFullVPNManager(t)

	newPeers := map[string]string{"charlie": "pubkey-charlie"}
	if err := mgr.SetPeers(newPeers); err != nil {
		t.Fatalf("SetPeers: %v", err)
	}

	peers := mgr.GetPeers()
	if len(peers) != 1 || peers["charlie"] != "pubkey-charlie" {
		t.Errorf("unexpected peers after set: %v", peers)
	}
}

// ── Enable/Disable tests ────────────────────────────────────────────────────

func TestEnableByName(t *testing.T) {
	mgr, exec := newTestFullVPNManager(t)

	override, err := mgr.Enable("alice")
	if err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if override.PeerName != "alice" {
		t.Errorf("peer name = %q, want alice", override.PeerName)
	}
	if override.PeerIP != "10.8.3.2" {
		t.Errorf("peer IP = %q, want 10.8.3.2", override.PeerIP)
	}
	if override.ExpiresAt.Before(time.Now()) {
		t.Error("expiry is in the past")
	}

	// Verify executor was called
	if exec.NATBypassCallCount() != 1 {
		t.Errorf("expected 1 NAT bypass call, got %d", exec.NATBypassCallCount())
	}
	nat := exec.LastNATBypass()
	if nat.PeerIP != "10.8.3.2" || !nat.Add || nat.PID != 12345 {
		t.Errorf("unexpected NAT bypass call: %+v", nat)
	}

	if exec.PolicyRuleCallCount() != 1 {
		t.Errorf("expected 1 policy rule call, got %d", exec.PolicyRuleCallCount())
	}
	pr := exec.LastPolicyRule()
	if pr.PeerIP != "10.8.3.2" || !pr.Add || pr.Table != "fulltunnel" {
		t.Errorf("unexpected policy rule call: %+v", pr)
	}

	// Verify state was persisted
	overrides := mgr.ActiveOverrides()
	if len(overrides) != 1 {
		t.Fatalf("expected 1 active override, got %d", len(overrides))
	}
}

func TestEnableByPubkey(t *testing.T) {
	mgr, _ := newTestFullVPNManager(t)

	override, err := mgr.Enable("pubkey-bob")
	if err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if override.PeerName != "bob" {
		t.Errorf("peer name = %q, want bob", override.PeerName)
	}
	if override.PeerIP != "10.8.3.3" {
		t.Errorf("peer IP = %q, want 10.8.3.3", override.PeerIP)
	}
}

func TestEnableUnknownPeer(t *testing.T) {
	mgr, _ := newTestFullVPNManager(t)

	_, err := mgr.Enable("unknown")
	if err == nil {
		t.Error("expected error for unknown peer")
	}
}

func TestDisable(t *testing.T) {
	mgr, exec := newTestFullVPNManager(t)

	// Enable first
	_, _ = mgr.Enable("alice")

	// Disable
	ip, err := mgr.Disable("alice")
	if err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if ip != "10.8.3.2" {
		t.Errorf("disabled IP = %q, want 10.8.3.2", ip)
	}

	// Verify cleanup calls
	exec.mu.Lock()
	natCalls := len(exec.natBypassCalls)
	prCalls := len(exec.policyRuleCalls)
	lastNAT := exec.natBypassCalls[natCalls-1]
	lastPR := exec.policyRuleCalls[prCalls-1]
	exec.mu.Unlock()

	if natCalls < 2 {
		t.Errorf("expected at least 2 NAT bypass calls (add+remove), got %d", natCalls)
	}
	if !lastNAT.Add == true {
		// Last NAT call should be remove (add=false)
	}
	if lastNAT.Add {
		t.Error("last NAT bypass call should be remove (add=false)")
	}
	if lastPR.Add {
		t.Error("last policy rule call should be remove (add=false)")
	}

	// Override should be gone
	if len(mgr.ActiveOverrides()) != 0 {
		t.Error("expected 0 active overrides after disable")
	}
}

func TestEnableRollbackOnPolicyRuleError(t *testing.T) {
	mgr, exec := newTestFullVPNManager(t)
	exec.policyRuleErr = fmt.Errorf("ip rule failed")

	_, err := mgr.Enable("alice")
	if err == nil {
		t.Error("expected error when policy rule fails")
	}

	// NAT bypass should have been rolled back
	exec.mu.Lock()
	lastNAT := exec.natBypassCalls[len(exec.natBypassCalls)-1]
	exec.mu.Unlock()
	if lastNAT.Add {
		t.Error("NAT bypass should have been rolled back (last call should be remove)")
	}
}

// ── Expiry / Cleanup tests ──────────────────────────────────────────────────

func TestCleanupExpiresOldOverrides(t *testing.T) {
	mgr, _ := newTestFullVPNManager(t)

	// Enable alice
	_, _ = mgr.Enable("alice")

	// Manually set expiry to the past
	mgr.mu.Lock()
	o := mgr.state.Overrides["10.8.3.2"]
	o.ExpiresAt = time.Now().Add(-1 * time.Minute)
	mgr.state.Overrides["10.8.3.2"] = o
	mgr.mu.Unlock()

	// Cleanup should expire it
	mgr.Cleanup()

	if len(mgr.ActiveOverrides()) != 0 {
		t.Error("expected 0 active overrides after cleanup")
	}
}

func TestCleanupReappliesActive(t *testing.T) {
	mgr, exec := newTestFullVPNManager(t)

	_, _ = mgr.Enable("alice")
	countBefore := exec.NATBypassCallCount()

	// Cleanup should re-apply
	mgr.Cleanup()

	if exec.NATBypassCallCount() <= countBefore {
		t.Error("expected cleanup to re-apply active override")
	}
}

// ── State persistence tests ─────────────────────────────────────────────────

func TestStatePersistence(t *testing.T) {
	mgr, _ := newTestFullVPNManager(t)

	_, _ = mgr.Enable("alice")

	// Create a new manager with the same work dir
	cfg := testFullVPNConfig(t)
	cfg.WorkDir = mgr.cfg.WorkDir
	exec2 := newFakeFullVPNExecutor()
	mgr2 := NewFullVPNManager(cfg, exec2)
	mgr2.peers = map[string]string{"alice": "pubkey-alice"}
	mgr2.LoadState()

	overrides := mgr2.ActiveOverrides()
	if len(overrides) != 1 {
		t.Fatalf("expected 1 override after reload, got %d", len(overrides))
	}
	if overrides[0].PeerName != "alice" {
		t.Errorf("override name = %q, want alice", overrides[0].PeerName)
	}
}

// ── Setup tests ─────────────────────────────────────────────────────────────

func TestSetup(t *testing.T) {
	mgr, exec := newTestFullVPNManager(t)

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	exec.mu.Lock()
	called := exec.setupCalled
	exec.mu.Unlock()

	if !called {
		t.Error("EnsureRouteSetup was not called")
	}
}

// ── HTTP handler tests ──────────────────────────────────────────────────────

func newTestFullVPNServer(t *testing.T) (*httptest.Server, *FullVPNManager, *fakeFullVPNExecutor) {
	t.Helper()
	cfg := testConfig(t) // from main_test.go
	fvpnCfg := testFullVPNConfig(t)
	exec := newFakeFullVPNExecutor()
	fvpnMgr := NewFullVPNManager(fvpnCfg, exec)
	fvpnMgr.peers = map[string]string{
		"alice": "pubkey-alice",
		"bob":   "pubkey-bob",
	}

	routeExec := &fakeExecutor{}
	routeRes := newFakeResolver()
	routeMgr := NewManager(cfg, routeExec, routeRes)
	_ = routeMgr.EnsureFiles()

	srv := httptest.NewServer(NewHandler(cfg, routeMgr, fvpnMgr))
	t.Cleanup(srv.Close)
	return srv, fvpnMgr, exec
}

func doFullVPNPost(t *testing.T, srv *httptest.Server, path string, token string, payload any) *http.Response {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	tsStr := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(tsStr))
	mac.Write([]byte(":"))
	mac.Write(body)
	bearer := hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("X-Timestamp", tsStr)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

func TestHandlerFullVPNEnable(t *testing.T) {
	srv, _, exec := newTestFullVPNServer(t)

	resp := doFullVPNPost(t, srv, fullvpnPath, "test-secret-token", fullvpnRequest{Peer: "alice"})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var r fullvpnResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.OK {
		t.Error("ok=false")
	}
	if r.Peer != "alice" {
		t.Errorf("peer = %q, want alice", r.Peer)
	}
	if r.IP != "10.8.3.2" {
		t.Errorf("ip = %q, want 10.8.3.2", r.IP)
	}
	if r.Enabled == nil || !*r.Enabled {
		t.Error("enabled should be true")
	}
	if r.ExpiresAt == "" {
		t.Error("expires_at should be set")
	}

	if exec.NATBypassCallCount() != 1 {
		t.Errorf("expected 1 NAT bypass call, got %d", exec.NATBypassCallCount())
	}
}

func TestHandlerFullVPNDisable(t *testing.T) {
	srv, _, _ := newTestFullVPNServer(t)

	// Enable first
	resp := doFullVPNPost(t, srv, fullvpnPath, "test-secret-token", fullvpnRequest{Peer: "alice"})
	resp.Body.Close()

	// Disable
	f := false
	resp = doFullVPNPost(t, srv, fullvpnPath, "test-secret-token", fullvpnRequest{Peer: "alice", Enable: &f})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var r fullvpnResponse
	json.NewDecoder(resp.Body).Decode(&r)
	if r.Enabled == nil || *r.Enabled {
		t.Error("enabled should be false")
	}
}

func TestHandlerFullVPNList(t *testing.T) {
	srv, _, _ := newTestFullVPNServer(t)

	// Enable alice
	resp := doFullVPNPost(t, srv, fullvpnPath, "test-secret-token", fullvpnRequest{Peer: "alice"})
	resp.Body.Close()

	// List (empty body)
	resp = doFullVPNPost(t, srv, fullvpnPath, "test-secret-token", struct{}{})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var r fullvpnResponse
	json.NewDecoder(resp.Body).Decode(&r)
	if len(r.Overrides) != 1 {
		t.Errorf("expected 1 override, got %d", len(r.Overrides))
	}
}

func TestHandlerFullVPNUnknownPeer(t *testing.T) {
	srv, _, _ := newTestFullVPNServer(t)

	resp := doFullVPNPost(t, srv, fullvpnPath, "test-secret-token", fullvpnRequest{Peer: "unknown"})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500 for unknown peer, got %d", resp.StatusCode)
	}
}

func TestHandlerFullVPNUnauthorized(t *testing.T) {
	srv, _, _ := newTestFullVPNServer(t)

	resp := doFullVPNPost(t, srv, fullvpnPath, "wrong-token", fullvpnRequest{Peer: "alice"})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

// ── Peers API handler tests ─────────────────────────────────────────────────

func TestHandlerPeersSet(t *testing.T) {
	srv, mgr, _ := newTestFullVPNServer(t)

	newPeers := map[string]string{"charlie": "pubkey-charlie"}
	resp := doFullVPNPost(t, srv, peersPath, "test-secret-token", peersRequest{Peers: newPeers})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var r peersResponse
	json.NewDecoder(resp.Body).Decode(&r)
	if !r.OK || r.Count != 1 {
		t.Errorf("unexpected response: %+v", r)
	}

	// Verify peers were saved
	peers := mgr.GetPeers()
	if peers["charlie"] != "pubkey-charlie" {
		t.Errorf("peers not updated: %v", peers)
	}

	// Verify file was written
	data, err := os.ReadFile(filepath.Join(mgr.cfg.WorkDir, "peers.json"))
	if err != nil {
		t.Fatalf("read peers.json: %v", err)
	}
	if !strings.Contains(string(data), "pubkey-charlie") {
		t.Error("peers.json not persisted")
	}
}

func TestHandlerPeersList(t *testing.T) {
	srv, _, _ := newTestFullVPNServer(t)

	resp := doFullVPNPost(t, srv, peersPath, "test-secret-token", struct{}{})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var r peersResponse
	json.NewDecoder(resp.Body).Decode(&r)
	if !r.OK {
		t.Error("ok=false")
	}
	if r.Peers["alice"] != "pubkey-alice" {
		t.Errorf("peers missing alice: %v", r.Peers)
	}
}

func TestHandlerPeersUnauthorized(t *testing.T) {
	srv, _, _ := newTestFullVPNServer(t)

	resp := doFullVPNPost(t, srv, peersPath, "wrong-token", peersRequest{})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

// ── Full-VPN disabled tests ─────────────────────────────────────────────────

func TestHandlerFullVPNDisabledReturns404(t *testing.T) {
	cfg := testConfig(t)
	routeExec := &fakeExecutor{}
	routeRes := newFakeResolver()
	routeMgr := NewManager(cfg, routeExec, routeRes)
	_ = routeMgr.EnsureFiles()

	// nil fullvpn manager = feature disabled
	srv := httptest.NewServer(NewHandler(cfg, routeMgr, nil))
	defer srv.Close()

	resp := doFullVPNPost(t, srv, fullvpnPath, "test-secret-token", fullvpnRequest{Peer: "alice"})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 when fullvpn disabled, got %d", resp.StatusCode)
	}
}

// ── Existing routes API still works with fullvpn ────────────────────────────

func TestRoutesAPIStillWorksWithFullVPN(t *testing.T) {
	srv, _, _ := newTestFullVPNServer(t)

	resp := doPost(t, srv, "test-secret-token", pushPayload{
		VPN: []string{"example.com"},
		ISP: []string{},
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("routes API broken with fullvpn enabled: got %d", resp.StatusCode)
	}
}
