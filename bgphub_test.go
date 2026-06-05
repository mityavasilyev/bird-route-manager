package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testBGPHubConfig(t *testing.T) BGPHubConfig {
	t.Helper()
	return BGPHubConfig{
		Enabled:      true,
		WorkDir:      t.TempDir(),
		Nexthop:      "10.8.3.1",
		LocalAS:      64999,
		ExportProtos: []string{"bgp_feed", "user_vpn"},
	}
}

func TestSanitizeBIRDName(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"home-router", "bgphub_home_router"},
		{"Home Router", "bgphub_home_router"},
		{"my.peer.1", "bgphub_my_peer_1"},
		{"alice", "bgphub_alice"},
		{"---", "bgphub_peer"},
		{"", "bgphub_peer"},
		{"a b c", "bgphub_a_b_c"},
	}
	for _, tt := range tests {
		got := sanitizeBIRDName(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeBIRDName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeBIRDNameMaxLength(t *testing.T) {
	long := strings.Repeat("a", 100)
	got := sanitizeBIRDName(long)
	if len(got) > 64 {
		t.Errorf("sanitizeBIRDName(100 chars) = len %d, want <= 64", len(got))
	}
}

func TestGenerateBGPHubConfNoPeers(t *testing.T) {
	cfg := testBGPHubConfig(t)
	content := GenerateBGPHubConf(cfg, nil)
	if !strings.Contains(content, "No peers configured") {
		t.Error("expected 'No peers configured' comment for empty peer list")
	}
	if strings.Contains(content, "filter bgphub_export") {
		t.Error("should not generate filter when no peers")
	}
}

func TestGenerateBGPHubConfOnePeer(t *testing.T) {
	cfg := testBGPHubConfig(t)
	peers := []BGPHubPeer{{Name: "home-router", IP: "10.8.3.8", AS: 64998}}

	content := GenerateBGPHubConf(cfg, peers)

	// Filter
	if !strings.Contains(content, "filter bgphub_export") {
		t.Error("missing export filter")
	}
	if !strings.Contains(content, `if proto = "bgp_feed"`) {
		t.Error("missing bgp_feed in export filter")
	}
	if !strings.Contains(content, `if proto = "user_vpn"`) {
		t.Error("missing user_vpn in export filter")
	}
	if !strings.Contains(content, "bgp_next_hop = 10.8.3.1") {
		t.Error("missing nexthop rewrite")
	}

	// Protocol block
	if !strings.Contains(content, "protocol bgp bgphub_home_router") {
		t.Error("missing protocol block")
	}
	if !strings.Contains(content, "local as 64999") {
		t.Error("missing local AS")
	}
	if !strings.Contains(content, "neighbor 10.8.3.8 as 64998") {
		t.Error("missing neighbor")
	}
	if !strings.Contains(content, "import none") {
		t.Error("missing import none")
	}
	if !strings.Contains(content, "export filter bgphub_export") {
		t.Error("missing export filter reference")
	}
}

func TestGenerateBGPHubConfTwoPeers(t *testing.T) {
	cfg := testBGPHubConfig(t)
	peers := []BGPHubPeer{
		{Name: "phone", IP: "10.8.3.9", AS: 64997},
		{Name: "home-router", IP: "10.8.3.8", AS: 64998},
	}

	content := GenerateBGPHubConf(cfg, peers)

	// Both protocols present
	if !strings.Contains(content, "protocol bgp bgphub_home_router") {
		t.Error("missing home-router protocol")
	}
	if !strings.Contains(content, "protocol bgp bgphub_phone") {
		t.Error("missing phone protocol")
	}

	// Filter appears only once
	if strings.Count(content, "filter bgphub_export {") != 1 {
		t.Error("filter should appear exactly once")
	}

	// Sorted by IP: 10.8.3.8 before 10.8.3.9
	idxRouter := strings.Index(content, "bgphub_home_router")
	idxPhone := strings.Index(content, "bgphub_phone")
	if idxRouter > idxPhone {
		t.Error("peers should be sorted by IP")
	}
}

func TestGenerateBGPHubConfCustomExportProtos(t *testing.T) {
	cfg := testBGPHubConfig(t)
	cfg.ExportProtos = []string{"bgp_feed"}
	peers := []BGPHubPeer{{Name: "test", IP: "10.8.3.2", AS: 64998}}

	content := GenerateBGPHubConf(cfg, peers)

	if !strings.Contains(content, `if proto = "bgp_feed"`) {
		t.Error("missing bgp_feed in filter")
	}
	if strings.Contains(content, `if proto = "user_vpn"`) {
		t.Error("user_vpn should not be in filter")
	}
}

func TestLoadSaveBGPHubPeers(t *testing.T) {
	dir := t.TempDir()

	// Load from nonexistent file returns nil
	peers, err := LoadBGPHubPeers(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if peers != nil {
		t.Error("expected nil peers from missing file")
	}

	// Save and reload
	want := []BGPHubPeer{
		{Name: "router", IP: "10.8.3.8", AS: 64998},
	}
	if err := SaveBGPHubPeers(dir, want); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := LoadBGPHubPeers(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 1 || got[0].Name != "router" || got[0].IP != "10.8.3.8" || got[0].AS != 64998 {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestAddBGPHubPeer(t *testing.T) {
	dir := t.TempDir()
	_, subnet, _ := net.ParseCIDR("10.8.3.0/24")

	peers, err := AddBGPHubPeer(dir, "router", "10.8.3.8", 64998, subnet)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}

	// Verify persisted
	loaded, err := LoadBGPHubPeers(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 persisted peer, got %d", len(loaded))
	}
}

func TestAddBGPHubPeerSubnetValidation(t *testing.T) {
	dir := t.TempDir()
	_, subnet, _ := net.ParseCIDR("10.8.3.0/24")

	_, err := AddBGPHubPeer(dir, "bad", "192.168.1.1", 64998, subnet)
	if err == nil {
		t.Error("expected error for IP outside subnet")
	}
	if !strings.Contains(err.Error(), "not in allowed subnet") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAddBGPHubPeerNilSubnet(t *testing.T) {
	dir := t.TempDir()

	// nil subnet = no validation
	_, err := AddBGPHubPeer(dir, "any", "192.168.1.1", 64998, nil)
	if err != nil {
		t.Fatalf("expected no error with nil subnet: %v", err)
	}
}

func TestAddBGPHubPeerDuplicateIP(t *testing.T) {
	dir := t.TempDir()

	_, err := AddBGPHubPeer(dir, "first", "10.8.3.8", 64998, nil)
	if err != nil {
		t.Fatalf("first add: %v", err)
	}

	_, err = AddBGPHubPeer(dir, "second", "10.8.3.8", 64997, nil)
	if err == nil {
		t.Error("expected error for duplicate IP")
	}
}

func TestAddBGPHubPeerConflictingName(t *testing.T) {
	dir := t.TempDir()

	_, err := AddBGPHubPeer(dir, "home-router", "10.8.3.8", 64998, nil)
	if err != nil {
		t.Fatalf("first add: %v", err)
	}

	// "Home Router" sanitizes to the same protocol name
	_, err = AddBGPHubPeer(dir, "Home Router", "10.8.3.9", 64997, nil)
	if err == nil {
		t.Error("expected error for conflicting protocol name")
	}
}

func TestAddBGPHubPeerInvalidIP(t *testing.T) {
	dir := t.TempDir()
	_, err := AddBGPHubPeer(dir, "bad", "not-an-ip", 64998, nil)
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestAddBGPHubPeerInvalidAS(t *testing.T) {
	dir := t.TempDir()
	_, err := AddBGPHubPeer(dir, "bad", "10.8.3.8", 0, nil)
	if err == nil {
		t.Error("expected error for AS 0")
	}
}

func TestRemoveBGPHubPeer(t *testing.T) {
	dir := t.TempDir()

	_, _ = AddBGPHubPeer(dir, "a", "10.8.3.8", 64998, nil)
	_, _ = AddBGPHubPeer(dir, "b", "10.8.3.9", 64997, nil)

	peers, err := RemoveBGPHubPeer(dir, "10.8.3.8")
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if len(peers) != 1 || peers[0].IP != "10.8.3.9" {
		t.Errorf("unexpected peers after remove: %+v", peers)
	}
}

func TestRemoveBGPHubPeerNotFound(t *testing.T) {
	dir := t.TempDir()
	_, err := RemoveBGPHubPeer(dir, "10.8.3.99")
	if err == nil {
		t.Error("expected error for removing nonexistent peer")
	}
}

func TestEnsureBGPHubConf(t *testing.T) {
	cfg := testBGPHubConfig(t)

	// Save a peer
	_ = SaveBGPHubPeers(cfg.WorkDir, []BGPHubPeer{
		{Name: "router", IP: "10.8.3.8", AS: 64998},
	})

	birdCalled := false
	err := EnsureBGPHubConf(cfg, func() error {
		birdCalled = true
		return nil
	})
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if !birdCalled {
		t.Error("expected birdConfigure to be called with peers present")
	}

	// Verify file was written
	content, err := os.ReadFile(filepath.Join(cfg.WorkDir, "bgphub-peers.conf"))
	if err != nil {
		t.Fatalf("read conf: %v", err)
	}
	if !strings.Contains(string(content), "bgphub_router") {
		t.Error("generated conf missing protocol block")
	}
}

func TestEnsureBGPHubConfNoPeers(t *testing.T) {
	cfg := testBGPHubConfig(t)

	birdCalled := false
	err := EnsureBGPHubConf(cfg, func() error {
		birdCalled = true
		return nil
	})
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if birdCalled {
		t.Error("birdConfigure should not be called with no peers")
	}
}
