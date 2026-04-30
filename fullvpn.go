// fullvpn.go — per-peer full-VPN override module.
//
// Temporarily routes individual VPN peers through the VPN tunnel for all traffic
// (bypassing split routing) for a configurable duration. Designed for AmneziaWG
// running in Docker, where the container masquerades peer traffic.
//
// How it works:
//   - Reads peer pubkey→IP mapping via `docker exec ... wg show`
//   - Bypasses container NAT for the peer via `nsenter ... iptables` (transient rule)
//   - Adds host `ip rule` to route that peer's traffic via the VPN tunnel
//   - A cleanup ticker expires overrides and re-applies active ones (survives restarts)
//
// Container interaction is read-only at the application layer — the only write is
// a transient iptables NAT bypass rule in the container's network namespace, which
// vanishes on container restart. The cleanup ticker re-applies it.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── Executor interface ──────────────────────────────────────────────────────

// FullVPNExecutor abstracts system commands for the full-VPN feature.
// Separate from the main Executor to keep concerns isolated.
type FullVPNExecutor interface {
	// WgPeers returns a pubkey→IP mapping from the WG interface inside a container.
	WgPeers(container, iface string) (map[string]string, error)
	// ContainerPID returns the PID of the container's init process.
	ContainerPID(container string) (int, error)
	// NATBypass adds or removes a RETURN rule in the container's NAT POSTROUTING
	// chain, causing the container to skip masquerade for this peer's traffic.
	NATBypass(pid int, peerIP, containerIface string, add bool) error
	// PolicyRule adds or removes a source-based ip rule on the host.
	PolicyRule(peerIP, table string, add bool) error
	// EnsureRouteSetup idempotently sets up the host routing infrastructure:
	//   - default route in the named table via vpnIface
	//   - host route for subnet via bridgeIP on bridgeName
	//   - MASQUERADE for subnet traffic leaving via non-bridge interfaces
	EnsureRouteSetup(table, vpnIface, subnet, bridgeName, bridgeIP string) error
}

// ── Real executor ───────────────────────────────────────────────────────────

type systemFullVPNExecutor struct{}

func (systemFullVPNExecutor) WgPeers(container, iface string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "exec", container, "wg", "show", iface, "allowed-ips").Output()
	if err != nil {
		return nil, fmt.Errorf("docker exec wg show: %w", err)
	}
	return parseWgAllowedIPs(string(out)), nil
}

// parseWgAllowedIPs parses `wg show <iface> allowed-ips` output.
// Each line: <pubkey>\t<ip1>/32 <ip2>/32 ...
// Returns pubkey → first IPv4 (without /32 suffix).
func parseWgAllowedIPs(output string) map[string]string {
	peers := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		pubkey := parts[0]
		for _, allowed := range parts[1:] {
			ip, _, err := net.ParseCIDR(allowed)
			if err != nil {
				continue
			}
			if ip.To4() != nil {
				peers[pubkey] = ip.String()
				break
			}
		}
	}
	return peers
}

func (systemFullVPNExecutor) ContainerPID(container string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "inspect", container, "--format", "{{.State.Pid}}").Output()
	if err != nil {
		return 0, fmt.Errorf("docker inspect: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("invalid container PID: %s", strings.TrimSpace(string(out)))
	}
	return pid, nil
}

// detectIptables determines whether the container uses iptables-legacy or iptables.
// Many Docker containers (including AmneziaWG) use iptables-legacy for NAT rules.
func detectIptables(pid int) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Check if iptables-legacy exists and has NAT rules in the container's namespace
	out, err := exec.CommandContext(ctx, "nsenter", "-t", strconv.Itoa(pid), "-n",
		"iptables-legacy", "-t", "nat", "-L", "POSTROUTING", "-n").CombinedOutput()
	if err == nil && strings.Contains(string(out), "MASQUERADE") {
		return "iptables-legacy"
	}
	return "iptables"
}

func (systemFullVPNExecutor) NATBypass(pid int, peerIP, containerIface string, add bool) error {
	iptCmd := detectIptables(pid)

	action := "-I"
	if !add {
		action = "-D"
	}

	// Check if rule already exists (for idempotency)
	checkCtx, checkCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer checkCancel()
	checkErr := exec.CommandContext(checkCtx, "nsenter", "-t", strconv.Itoa(pid), "-n",
		iptCmd, "-t", "nat", "-C", "POSTROUTING",
		"-s", peerIP, "-o", containerIface, "-j", "RETURN").Run()
	ruleExists := checkErr == nil

	if add && ruleExists {
		return nil // already in place
	}
	if !add && !ruleExists {
		return nil // already gone
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nsenter", "-t", strconv.Itoa(pid), "-n",
		iptCmd, "-t", "nat", action, "POSTROUTING",
		"-s", peerIP, "-o", containerIface, "-j", "RETURN").CombinedOutput()
	if err != nil {
		return fmt.Errorf("nsenter %s %s: %w — %s", iptCmd, action, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (systemFullVPNExecutor) PolicyRule(peerIP, table string, add bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check if rule exists
	checkCtx, checkCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer checkCancel()
	checkOut, _ := exec.CommandContext(checkCtx, "ip", "rule", "show", "from", peerIP).Output()
	ruleExists := strings.Contains(string(checkOut), "lookup "+table)

	if add && ruleExists {
		return nil
	}
	if !add && !ruleExists {
		return nil
	}

	action := "add"
	if !add {
		action = "del"
	}

	args := []string{"rule", action, "from", peerIP, "table", table}
	if add {
		args = append(args, "priority", "100")
	}

	out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip rule %s: %w — %s", action, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (systemFullVPNExecutor) EnsureRouteSetup(table, vpnIface, subnet, bridgeName, bridgeIP string) error {
	// 1. Default route in the fullvpn table via the VPN interface
	ctx1, cancel1 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel1()
	if out, err := exec.CommandContext(ctx1, "ip", "route", "replace", "default", "dev", vpnIface, "table", table).CombinedOutput(); err != nil {
		log.Printf("fullvpn: warn: default route in table %s: %v — %s", table, err, strings.TrimSpace(string(out)))
	}

	// 2. Host route for VPN subnet via container bridge IP
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if out, err := exec.CommandContext(ctx2, "ip", "route", "replace", subnet, "via", bridgeIP, "dev", bridgeName).CombinedOutput(); err != nil {
		return fmt.Errorf("host route for %s via %s dev %s: %w — %s", subnet, bridgeIP, bridgeName, err, strings.TrimSpace(string(out)))
	}

	// 3. MASQUERADE for VPN subnet traffic (idempotent: check first)
	ctx3, cancel3 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel3()
	checkErr := exec.CommandContext(ctx3, "iptables", "-t", "nat", "-C", "POSTROUTING",
		"-s", subnet, "!", "-o", bridgeName, "-j", "MASQUERADE").Run()
	if checkErr != nil {
		ctx4, cancel4 := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel4()
		if out, err := exec.CommandContext(ctx4, "iptables", "-t", "nat", "-I", "POSTROUTING",
			"-s", subnet, "!", "-o", bridgeName, "-j", "MASQUERADE").CombinedOutput(); err != nil {
			return fmt.Errorf("iptables MASQUERADE: %w — %s", err, strings.TrimSpace(string(out)))
		}
	}

	log.Printf("fullvpn: route setup OK (table=%s, iface=%s, subnet=%s, bridge=%s via %s)", table, vpnIface, subnet, bridgeName, bridgeIP)
	return nil
}

// ── Config ──────────────────────────────────────────────────────────────────

// FullVPNConfig holds configuration for the full-VPN feature.
type FullVPNConfig struct {
	Enabled          bool
	WorkDir          string
	ContainerName    string
	WgInterface      string
	ContainerIface   string
	RouteTable       string
	VPNInterface     string // host VPN interface (e.g. wg-ch) — from main config
	OverrideDuration time.Duration
	CleanupInterval  time.Duration
	Subnet           string
	BridgeName       string
	BridgeIP         string
}

func fullvpnConfigFromEnv(workDir, vpnInterface string) FullVPNConfig {
	return FullVPNConfig{
		Enabled:          os.Getenv("FULLVPN_ENABLED") == "true",
		WorkDir:          workDir,
		ContainerName:    envOr("AWG_CONTAINER", "amnezia-awg"),
		WgInterface:      envOr("AWG_WG_INTERFACE", "wg0"),
		ContainerIface:   envOr("AWG_CONTAINER_IFACE", "eth1"),
		RouteTable:       envOr("FULLVPN_TABLE", "fulltunnel"),
		VPNInterface:     vpnInterface,
		OverrideDuration: time.Duration(envOrInt("FULLVPN_DURATION", 900)) * time.Second,
		CleanupInterval:  time.Duration(envOrInt("FULLVPN_CLEANUP", 180)) * time.Second,
		Subnet:           envOr("FULLVPN_SUBNET", "10.8.3.0/24"),
		BridgeName:       envOr("FULLVPN_BRIDGE", "amn0"),
		BridgeIP:         envOr("FULLVPN_BRIDGE_IP", "172.29.172.2"),
	}
}

// ── State ───────────────────────────────────────────────────────────────────

// FullVPNOverride represents an active full-VPN override for a peer.
type FullVPNOverride struct {
	PeerName  string    `json:"peer_name"`
	PeerIP    string    `json:"peer_ip"`
	ExpiresAt time.Time `json:"expires_at"`
}

// fullVPNState is persisted to fullvpn-state.json.
type fullVPNState struct {
	Overrides map[string]FullVPNOverride `json:"overrides"` // key = peer IP
}

// ── Manager ─────────────────────────────────────────────────────────────────

// FullVPNManager manages per-peer full-VPN overrides.
type FullVPNManager struct {
	cfg  FullVPNConfig
	exec FullVPNExecutor

	mu    sync.Mutex
	state fullVPNState
	peers map[string]string // name → pubkey
}

// NewFullVPNManager creates a new FullVPNManager.
func NewFullVPNManager(cfg FullVPNConfig, exec FullVPNExecutor) *FullVPNManager {
	return &FullVPNManager{
		cfg:   cfg,
		exec:  exec,
		state: fullVPNState{Overrides: make(map[string]FullVPNOverride)},
		peers: make(map[string]string),
	}
}

func (m *FullVPNManager) peersPath() string { return filepath.Join(m.cfg.WorkDir, "peers.json") }
func (m *FullVPNManager) statePath() string {
	return filepath.Join(m.cfg.WorkDir, "fullvpn-state.json")
}

// ── Peers management ────────────────────────────────────────────────────────

// LoadPeers reads peers.json from disk. Non-fatal if missing.
func (m *FullVPNManager) LoadPeers() {
	data, err := os.ReadFile(m.peersPath())
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("fullvpn: warn: load peers: %v", err)
		}
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := json.Unmarshal(data, &m.peers); err != nil {
		log.Printf("fullvpn: warn: decode peers: %v", err)
	}
	log.Printf("fullvpn: loaded %d peers", len(m.peers))
}

// SavePeers writes peers.json to disk.
func (m *FullVPNManager) SavePeers() error {
	m.mu.Lock()
	data, err := json.MarshalIndent(m.peers, "", "  ")
	m.mu.Unlock()
	if err != nil {
		return err
	}
	return atomicWrite(m.peersPath(), string(data)+"\n")
}

// SetPeers replaces the peer registry and saves to disk.
func (m *FullVPNManager) SetPeers(peers map[string]string) error {
	m.mu.Lock()
	m.peers = peers
	m.mu.Unlock()
	return m.SavePeers()
}

// GetPeers returns a copy of the current peer registry.
func (m *FullVPNManager) GetPeers() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make(map[string]string, len(m.peers))
	for k, v := range m.peers {
		cp[k] = v
	}
	return cp
}

// ── State management ────────────────────────────────────────────────────────

// LoadState reads fullvpn-state.json and re-applies active overrides.
func (m *FullVPNManager) LoadState() {
	data, err := os.ReadFile(m.statePath())
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("fullvpn: warn: load state: %v", err)
		}
		return
	}
	var s fullVPNState
	if err := json.Unmarshal(data, &s); err != nil {
		log.Printf("fullvpn: warn: decode state: %v", err)
		return
	}
	if s.Overrides == nil {
		s.Overrides = make(map[string]FullVPNOverride)
	}

	m.mu.Lock()
	m.state = s
	m.mu.Unlock()

	log.Printf("fullvpn: loaded %d overrides from state, applying...", len(s.Overrides))
	m.Cleanup()
}

func (m *FullVPNManager) saveStateLocked() error {
	data, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(m.statePath(), string(data)+"\n")
}

// ── Core operations ─────────────────────────────────────────────────────────

// resolvePeer resolves a peer name or pubkey to (name, pubkey, IP).
func (m *FullVPNManager) resolvePeer(peerNameOrKey string) (name, pubkey, ip string, err error) {
	m.mu.Lock()
	// Check if it's a peer name
	if pk, ok := m.peers[peerNameOrKey]; ok {
		name = peerNameOrKey
		pubkey = pk
	} else {
		// Check if it's a pubkey directly (look for it in the peers map values)
		for n, pk := range m.peers {
			if pk == peerNameOrKey {
				name = n
				pubkey = pk
				break
			}
		}
		if pubkey == "" {
			// Treat as raw pubkey not in the registry
			pubkey = peerNameOrKey
		}
	}
	m.mu.Unlock()

	// Look up IP from WireGuard
	wgPeers, wgErr := m.exec.WgPeers(m.cfg.ContainerName, m.cfg.WgInterface)
	if wgErr != nil {
		return "", "", "", fmt.Errorf("wg peers: %w", wgErr)
	}

	ip, ok := wgPeers[pubkey]
	if !ok {
		return "", "", "", fmt.Errorf("peer %q not found in WireGuard interface", peerNameOrKey)
	}

	if name == "" {
		name = pubkey[:12] + "..." // truncated pubkey as fallback name
	}

	return name, pubkey, ip, nil
}

// Enable activates a full-VPN override for the given peer.
func (m *FullVPNManager) Enable(peerNameOrKey string) (*FullVPNOverride, error) {
	name, _, ip, err := m.resolvePeer(peerNameOrKey)
	if err != nil {
		return nil, err
	}

	pid, err := m.exec.ContainerPID(m.cfg.ContainerName)
	if err != nil {
		return nil, err
	}

	// Apply NAT bypass in container
	if err := m.exec.NATBypass(pid, ip, m.cfg.ContainerIface, true); err != nil {
		return nil, fmt.Errorf("nat bypass: %w", err)
	}

	// Apply host policy rule
	if err := m.exec.PolicyRule(ip, m.cfg.RouteTable, true); err != nil {
		// Try to roll back NAT bypass
		_ = m.exec.NATBypass(pid, ip, m.cfg.ContainerIface, false)
		return nil, fmt.Errorf("policy rule: %w", err)
	}

	override := FullVPNOverride{
		PeerName:  name,
		PeerIP:    ip,
		ExpiresAt: time.Now().Add(m.cfg.OverrideDuration),
	}

	m.mu.Lock()
	m.state.Overrides[ip] = override
	if err := m.saveStateLocked(); err != nil {
		log.Printf("fullvpn: warn: save state: %v", err)
	}
	m.mu.Unlock()

	log.Printf("fullvpn: enabled for %s (%s), expires %s", name, ip, override.ExpiresAt.Format(time.RFC3339))
	return &override, nil
}

// Disable removes a full-VPN override for the given peer.
func (m *FullVPNManager) Disable(peerNameOrKey string) (string, error) {
	name, _, ip, err := m.resolvePeer(peerNameOrKey)
	if err != nil {
		// If we can't resolve the peer from WG, check if we have it in state by name
		m.mu.Lock()
		for oIP, o := range m.state.Overrides {
			if o.PeerName == peerNameOrKey {
				ip = oIP
				name = o.PeerName
				break
			}
		}
		m.mu.Unlock()
		if ip == "" {
			return "", err
		}
	}

	m.disableByIP(ip)
	log.Printf("fullvpn: disabled for %s (%s)", name, ip)
	return ip, nil
}

// disableByIP removes routing rules and state for a peer IP.
func (m *FullVPNManager) disableByIP(ip string) {
	// Remove host policy rule (best-effort)
	if err := m.exec.PolicyRule(ip, m.cfg.RouteTable, false); err != nil {
		log.Printf("fullvpn: warn: remove policy rule for %s: %v", ip, err)
	}

	// Remove container NAT bypass (best-effort)
	pid, pidErr := m.exec.ContainerPID(m.cfg.ContainerName)
	if pidErr != nil {
		log.Printf("fullvpn: warn: get container PID: %v", pidErr)
	} else {
		if err := m.exec.NATBypass(pid, ip, m.cfg.ContainerIface, false); err != nil {
			log.Printf("fullvpn: warn: remove NAT bypass for %s: %v", ip, err)
		}
	}

	m.mu.Lock()
	delete(m.state.Overrides, ip)
	if err := m.saveStateLocked(); err != nil {
		log.Printf("fullvpn: warn: save state: %v", err)
	}
	m.mu.Unlock()
}

// ActiveOverrides returns a copy of all active overrides.
func (m *FullVPNManager) ActiveOverrides() []FullVPNOverride {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]FullVPNOverride, 0, len(m.state.Overrides))
	for _, o := range m.state.Overrides {
		out = append(out, o)
	}
	return out
}

// Cleanup expires old overrides and re-applies active ones. Idempotent.
func (m *FullVPNManager) Cleanup() {
	m.mu.Lock()
	var expired []string
	var active []FullVPNOverride
	for ip, o := range m.state.Overrides {
		if time.Now().After(o.ExpiresAt) {
			expired = append(expired, ip)
		} else {
			active = append(active, o)
		}
	}
	m.mu.Unlock()

	// Expire old overrides
	for _, ip := range expired {
		log.Printf("fullvpn: expiring override for %s", ip)
		m.disableByIP(ip)
	}

	// Re-apply active overrides (handles container restarts)
	if len(active) > 0 {
		pid, pidErr := m.exec.ContainerPID(m.cfg.ContainerName)
		if pidErr != nil {
			log.Printf("fullvpn: warn: cleanup: get container PID: %v", pidErr)
			return
		}
		for _, o := range active {
			if err := m.exec.NATBypass(pid, o.PeerIP, m.cfg.ContainerIface, true); err != nil {
				log.Printf("fullvpn: warn: re-apply NAT bypass for %s: %v", o.PeerIP, err)
			}
			if err := m.exec.PolicyRule(o.PeerIP, m.cfg.RouteTable, true); err != nil {
				log.Printf("fullvpn: warn: re-apply policy rule for %s: %v", o.PeerIP, err)
			}
		}
	}
}

// StartCleanupTicker starts the periodic cleanup goroutine.
func (m *FullVPNManager) StartCleanupTicker(ctx context.Context) {
	if m.cfg.CleanupInterval <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(m.cfg.CleanupInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.Cleanup()
			}
		}
	}()
}

// Setup performs one-time host routing setup. Called on service startup.
func (m *FullVPNManager) Setup() error {
	return m.exec.EnsureRouteSetup(
		m.cfg.RouteTable,
		m.cfg.VPNInterface,
		m.cfg.Subnet,
		m.cfg.BridgeName,
		m.cfg.BridgeIP,
	)
}

// ── HTTP handlers ───────────────────────────────────────────────────────────

const (
	fullvpnPath = "/api/v1/fullvpn"
	peersPath   = "/api/v1/peers"
)

type fullvpnRequest struct {
	Peer   string `json:"peer"`
	Enable *bool  `json:"enable"` // pointer so we can detect omission (default: true)
}

type fullvpnResponse struct {
	OK        bool              `json:"ok"`
	Peer      string            `json:"peer,omitempty"`
	IP        string            `json:"ip,omitempty"`
	Enabled   *bool             `json:"enabled,omitempty"`
	ExpiresAt string            `json:"expires_at,omitempty"`
	Overrides []FullVPNOverride `json:"overrides,omitempty"`
}

type peersRequest struct {
	Peers map[string]string `json:"peers"`
}

type peersResponse struct {
	OK    bool              `json:"ok"`
	Count int               `json:"count,omitempty"`
	Peers map[string]string `json:"peers,omitempty"`
}

// HandleFullVPN handles POST /api/v1/fullvpn.
func (m *FullVPNManager) HandleFullVPN(cfg Config, w http.ResponseWriter, r *http.Request, body []byte) {
	var req fullvpnRequest
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			errResp(w, http.StatusBadRequest, "bad request")
			return
		}
	}

	// No peer specified → list active overrides
	if req.Peer == "" {
		overrides := m.ActiveOverrides()
		jsonResp(w, http.StatusOK, fullvpnResponse{OK: true, Overrides: overrides})
		return
	}

	// Determine enable/disable — default is enable
	enable := true
	if req.Enable != nil {
		enable = *req.Enable
	}

	if enable {
		override, err := m.Enable(req.Peer)
		if err != nil {
			log.Printf("fullvpn: enable error: %v", err)
			errResp(w, http.StatusInternalServerError, err.Error())
			return
		}
		enabled := true
		jsonResp(w, http.StatusOK, fullvpnResponse{
			OK:        true,
			Peer:      override.PeerName,
			IP:        override.PeerIP,
			Enabled:   &enabled,
			ExpiresAt: override.ExpiresAt.Format(time.RFC3339),
		})
	} else {
		ip, err := m.Disable(req.Peer)
		if err != nil {
			log.Printf("fullvpn: disable error: %v", err)
			errResp(w, http.StatusInternalServerError, err.Error())
			return
		}
		disabled := false
		jsonResp(w, http.StatusOK, fullvpnResponse{
			OK:      true,
			Peer:    req.Peer,
			IP:      ip,
			Enabled: &disabled,
		})
	}
}

// HandlePeers handles POST /api/v1/peers.
func (m *FullVPNManager) HandlePeers(cfg Config, w http.ResponseWriter, r *http.Request, body []byte) {
	var req peersRequest
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			errResp(w, http.StatusBadRequest, "bad request")
			return
		}
	}

	// No peers in request → list current peers
	if req.Peers == nil {
		peers := m.GetPeers()
		jsonResp(w, http.StatusOK, peersResponse{OK: true, Count: len(peers), Peers: peers})
		return
	}

	if err := m.SetPeers(req.Peers); err != nil {
		log.Printf("fullvpn: set peers error: %v", err)
		errResp(w, http.StatusInternalServerError, "failed to save peers")
		return
	}

	log.Printf("fullvpn: peers updated (%d entries)", len(req.Peers))
	jsonResp(w, http.StatusOK, peersResponse{OK: true, Count: len(req.Peers)})
}

// ── Helpers shared with tests ───────────────────────────────────────────────

// verifyAndReadBody handles auth verification and body reading for all API endpoints.
// Returns the body bytes if auth passes, or writes an error response and returns nil.
func verifyAndReadBody(cfg Config, rl *rateLimiter, w http.ResponseWriter, r *http.Request) []byte {
	if r.Method != http.MethodPost {
		errResp(w, http.StatusNotFound, "not found")
		return nil
	}
	if cfg.Token == "" {
		errResp(w, http.StatusServiceUnavailable, "api not enabled")
		return nil
	}
	if !rl.Allow() {
		errResp(w, http.StatusTooManyRequests, "too many requests")
		return nil
	}

	body, err := readLimitedBody(r, cfg.MaxBodyBytes)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			errResp(w, http.StatusRequestEntityTooLarge, "payload too large")
		} else {
			errResp(w, http.StatusBadRequest, "bad request")
		}
		return nil
	}

	if !strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		errResp(w, http.StatusUnsupportedMediaType, "unsupported media type")
		return nil
	}

	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		errResp(w, http.StatusUnauthorized, "unauthorized")
		return nil
	}
	bearer := strings.TrimPrefix(auth, "Bearer ")
	tsStr := r.Header.Get("X-Timestamp")

	if !tsInWindow(tsStr, cfg.TimestampWindow) {
		errResp(w, http.StatusUnauthorized, "unauthorized")
		return nil
	}
	if !verifyHMAC(cfg.Token, bearer, tsStr, body) {
		errResp(w, http.StatusUnauthorized, "unauthorized")
		return nil
	}

	return body
}

var errBodyTooLarge = errors.New("body too large")

func readLimitedBody(r *http.Request, maxBytes int64) ([]byte, error) {
	body, err := readAllLimited(r.Body, maxBytes+1)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, errBodyTooLarge
	}
	return body, nil
}
