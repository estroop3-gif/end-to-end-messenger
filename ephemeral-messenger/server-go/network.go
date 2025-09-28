package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// NetworkManager handles network operations and Tor integration
type NetworkManager struct {
	torManager    *TorManager
	dialer        proxy.Dialer
	httpClient    *http.Client
	config        NetworkConfig
	circuits      map[string]*Circuit
	circuitsMutex sync.RWMutex
	running       bool
}

// NetworkConfig represents network configuration
type NetworkConfig struct {
	TorEnabled        bool          `json:"tor_enabled"`
	SOCKSProxy        string        `json:"socks_proxy"`
	CircuitTimeout    time.Duration `json:"circuit_timeout"`
	MaxCircuits       int           `json:"max_circuits"`
	GuardNodes        []string      `json:"guard_nodes"`
	ExitNodes         []string      `json:"exit_nodes"`
	ExcludeNodes      []string      `json:"exclude_nodes"`
	BridgeMode        bool          `json:"bridge_mode"`
	Bridges           []string      `json:"bridges"`
	ClientAuth        bool          `json:"client_auth"`
	IsolateStreams    bool          `json:"isolate_streams"`
	ConnectionTimeout time.Duration `json:"connection_timeout"`
	RetryAttempts     int           `json:"retry_attempts"`
}

// Circuit represents a Tor circuit
type Circuit struct {
	ID         string    `json:"id"`
	Path       []string  `json:"path"`
	Purpose    string    `json:"purpose"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsed   time.Time `json:"last_used"`
	StreamCount int      `json:"stream_count"`
}

// ClientAuthConfig represents client authorization configuration
type ClientAuthConfig struct {
	Enabled     bool              `json:"enabled"`
	AuthorizedClients map[string]string `json:"authorized_clients"` // client_name -> public_key
	RequireAuth bool              `json:"require_auth"`
	MaxClients  int               `json:"max_clients"`
}

// OnionServiceConfig represents enhanced onion service configuration
type OnionServiceConfig struct {
	Name            string            `json:"name"`
	Ports           []PortMap         `json:"ports"`
	Version         int               `json:"version"`
	ClientAuth      ClientAuthConfig  `json:"client_auth"`
	MaxStreams      int               `json:"max_streams"`
	MaxStreamsClose int               `json:"max_streams_close"`
	SingleHopService bool             `json:"single_hop_service"`
	NonAnonymous    bool              `json:"non_anonymous"`
	DiscardPK       bool              `json:"discard_pk"`
}

// NewNetworkManager creates a new network manager
func NewNetworkManager(config NetworkConfig, torManager *TorManager) *NetworkManager {
	nm := &NetworkManager{
		torManager: torManager,
		config:     config,
		circuits:   make(map[string]*Circuit),
	}

	if config.TorEnabled {
		nm.setupTorDialer()
	} else {
		nm.setupDirectDialer()
	}

	return nm
}

// Start initializes the network manager
func (nm *NetworkManager) Start(ctx context.Context) error {
	if nm.config.TorEnabled && nm.torManager != nil {
		if err := nm.torManager.Start(ctx); err != nil {
			return fmt.Errorf("failed to start tor manager: %v", err)
		}
	}

	nm.running = true
	log.Println("Network manager started")

	// Start circuit monitoring if Tor is enabled
	if nm.config.TorEnabled {
		go nm.monitorCircuits(ctx)
	}

	return nil
}

// Stop shuts down the network manager
func (nm *NetworkManager) Stop() error {
	nm.running = false

	if nm.torManager != nil {
		if err := nm.torManager.Stop(); err != nil {
			log.Printf("Error stopping tor manager: %v", err)
		}
	}

	log.Println("Network manager stopped")
	return nil
}

// setupTorDialer configures dialer to use Tor SOCKS proxy
func (nm *NetworkManager) setupTorDialer() {
	socksAddr := nm.config.SOCKSProxy
	if socksAddr == "" {
		socksAddr = "127.0.0.1:9050" // Default Tor SOCKS port
	}

	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		log.Printf("Failed to create SOCKS5 dialer: %v", err)
		nm.setupDirectDialer()
		return
	}

	nm.dialer = dialer

	// Create HTTP client with Tor proxy
	transport := &http.Transport{
		Dial:                dialer.Dial,
		TLSHandshakeTimeout: 30 * time.Second,
		DisableKeepAlives:   nm.config.IsolateStreams,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
	}

	nm.httpClient = &http.Client{
		Transport: transport,
		Timeout:   nm.config.ConnectionTimeout,
	}

	log.Printf("Configured Tor SOCKS proxy: %s", socksAddr)
}

// setupDirectDialer configures direct network dialer
func (nm *NetworkManager) setupDirectDialer() {
	nm.dialer = proxy.Direct

	transport := &http.Transport{
		Dial: (&net.Dialer{
			Timeout:   nm.config.ConnectionTimeout,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	nm.httpClient = &http.Client{
		Transport: transport,
		Timeout:   nm.config.ConnectionTimeout,
	}

	log.Println("Configured direct network dialer")
}

// Dial creates a network connection
func (nm *NetworkManager) Dial(network, address string) (net.Conn, error) {
	if !nm.running {
		return nil, fmt.Errorf("network manager not running")
	}

	// Add stream isolation for Tor connections
	if nm.config.TorEnabled && nm.config.IsolateStreams {
		address = nm.addStreamIsolation(address)
	}

	ctx, cancel := context.WithTimeout(context.Background(), nm.config.ConnectionTimeout)
	defer cancel()

	// Attempt connection with retries
	var lastErr error
	for attempt := 0; attempt < nm.config.RetryAttempts; attempt++ {
		conn, err := nm.dialWithContext(ctx, network, address)
		if err == nil {
			return conn, nil
		}

		lastErr = err
		if attempt < nm.config.RetryAttempts-1 {
			time.Sleep(time.Duration(attempt+1) * time.Second)
		}
	}

	return nil, fmt.Errorf("failed to connect after %d attempts: %v", nm.config.RetryAttempts, lastErr)
}

// dialWithContext creates a connection with context
func (nm *NetworkManager) dialWithContext(ctx context.Context, network, address string) (net.Conn, error) {
	if nm.dialer == nil {
		return nil, fmt.Errorf("no dialer configured")
	}

	// For context-aware dialing
	if contextDialer, ok := nm.dialer.(proxy.ContextDialer); ok {
		return contextDialer.DialContext(ctx, network, address)
	}

	// Fallback to regular dialing
	return nm.dialer.Dial(network, address)
}

// addStreamIsolation adds stream isolation parameters to address
func (nm *NetworkManager) addStreamIsolation(address string) string {
	// Generate random isolation ID
	isolationID := make([]byte, 8)
	rand.Read(isolationID)

	// Parse address to add authentication parameters
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}

	// Add stream isolation via authentication
	isolationParam := hex.EncodeToString(isolationID)
	return fmt.Sprintf("%s:%s@%s", isolationParam, isolationParam, net.JoinHostPort(host, port))
}

// CreateOnionService creates an enhanced onion service
func (nm *NetworkManager) CreateOnionService(config OnionServiceConfig) (*HiddenService, error) {
	if !nm.config.TorEnabled || nm.torManager == nil {
		return nil, fmt.Errorf("tor not enabled")
	}

	// Create basic hidden service
	hs, err := nm.torManager.CreateHiddenService(config.Name, config.Ports, config.Version)
	if err != nil {
		return nil, err
	}

	// Configure client authorization if enabled
	if config.ClientAuth.Enabled {
		if err := nm.configureClientAuth(hs, config.ClientAuth); err != nil {
			log.Printf("Warning: Failed to configure client auth: %v", err)
		}
	}

	log.Printf("Enhanced onion service created: %s", hs.OnionAddr)
	return hs, nil
}

// configureClientAuth configures client authorization for hidden service
func (nm *NetworkManager) configureClientAuth(hs *HiddenService, authConfig ClientAuthConfig) error {
	if nm.torManager.controlConn == nil {
		return fmt.Errorf("no tor control connection")
	}

	// Enable client authorization
	cmd := fmt.Sprintf("SETCONF HiddenServiceAuthorizeClient stealth %s", hs.Name)
	if _, err := nm.torManager.controlConn.Write([]byte(cmd + "\r\n")); err != nil {
		return err
	}

	// Add authorized clients
	for clientName, publicKey := range authConfig.AuthorizedClients {
		authCmd := fmt.Sprintf("ADD_ONION %s Port=%d,%s:%d ClientAuth=%s:%s",
			hs.PrivateKey,
			hs.Ports[0].VirtualPort,
			hs.Ports[0].TargetHost,
			hs.Ports[0].TargetPort,
			clientName,
			publicKey,
		)

		if _, err := nm.torManager.controlConn.Write([]byte(authCmd + "\r\n")); err != nil {
			return fmt.Errorf("failed to add client auth: %v", err)
		}
	}

	hs.ClientAuth = true
	log.Printf("Client authorization configured for %s with %d clients", hs.Name, len(authConfig.AuthorizedClients))

	return nil
}

// GenerateClientAuthKeys generates client authorization keys
func (nm *NetworkManager) GenerateClientAuthKeys(clientName string) (string, string, error) {
	// Generate x25519 key pair for client authorization
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return "", "", err
	}

	// Derive public key (simplified - in production use proper x25519)
	publicKey := make([]byte, 32)
	copy(publicKey, privateKey) // Placeholder

	privateKeyStr := base64.StdEncoding.EncodeToString(privateKey)
	publicKeyStr := base64.StdEncoding.EncodeToString(publicKey)

	log.Printf("Generated client auth keys for %s", clientName)

	return privateKeyStr, publicKeyStr, nil
}

// monitorCircuits monitors Tor circuit status
func (nm *NetworkManager) monitorCircuits(ctx context.Context) {
	if nm.torManager.controlConn == nil {
		return
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			nm.updateCircuitStatus()
		}
	}
}

// updateCircuitStatus updates circuit information
func (nm *NetworkManager) updateCircuitStatus() {
	// Get circuit information from Tor
	cmd := "GETINFO circuit-status\r\n"
	if _, err := nm.torManager.controlConn.Write([]byte(cmd)); err != nil {
		log.Printf("Failed to get circuit status: %v", err)
		return
	}

	// This is a simplified implementation
	// In production, properly parse Tor control protocol responses
	nm.circuitsMutex.Lock()
	// Update circuits map based on Tor response
	nm.circuitsMutex.Unlock()
}

// GetCircuits returns current circuit information
func (nm *NetworkManager) GetCircuits() []*Circuit {
	nm.circuitsMutex.RLock()
	defer nm.circuitsMutex.RUnlock()

	circuits := make([]*Circuit, 0, len(nm.circuits))
	for _, circuit := range nm.circuits {
		circuits = append(circuits, circuit)
	}

	return circuits
}

// TestOnionConnectivity tests connectivity to an onion service
func (nm *NetworkManager) TestOnionConnectivity(onionAddr string, port int) error {
	if !nm.config.TorEnabled {
		return fmt.Errorf("tor not enabled")
	}

	// Test HTTP connection to onion service
	testURL := fmt.Sprintf("http://%s:%d/health", onionAddr, port)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return err
	}

	resp, err := nm.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("connection test failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	log.Printf("Onion connectivity test successful: %s", onionAddr)
	return nil
}

// CreateSecureConnection creates a secure connection with optional client certificates
func (nm *NetworkManager) CreateSecureConnection(address string, clientCert *tls.Certificate) (net.Conn, error) {
	conn, err := nm.Dial("tcp", address)
	if err != nil {
		return nil, err
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         extractHostname(address),
	}

	if clientCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*clientCert}
	}

	tlsConn := tls.Client(conn, tlsConfig)

	// Perform TLS handshake
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tls handshake failed: %v", err)
	}

	return tlsConn, nil
}

// GetNetworkStatus returns current network status
func (nm *NetworkManager) GetNetworkStatus() map[string]interface{} {
	status := map[string]interface{}{
		"running":          nm.running,
		"tor_enabled":      nm.config.TorEnabled,
		"socks_proxy":      nm.config.SOCKSProxy,
		"isolation_enabled": nm.config.IsolateStreams,
		"bridge_mode":      nm.config.BridgeMode,
		"circuit_count":    len(nm.circuits),
	}

	if nm.torManager != nil {
		status["tor_status"] = nm.torManager.GetTorStatus()
	}

	return status
}

// RouteTrafficThroughTor routes HTTP traffic through Tor
func (nm *NetworkManager) RouteTrafficThroughTor(req *http.Request) (*http.Response, error) {
	if !nm.config.TorEnabled {
		return nil, fmt.Errorf("tor not enabled")
	}

	if nm.httpClient == nil {
		return nil, fmt.Errorf("tor http client not configured")
	}

	// Add headers for anonymity
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "close")

	return nm.httpClient.Do(req)
}

// Helper functions

func extractHostname(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}

// BridgeManager manages Tor bridges for censorship resistance
type BridgeManager struct {
	bridges      []Bridge
	activeBridge *Bridge
	mutex        sync.RWMutex
}

// Bridge represents a Tor bridge
type Bridge struct {
	Type        string `json:"type"`        // obfs4, meek, etc.
	Address     string `json:"address"`
	Port        int    `json:"port"`
	Fingerprint string `json:"fingerprint"`
	Certificate string `json:"certificate,omitempty"`
	Active      bool   `json:"active"`
}

// NewBridgeManager creates a new bridge manager
func NewBridgeManager() *BridgeManager {
	return &BridgeManager{
		bridges: make([]Bridge, 0),
	}
}

// AddBridge adds a bridge to the manager
func (bm *BridgeManager) AddBridge(bridge Bridge) {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	bm.bridges = append(bm.bridges, bridge)
	log.Printf("Added bridge: %s %s:%d", bridge.Type, bridge.Address, bridge.Port)
}

// GetActiveBridge returns the currently active bridge
func (bm *BridgeManager) GetActiveBridge() *Bridge {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()

	return bm.activeBridge
}

// SetActiveBridge sets the active bridge
func (bm *BridgeManager) SetActiveBridge(fingerprint string) error {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	for i, bridge := range bm.bridges {
		if bridge.Fingerprint == fingerprint {
			bm.activeBridge = &bm.bridges[i]
			bm.bridges[i].Active = true
			log.Printf("Activated bridge: %s", fingerprint)
			return nil
		}
	}

	return fmt.Errorf("bridge not found: %s", fingerprint)
}

// ListBridges returns all configured bridges
func (bm *BridgeManager) ListBridges() []Bridge {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()

	bridges := make([]Bridge, len(bm.bridges))
	copy(bridges, bm.bridges)
	return bridges
}