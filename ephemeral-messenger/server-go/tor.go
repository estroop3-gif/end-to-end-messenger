package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
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

// TorManager manages Tor integration and hidden services
type TorManager struct {
	config         TorConfig
	controlConn    net.Conn
	hiddenServices map[string]*HiddenService
	mutex          sync.RWMutex
	running        bool
	torProcess     *exec.Cmd
	dataDir        string
}

// TorConfig represents Tor configuration
type TorConfig struct {
	ControlPort       int      `json:"control_port"`
	SOCKSPort        int      `json:"socks_port"`
	DataDirectory    string   `json:"data_directory"`
	HiddenServiceDir string   `json:"hidden_service_dir"`
	BridgeMode       bool     `json:"bridge_mode"`
	Bridges          []string `json:"bridges"`
	ExitNodes        []string `json:"exit_nodes"`
	EntryNodes       []string `json:"entry_nodes"`
	StrictNodes      bool     `json:"strict_nodes"`
	CircuitTimeout   int      `json:"circuit_timeout"`
	MaxCircuits      int      `json:"max_circuits"`
	LogLevel         string   `json:"log_level"`
	ControlPassword  string   `json:"control_password"`
}

// HiddenService represents a Tor hidden service
type HiddenService struct {
	Name        string    `json:"name"`
	OnionAddr   string    `json:"onion_addr"`
	PrivateKey  string    `json:"private_key"`
	PublicKey   string    `json:"public_key"`
	Ports       []PortMap `json:"ports"`
	Directory   string    `json:"directory"`
	Version     int       `json:"version"`
	ClientAuth  bool      `json:"client_auth"`
	MaxStreams  int       `json:"max_streams"`
	CreatedAt   time.Time `json:"created_at"`
}

// PortMap represents port mapping for hidden services
type PortMap struct {
	VirtualPort int    `json:"virtual_port"`
	TargetHost  string `json:"target_host"`
	TargetPort  int    `json:"target_port"`
}

// TorClient represents a Tor SOCKS proxy client
type TorClient struct {
	proxyAddr string
	transport *http.Transport
}

// NewTorManager creates a new Tor manager
func NewTorManager(config TorConfig) *TorManager {
	return &TorManager{
		config:         config,
		hiddenServices: make(map[string]*HiddenService),
		dataDir:        config.DataDirectory,
	}
}

// Start initializes and starts the Tor manager
func (tm *TorManager) Start(ctx context.Context) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	if tm.running {
		return fmt.Errorf("tor manager already running")
	}

	// Create data directory
	if err := os.MkdirAll(tm.dataDir, 0700); err != nil {
		return fmt.Errorf("failed to create tor data directory: %v", err)
	}

	// Start Tor daemon if not already running
	if err := tm.startTorDaemon(ctx); err != nil {
		return fmt.Errorf("failed to start tor daemon: %v", err)
	}

	// Connect to Tor control port
	if err := tm.connectToControl(); err != nil {
		return fmt.Errorf("failed to connect to tor control: %v", err)
	}

	// Authenticate with Tor control
	if err := tm.authenticateControl(); err != nil {
		return fmt.Errorf("failed to authenticate with tor control: %v", err)
	}

	tm.running = true
	log.Println("Tor manager started successfully")

	return nil
}

// Stop shuts down the Tor manager
func (tm *TorManager) Stop() error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	if !tm.running {
		return nil
	}

	// Close control connection
	if tm.controlConn != nil {
		tm.controlConn.Close()
	}

	// Stop Tor process if we started it
	if tm.torProcess != nil {
		if err := tm.torProcess.Process.Kill(); err != nil {
			log.Printf("Failed to kill tor process: %v", err)
		}
		tm.torProcess.Wait()
	}

	tm.running = false
	log.Println("Tor manager stopped")

	return nil
}

// startTorDaemon starts the Tor daemon with appropriate configuration
func (tm *TorManager) startTorDaemon(ctx context.Context) error {
	// Check if Tor is already running
	if tm.isTorRunning() {
		log.Println("Tor daemon already running, using existing instance")
		return nil
	}

	// Generate Tor configuration
	torrcPath := filepath.Join(tm.dataDir, "torrc")
	if err := tm.generateTorrc(torrcPath); err != nil {
		return fmt.Errorf("failed to generate torrc: %v", err)
	}

	// Start Tor daemon
	cmd := exec.CommandContext(ctx, "tor", "-f", torrcPath)
	cmd.Dir = tm.dataDir

	// Set up logging
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start tor: %v", err)
	}

	tm.torProcess = cmd

	// Monitor Tor output
	go tm.monitorTorOutput(stdout, "STDOUT")
	go tm.monitorTorOutput(stderr, "STDERR")

	// Wait for Tor to be ready
	if err := tm.waitForTorReady(); err != nil {
		return fmt.Errorf("tor failed to start: %v", err)
	}

	log.Println("Tor daemon started successfully")
	return nil
}

// isTorRunning checks if Tor is already running on the control port
func (tm *TorManager) isTorRunning() bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", tm.config.ControlPort), 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// generateTorrc generates a Tor configuration file
func (tm *TorManager) generateTorrc(path string) error {
	config := fmt.Sprintf(`# Ephemeral Messenger Tor Configuration
DataDirectory %s
ControlPort %d
SOCKSPort %d
Log %s file %s
CookieAuthentication 1
HashedControlPassword %s

# Circuit settings
CircuitBuildTimeout %d
MaxCircuitDirtiness 600
NewCircuitPeriod 30

# Security settings
ExcludeExitNodes {??}
StrictNodes %d
LearnCircuitBuildTimeout 0
PathsNeededToBuildCircuits 0.25

# Hidden service directory
HiddenServiceDir %s
`,
		tm.dataDir,
		tm.config.ControlPort,
		tm.config.SOCKSPort,
		tm.config.LogLevel,
		filepath.Join(tm.dataDir, "tor.log"),
		tm.hashControlPassword(),
		tm.config.CircuitTimeout,
		boolToInt(tm.config.StrictNodes),
		tm.config.HiddenServiceDir,
	)

	// Add bridge configuration if enabled
	if tm.config.BridgeMode {
		config += "UseBridges 1\n"
		for _, bridge := range tm.config.Bridges {
			config += fmt.Sprintf("Bridge %s\n", bridge)
		}
	}

	// Add entry/exit nodes if specified
	if len(tm.config.EntryNodes) > 0 {
		config += fmt.Sprintf("EntryNodes %s\n", strings.Join(tm.config.EntryNodes, ","))
	}
	if len(tm.config.ExitNodes) > 0 {
		config += fmt.Sprintf("ExitNodes %s\n", strings.Join(tm.config.ExitNodes, ","))
	}

	return ioutil.WriteFile(path, []byte(config), 0600)
}

// hashControlPassword creates a hashed control password
func (tm *TorManager) hashControlPassword() string {
	if tm.config.ControlPassword == "" {
		return ""
	}

	// Generate salt
	salt := make([]byte, 8)
	rand.Read(salt)

	// Hash password with salt (simplified - in production use proper Tor password hashing)
	hash := sha256.Sum256([]byte(tm.config.ControlPassword + string(salt)))

	return fmt.Sprintf("16:%s%s", hex.EncodeToString(salt), hex.EncodeToString(hash[:]))
}

// waitForTorReady waits for Tor to be ready to accept connections
func (tm *TorManager) waitForTorReady() error {
	maxAttempts := 30
	for i := 0; i < maxAttempts; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", tm.config.ControlPort), 2*time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("tor failed to start within timeout")
}

// monitorTorOutput monitors Tor daemon output
func (tm *TorManager) monitorTorOutput(reader io.Reader, prefix string) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		log.Printf("[TOR-%s] %s", prefix, line)
	}
}

// connectToControl establishes connection to Tor control port
func (tm *TorManager) connectToControl() error {
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tm.config.ControlPort))
	if err != nil {
		return fmt.Errorf("failed to connect to tor control port: %v", err)
	}

	tm.controlConn = conn
	return nil
}

// authenticateControl authenticates with Tor control port
func (tm *TorManager) authenticateControl() error {
	if tm.controlConn == nil {
		return fmt.Errorf("no control connection")
	}

	// Try cookie authentication first
	cookiePath := filepath.Join(tm.dataDir, "control_auth_cookie")
	if cookie, err := ioutil.ReadFile(cookiePath); err == nil {
		auth := fmt.Sprintf("AUTHENTICATE %s\r\n", hex.EncodeToString(cookie))
		if _, err := tm.controlConn.Write([]byte(auth)); err != nil {
			return err
		}
	} else if tm.config.ControlPassword != "" {
		// Fall back to password authentication
		auth := fmt.Sprintf("AUTHENTICATE \"%s\"\r\n", tm.config.ControlPassword)
		if _, err := tm.controlConn.Write([]byte(auth)); err != nil {
			return err
		}
	} else {
		// Try null authentication
		if _, err := tm.controlConn.Write([]byte("AUTHENTICATE\r\n")); err != nil {
			return err
		}
	}

	// Read authentication response
	response := make([]byte, 1024)
	n, err := tm.controlConn.Read(response)
	if err != nil {
		return err
	}

	if !strings.Contains(string(response[:n]), "250 OK") {
		return fmt.Errorf("authentication failed: %s", string(response[:n]))
	}

	return nil
}

// CreateHiddenService creates a new Tor hidden service
func (tm *TorManager) CreateHiddenService(name string, ports []PortMap, version int) (*HiddenService, error) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	if !tm.running {
		return nil, fmt.Errorf("tor manager not running")
	}

	// Generate Ed25519 key pair for v3 hidden service
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate hidden service keys: %v", err)
	}

	// Calculate onion address
	onionAddr := tm.calculateOnionAddress(publicKey, version)

	// Create hidden service directory
	hsDir := filepath.Join(tm.config.HiddenServiceDir, name)
	if err := os.MkdirAll(hsDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create hidden service directory: %v", err)
	}

	// Save private key
	privateKeyPEM := &pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: privateKey.Seed(),
	}
	privateKeyPath := filepath.Join(hsDir, "hs_ed25519_secret_key")
	if err := ioutil.WriteFile(privateKeyPath, pem.EncodeToMemory(privateKeyPEM), 0600); err != nil {
		return nil, fmt.Errorf("failed to save private key: %v", err)
	}

	// Create hidden service
	hs := &HiddenService{
		Name:       name,
		OnionAddr:  onionAddr,
		PrivateKey: base64.StdEncoding.EncodeToString(privateKey.Seed()),
		PublicKey:  base64.StdEncoding.EncodeToString(publicKey),
		Ports:      ports,
		Directory:  hsDir,
		Version:    version,
		CreatedAt:  time.Now(),
	}

	// Configure hidden service via control port
	if err := tm.configureHiddenService(hs); err != nil {
		return nil, fmt.Errorf("failed to configure hidden service: %v", err)
	}

	tm.hiddenServices[name] = hs

	log.Printf("Hidden service '%s' created: %s.onion", name, onionAddr)

	return hs, nil
}

// calculateOnionAddress calculates the .onion address for a public key
func (tm *TorManager) calculateOnionAddress(publicKey ed25519.PublicKey, version int) string {
	if version == 3 {
		// v3 onion address calculation
		checksum := sha256.Sum256(append([]byte(".onion checksum"), publicKey...))
		onionBytes := append(publicKey, checksum[:2]...)
		onionBytes = append(onionBytes, 0x03) // version byte

		return strings.ToLower(base32.StdEncoding.EncodeToString(onionBytes))
	}

	// Default to v3 if unsupported version
	return tm.calculateOnionAddress(publicKey, 3)
}

// configureHiddenService configures hidden service via Tor control port
func (tm *TorManager) configureHiddenService(hs *HiddenService) error {
	if tm.controlConn == nil {
		return fmt.Errorf("no control connection")
	}

	// Add hidden service to Tor
	commands := []string{
		fmt.Sprintf("ADD_ONION ED25519-V3:%s", hs.PrivateKey),
	}

	for _, port := range hs.Ports {
		commands = append(commands, fmt.Sprintf("Port=%d,%s:%d", port.VirtualPort, port.TargetHost, port.TargetPort))
	}

	for _, cmd := range commands {
		if _, err := tm.controlConn.Write([]byte(cmd + "\r\n")); err != nil {
			return err
		}

		// Read response
		response := make([]byte, 1024)
		n, err := tm.controlConn.Read(response)
		if err != nil {
			return err
		}

		if !strings.Contains(string(response[:n]), "250") {
			return fmt.Errorf("command failed: %s - %s", cmd, string(response[:n]))
		}
	}

	return nil
}

// GetHiddenService retrieves a hidden service by name
func (tm *TorManager) GetHiddenService(name string) (*HiddenService, bool) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	hs, exists := tm.hiddenServices[name]
	return hs, exists
}

// ListHiddenServices returns all configured hidden services
func (tm *TorManager) ListHiddenServices() []*HiddenService {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	services := make([]*HiddenService, 0, len(tm.hiddenServices))
	for _, hs := range tm.hiddenServices {
		services = append(services, hs)
	}

	return services
}

// NewTorClient creates a new Tor SOCKS client
func NewTorClient(socksAddr string) *TorClient {
	transport := &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			return net.Dial("tcp", socksAddr)
		},
		DisableKeepAlives: true,
	}

	return &TorClient{
		proxyAddr: socksAddr,
		transport: transport,
	}
}

// DialTor creates a connection through Tor SOCKS proxy
func (tc *TorClient) DialTor(network, addr string) (net.Conn, error) {
	socksConn, err := net.Dial("tcp", tc.proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to tor socks: %v", err)
	}

	// SOCKS5 handshake
	if err := tc.socks5Handshake(socksConn, addr); err != nil {
		socksConn.Close()
		return nil, fmt.Errorf("socks5 handshake failed: %v", err)
	}

	return socksConn, nil
}

// socks5Handshake performs SOCKS5 handshake
func (tc *TorClient) socks5Handshake(conn net.Conn, addr string) error {
	// Initial handshake
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}

	response := make([]byte, 2)
	if _, err := conn.Read(response); err != nil {
		return err
	}

	if response[0] != 0x05 || response[1] != 0x00 {
		return fmt.Errorf("invalid socks5 response: %v", response)
	}

	// Connection request
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}

	request := []byte{0x05, 0x01, 0x00, 0x03}
	request = append(request, byte(len(host)))
	request = append(request, []byte(host)...)
	request = append(request, byte(port>>8), byte(port&0xff))

	if _, err := conn.Write(request); err != nil {
		return err
	}

	// Read response
	if _, err := conn.Read(response); err != nil {
		return err
	}

	if response[0] != 0x05 || response[1] != 0x00 {
		return fmt.Errorf("socks5 connection failed: %v", response)
	}

	// Read remaining response
	remaining := make([]byte, 6)
	if _, err := conn.Read(remaining); err != nil {
		return err
	}

	return nil
}

// GetTorStatus returns the current status of Tor
func (tm *TorManager) GetTorStatus() map[string]interface{} {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	return map[string]interface{}{
		"running":         tm.running,
		"control_port":    tm.config.ControlPort,
		"socks_port":      tm.config.SOCKSPort,
		"data_directory":  tm.dataDir,
		"hidden_services": len(tm.hiddenServices),
		"bridge_mode":     tm.config.BridgeMode,
	}
}

// Helper functions

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}