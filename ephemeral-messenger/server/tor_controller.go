package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"net"
	"strings"
	"time"
)

// TorController manages Tor control port connections
type TorController struct {
	conn     net.Conn
	onionAddr string
	serviceID string
}

// NewTorController creates a new Tor controller connection
func NewTorController(controlPort string) (*TorController, error) {
	conn, err := net.Dial("tcp", controlPort)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Tor control port: %w", err)
	}

	tc := &TorController{conn: conn}

	// Authenticate with Tor (assumes cookie auth or no auth for simplicity)
	if err := tc.authenticate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to authenticate with Tor: %w", err)
	}

	return tc, nil
}

// authenticate performs authentication with Tor control port
func (tc *TorController) authenticate() error {
	// Try AUTHENTICATE command (assumes cookie auth or no password)
	if err := tc.sendCommand("AUTHENTICATE"); err != nil {
		return err
	}

	response, err := tc.readResponse()
	if err != nil {
		return err
	}

	if !strings.HasPrefix(response, "250") {
		return fmt.Errorf("authentication failed: %s", response)
	}

	return nil
}

// CreateEphemeralOnion creates an ephemeral v3 onion service
func (tc *TorController) CreateEphemeralOnion() (string, error) {
	// Generate a random service ID for this session
	serviceIDBytes := make([]byte, 10)
	if _, err := rand.Read(serviceIDBytes); err != nil {
		return "", fmt.Errorf("failed to generate service ID: %w", err)
	}
	tc.serviceID = base32.StdEncoding.EncodeToString(serviceIDBytes)

	// Create ephemeral hidden service
	// Port 80 maps to our HTTP server on 8080
	cmd := fmt.Sprintf("ADD_ONION NEW:ED25519-V3 Port=80,127.0.0.1:8080 Flags=Detach")
	if err := tc.sendCommand(cmd); err != nil {
		return "", err
	}

	response, err := tc.readResponse()
	if err != nil {
		return "", err
	}

	if !strings.HasPrefix(response, "250") {
		return "", fmt.Errorf("failed to create onion service: %s", response)
	}

	// Parse the onion address from response
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		if strings.Contains(line, "ServiceID=") {
			parts := strings.Split(line, "ServiceID=")
			if len(parts) > 1 {
				tc.onionAddr = strings.TrimSpace(parts[1]) + ".onion"
				break
			}
		}
	}

	if tc.onionAddr == "" {
		return "", fmt.Errorf("failed to parse onion address from response")
	}

	return tc.onionAddr, nil
}

// CreateOnionWithClientAuth creates an onion service with client authorization
func (tc *TorController) CreateOnionWithClientAuth(clientPubKey string) (string, error) {
	// Generate service ID
	serviceIDBytes := make([]byte, 10)
	if _, err := rand.Read(serviceIDBytes); err != nil {
		return "", fmt.Errorf("failed to generate service ID: %w", err)
	}
	tc.serviceID = base32.StdEncoding.EncodeToString(serviceIDBytes)

	// Create onion service with client authorization
	cmd := fmt.Sprintf("ADD_ONION NEW:ED25519-V3 Port=80,127.0.0.1:8080 ClientAuth=%s Flags=Detach", clientPubKey)
	if err := tc.sendCommand(cmd); err != nil {
		return "", err
	}

	response, err := tc.readResponse()
	if err != nil {
		return "", err
	}

	if !strings.HasPrefix(response, "250") {
		return "", fmt.Errorf("failed to create onion service with client auth: %s", response)
	}

	// Parse the onion address
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		if strings.Contains(line, "ServiceID=") {
			parts := strings.Split(line, "ServiceID=")
			if len(parts) > 1 {
				tc.onionAddr = strings.TrimSpace(parts[1]) + ".onion"
				break
			}
		}
	}

	return tc.onionAddr, nil
}

// DeleteOnion removes the ephemeral onion service
func (tc *TorController) DeleteOnion() error {
	if tc.onionAddr == "" {
		return nil // Nothing to delete
	}

	// Extract service ID from onion address
	serviceID := strings.TrimSuffix(tc.onionAddr, ".onion")
	cmd := fmt.Sprintf("DEL_ONION %s", serviceID)

	if err := tc.sendCommand(cmd); err != nil {
		return err
	}

	response, err := tc.readResponse()
	if err != nil {
		return err
	}

	if !strings.HasPrefix(response, "250") {
		return fmt.Errorf("failed to delete onion service: %s", response)
	}

	tc.onionAddr = ""
	return nil
}

// GetOnionAddress returns the current onion address
func (tc *TorController) GetOnionAddress() string {
	return tc.onionAddr
}

// GetCircuitInfo gets information about Tor circuits
func (tc *TorController) GetCircuitInfo() (string, error) {
	if err := tc.sendCommand("GETINFO circuit-status"); err != nil {
		return "", err
	}

	response, err := tc.readResponse()
	if err != nil {
		return "", err
	}

	return response, nil
}

// CheckTorStatus verifies Tor is running and reachable
func (tc *TorController) CheckTorStatus() error {
	if err := tc.sendCommand("GETINFO status/circuit-established"); err != nil {
		return err
	}

	response, err := tc.readResponse()
	if err != nil {
		return err
	}

	if !strings.Contains(response, "status/circuit-established=1") {
		return fmt.Errorf("Tor circuits not established")
	}

	return nil
}

// sendCommand sends a command to the Tor control port
func (tc *TorController) sendCommand(cmd string) error {
	_, err := fmt.Fprintf(tc.conn, "%s\r\n", cmd)
	return err
}

// readResponse reads a response from the Tor control port
func (tc *TorController) readResponse() (string, error) {
	tc.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	scanner := bufio.NewScanner(tc.conn)

	var response strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		response.WriteString(line)
		response.WriteString("\n")

		// End of response when we get a line starting with "250 " or error codes
		if strings.HasPrefix(line, "250 ") ||
		   strings.HasPrefix(line, "451 ") ||
		   strings.HasPrefix(line, "500 ") ||
		   strings.HasPrefix(line, "510 ") ||
		   strings.HasPrefix(line, "550 ") {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return response.String(), nil
}

// Close closes the Tor controller connection
func (tc *TorController) Close() error {
	if tc.conn != nil {
		return tc.conn.Close()
	}
	return nil
}