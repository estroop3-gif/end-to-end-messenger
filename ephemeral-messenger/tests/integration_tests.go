// Integration Tests for Ephemeral Messenger
// Tests end-to-end messaging flows, Tor integration, and security features

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test configuration
const (
	TestServerPort   = "18443"
	TestServerURL    = "http://localhost:" + TestServerPort
	TestWSURL        = "ws://localhost:" + TestServerPort + "/ws"
	TestTimeout      = 30 * time.Second
	MessageWaitTime  = 5 * time.Second
)

// Test fixtures
type TestMessage struct {
	ID           string    `json:"id"`
	From         string    `json:"from"`
	To           string    `json:"to"`
	Content      string    `json:"content"`
	Timestamp    time.Time `json:"timestamp"`
	ExpiresAt    time.Time `json:"expires_at"`
	DeliveryType string    `json:"delivery_type"`
}

type TestClient struct {
	ID          string
	Fingerprint string
	Conn        *websocket.Conn
	Messages    chan TestMessage
	Errors      chan error
	mutex       sync.RWMutex
}

type IntegrationTestSuite struct {
	server     *http.Server
	clients    map[string]*TestClient
	serverURL  string
	wsURL      string
	ctx        context.Context
	cancel     context.CancelFunc
}

// SetupTestSuite initializes the test environment
func SetupTestSuite(t *testing.T) *IntegrationTestSuite {
	ctx, cancel := context.WithCancel(context.Background())

	suite := &IntegrationTestSuite{
		clients:   make(map[string]*TestClient),
		serverURL: TestServerURL,
		wsURL:     TestWSURL,
		ctx:       ctx,
		cancel:    cancel,
	}

	// Start test server (assuming main server can be started programmatically)
	go func() {
		// This would start the actual server
		// For now, assume server is running externally
	}()

	// Wait for server to be ready
	suite.waitForServer(t)

	return suite
}

// TeardownTestSuite cleans up the test environment
func (suite *IntegrationTestSuite) TeardownTestSuite(t *testing.T) {
	// Close all client connections
	for _, client := range suite.clients {
		suite.closeClient(client)
	}

	suite.cancel()

	// Stop server if we started it
	if suite.server != nil {
		suite.server.Shutdown(suite.ctx)
	}
}

// waitForServer waits for the server to be ready
func (suite *IntegrationTestSuite) waitForServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(suite.ctx, TestTimeout)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			t.Fatal("Server did not start within timeout")
		default:
			resp, err := http.Get(suite.serverURL + "/health")
			if err == nil && resp.StatusCode == 200 {
				resp.Body.Close()
				return
			}
			if resp != nil {
				resp.Body.Close()
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
}

// createTestClient creates a new test client
func (suite *IntegrationTestSuite) createTestClient(t *testing.T, fingerprint string) *TestClient {
	wsURL, err := url.Parse(suite.wsURL)
	require.NoError(t, err)

	query := wsURL.Query()
	query.Set("fingerprint", fingerprint)
	wsURL.RawQuery = query.Encode()

	dialer := websocket.DefaultDialer
	dialer.HandshakeTimeout = TestTimeout

	conn, _, err := dialer.Dial(wsURL.String(), nil)
	require.NoError(t, err, "Failed to connect WebSocket")

	client := &TestClient{
		ID:          generateClientID(),
		Fingerprint: fingerprint,
		Conn:        conn,
		Messages:    make(chan TestMessage, 100),
		Errors:      make(chan error, 10),
	}

	// Start message reader
	go suite.clientMessageReader(client)

	suite.clients[client.ID] = client
	return client
}

// closeClient closes a test client connection
func (suite *IntegrationTestSuite) closeClient(client *TestClient) {
	client.mutex.Lock()
	defer client.mutex.Unlock()

	if client.Conn != nil {
		client.Conn.Close()
		client.Conn = nil
	}

	close(client.Messages)
	close(client.Errors)
}

// clientMessageReader reads messages from WebSocket
func (suite *IntegrationTestSuite) clientMessageReader(client *TestClient) {
	defer suite.closeClient(client)

	for {
		var message TestMessage
		err := client.Conn.ReadJSON(&message)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				client.Errors <- fmt.Errorf("WebSocket error: %v", err)
			}
			return
		}

		select {
		case client.Messages <- message:
		case <-suite.ctx.Done():
			return
		default:
			// Channel full, drop message
		}
	}
}

// sendMessage sends a message through the client
func (suite *IntegrationTestSuite) sendMessage(t *testing.T, client *TestClient, to, content string) {
	message := TestMessage{
		To:      to,
		Content: content,
	}

	client.mutex.RLock()
	conn := client.Conn
	client.mutex.RUnlock()

	require.NotNil(t, conn, "Client connection is closed")

	err := conn.WriteJSON(message)
	require.NoError(t, err, "Failed to send message")
}

// waitForMessage waits for a message to be received
func (suite *IntegrationTestSuite) waitForMessage(t *testing.T, client *TestClient, timeout time.Duration) TestMessage {
	select {
	case message := <-client.Messages:
		return message
	case err := <-client.Errors:
		t.Fatalf("Client error while waiting for message: %v", err)
	case <-time.After(timeout):
		t.Fatal("Timeout waiting for message")
	}
	return TestMessage{}
}

// TestBasicMessaging tests basic message sending and receiving
func TestBasicMessaging(t *testing.T) {
	suite := SetupTestSuite(t)
	defer suite.TeardownTestSuite(t)

	// Create two clients
	alice := suite.createTestClient(t, "alice_fingerprint_001")
	bob := suite.createTestClient(t, "bob_fingerprint_002")

	// Alice sends message to Bob
	testContent := "Hello Bob, this is Alice!"
	suite.sendMessage(t, alice, bob.Fingerprint, testContent)

	// Bob should receive the message
	receivedMessage := suite.waitForMessage(t, bob, MessageWaitTime)

	assert.Equal(t, alice.Fingerprint, receivedMessage.From, "Message from field incorrect")
	assert.Equal(t, bob.Fingerprint, receivedMessage.To, "Message to field incorrect")
	assert.Equal(t, testContent, receivedMessage.Content, "Message content incorrect")
	assert.NotEmpty(t, receivedMessage.ID, "Message ID should not be empty")
	assert.False(t, receivedMessage.Timestamp.IsZero(), "Message timestamp should be set")
}

// TestMessageDeliveryConfirmation tests delivery confirmations
func TestMessageDeliveryConfirmation(t *testing.T) {
	suite := SetupTestSuite(t)
	defer suite.TeardownTestSuite(t)

	alice := suite.createTestClient(t, "alice_confirmation_001")
	bob := suite.createTestClient(t, "bob_confirmation_002")

	// Alice sends message to Bob
	suite.sendMessage(t, alice, bob.Fingerprint, "Test confirmation")

	// Alice should receive delivery confirmation
	confirmation := suite.waitForMessage(t, alice, MessageWaitTime)

	assert.Equal(t, "server", confirmation.From, "Confirmation should come from server")
	assert.Contains(t, confirmation.Content, "delivery_status", "Should contain delivery status")

	// Parse confirmation content
	var confirmationData map[string]interface{}
	err := json.Unmarshal([]byte(confirmation.Content), &confirmationData)
	require.NoError(t, err, "Confirmation content should be valid JSON")

	assert.Equal(t, "delivery_status", confirmationData["type"], "Confirmation type incorrect")
	assert.NotNil(t, confirmationData["delivered"], "Confirmation should indicate delivery status")
}

// TestMessagePersistence tests temporary message persistence
func TestMessagePersistence(t *testing.T) {
	suite := SetupTestSuite(t)
	defer suite.TeardownTestSuite(t)

	alice := suite.createTestClient(t, "alice_persistence_001")

	// Send message to offline recipient
	suite.sendMessage(t, alice, "offline_recipient_001", "Message for offline user")

	// Wait a moment
	time.Sleep(2 * time.Second)

	// Create the recipient client
	bob := suite.createTestClient(t, "offline_recipient_001")

	// Bob should receive the pending message
	pendingMessage := suite.waitForMessage(t, bob, MessageWaitTime)

	assert.Equal(t, alice.Fingerprint, pendingMessage.From, "Pending message from field incorrect")
	assert.Equal(t, "Message for offline user", pendingMessage.Content, "Pending message content incorrect")
}

// TestMultipleClients tests multiple clients with same fingerprint
func TestMultipleClients(t *testing.T) {
	suite := SetupTestSuite(t)
	defer suite.TeardownTestSuite(t)

	fingerprint := "multi_client_001"

	// Create first client
	client1 := suite.createTestClient(t, fingerprint)

	// Create second client with same fingerprint (should replace first)
	client2 := suite.createTestClient(t, fingerprint)

	// Send message from another client
	sender := suite.createTestClient(t, "sender_001")
	suite.sendMessage(t, sender, fingerprint, "Test multiple clients")

	// Only client2 should receive the message
	receivedMessage := suite.waitForMessage(t, client2, MessageWaitTime)
	assert.Equal(t, "Test multiple clients", receivedMessage.Content)

	// client1 should not receive anything (connection should be closed)
	select {
	case <-client1.Messages:
		t.Error("Client1 should not receive messages after being replaced")
	case <-time.After(2 * time.Second):
		// Expected - no message received
	}
}

// TestRateLimiting tests rate limiting functionality
func TestRateLimiting(t *testing.T) {
	suite := SetupTestSuite(t)
	defer suite.TeardownTestSuite(t)

	alice := suite.createTestClient(t, "alice_ratelimit_001")
	bob := suite.createTestClient(t, "bob_ratelimit_002")

	// Send many messages rapidly
	messageCount := 150 // Exceed rate limit
	for i := 0; i < messageCount; i++ {
		suite.sendMessage(t, alice, bob.Fingerprint, fmt.Sprintf("Rapid message %d", i))
	}

	// Count received messages
	receivedCount := 0
	timeout := time.After(5 * time.Second)

	for {
		select {
		case <-bob.Messages:
			receivedCount++
		case <-timeout:
			goto countComplete
		}
	}

countComplete:
	// Should receive fewer messages due to rate limiting
	assert.Less(t, receivedCount, messageCount, "Rate limiting should reduce message count")
	assert.Greater(t, receivedCount, 0, "Should receive some messages")
}

// TestHealthEndpoint tests the health check endpoint
func TestHealthEndpoint(t *testing.T) {
	suite := SetupTestSuite(t)
	defer suite.TeardownTestSuite(t)

	resp, err := http.Get(suite.serverURL + "/health")
	require.NoError(t, err, "Health check request failed")
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "Health check should return 200")

	var healthData map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&healthData)
	require.NoError(t, err, "Health response should be valid JSON")

	assert.Equal(t, "healthy", healthData["status"], "Health status should be healthy")
	assert.NotNil(t, healthData["timestamp"], "Health response should include timestamp")
}

// TestStatsEndpoint tests the statistics endpoint
func TestStatsEndpoint(t *testing.T) {
	suite := SetupTestSuite(t)
	defer suite.TeardownTestSuite(t)

	// Create some clients first
	suite.createTestClient(t, "stats_client_001")
	suite.createTestClient(t, "stats_client_002")

	resp, err := http.Get(suite.serverURL + "/stats")
	require.NoError(t, err, "Stats request failed")
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "Stats should return 200")

	var statsData map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&statsData)
	require.NoError(t, err, "Stats response should be valid JSON")

	assert.NotNil(t, statsData["server"], "Stats should include server info")
	assert.NotNil(t, statsData["clients"], "Stats should include client info")
}

// TestTorStatusEndpoint tests Tor status endpoint
func TestTorStatusEndpoint(t *testing.T) {
	suite := SetupTestSuite(t)
	defer suite.TeardownTestSuite(t)

	resp, err := http.Get(suite.serverURL + "/tor/status")
	if err != nil {
		t.Skip("Tor endpoints not available - skipping Tor tests")
		return
	}
	defer resp.Body.Close()

	// Accept both 200 (Tor available) and 503 (Tor not available)
	if resp.StatusCode == http.StatusServiceUnavailable {
		t.Skip("Tor not available for testing")
		return
	}

	assert.Equal(t, http.StatusOK, resp.StatusCode, "Tor status should return 200 if available")

	var torData map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&torData)
	require.NoError(t, err, "Tor response should be valid JSON")

	assert.NotNil(t, torData["connected"], "Tor status should include connection state")
	assert.NotNil(t, torData["socks_port"], "Tor status should include SOCKS port")
}

// TestCORSHeaders tests CORS header configuration
func TestCORSHeaders(t *testing.T) {
	suite := SetupTestSuite(t)
	defer suite.TeardownTestSuite(t)

	req, err := http.NewRequest("OPTIONS", suite.serverURL+"/health", nil)
	require.NoError(t, err)

	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "GET")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Check CORS headers
	assert.NotEmpty(t, resp.Header.Get("Access-Control-Allow-Origin"), "Should have CORS origin header")
	assert.NotEmpty(t, resp.Header.Get("Access-Control-Allow-Methods"), "Should have CORS methods header")
}

// TestSecurityHeaders tests security header configuration
func TestSecurityHeaders(t *testing.T) {
	suite := SetupTestSuite(t)
	defer suite.TeardownTestSuite(t)

	resp, err := http.Get(suite.serverURL + "/health")
	require.NoError(t, err)
	defer resp.Body.Close()

	securityHeaders := []string{
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-XSS-Protection",
		"Strict-Transport-Security",
		"Content-Security-Policy",
	}

	for _, header := range securityHeaders {
		assert.NotEmpty(t, resp.Header.Get(header), "Should have security header: "+header)
	}
}

// TestWebSocketUpgrade tests WebSocket upgrade handling
func TestWebSocketUpgrade(t *testing.T) {
	suite := SetupTestSuite(t)
	defer suite.TeardownTestSuite(t)

	// Test WebSocket connection without fingerprint
	wsURL := suite.wsURL // No fingerprint parameter

	dialer := websocket.DefaultDialer
	_, resp, err := dialer.Dial(wsURL, nil)

	// Should fail without fingerprint
	assert.Error(t, err, "WebSocket connection should fail without fingerprint")
	if resp != nil {
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "Should return 400 for missing fingerprint")
		resp.Body.Close()
	}
}

// TestConcurrentConnections tests handling of many concurrent connections
func TestConcurrentConnections(t *testing.T) {
	suite := SetupTestSuite(t)
	defer suite.TeardownTestSuite(t)

	const clientCount = 20
	var wg sync.WaitGroup
	clients := make([]*TestClient, clientCount)

	// Create clients concurrently
	wg.Add(clientCount)
	for i := 0; i < clientCount; i++ {
		go func(index int) {
			defer wg.Done()
			clients[index] = suite.createTestClient(t, fmt.Sprintf("concurrent_client_%03d", index))
		}(i)
	}

	wg.Wait()

	// Verify all clients connected
	for i, client := range clients {
		assert.NotNil(t, client, "Client %d should be created", i)
		assert.NotNil(t, client.Conn, "Client %d should have connection", i)
	}

	// Send message from first client to all others
	sender := clients[0]
	testMessage := "Broadcast test message"

	for i := 1; i < clientCount; i++ {
		suite.sendMessage(t, sender, clients[i].Fingerprint, testMessage)
	}

	// Verify all recipients receive the message
	for i := 1; i < clientCount; i++ {
		receivedMessage := suite.waitForMessage(t, clients[i], MessageWaitTime)
		assert.Equal(t, testMessage, receivedMessage.Content, "Client %d should receive message", i)
	}
}

// TestMessageExpiration tests message expiration functionality
func TestMessageExpiration(t *testing.T) {
	suite := SetupTestSuite(t)
	defer suite.TeardownTestSuite(t)

	alice := suite.createTestClient(t, "alice_expiration_001")

	// Send message to offline recipient
	suite.sendMessage(t, alice, "offline_expiration_001", "This message should expire")

	// Wait longer than message TTL (if TTL is short)
	// Note: This test assumes message TTL can be configured for testing
	time.Sleep(2 * time.Second)

	// Create recipient after expiration
	bob := suite.createTestClient(t, "offline_expiration_001")

	// Bob should not receive expired message
	select {
	case <-bob.Messages:
		t.Error("Should not receive expired message")
	case <-time.After(3 * time.Second):
		// Expected - no message received
	}
}

// Helper functions

func generateClientID() string {
	return fmt.Sprintf("client_%d_%d", time.Now().UnixNano(), os.Getpid())
}

// TestMain runs the test suite
func TestMain(m *testing.M) {
	// Setup
	fmt.Println("Starting Ephemeral Messenger Integration Tests")
	fmt.Println("==============================================")

	// Check if server is running
	resp, err := http.Get(TestServerURL + "/health")
	if err != nil {
		fmt.Printf("Server not running on %s - please start server first\n", TestServerURL)
		fmt.Println("Run: go run . &")
		os.Exit(1)
	}
	resp.Body.Close()

	// Run tests
	code := m.Run()

	// Cleanup
	fmt.Println("\nIntegration tests completed")

	os.Exit(code)
}

// Benchmark tests

func BenchmarkMessageThroughput(b *testing.B) {
	suite := SetupTestSuite(&testing.T{})
	defer suite.TeardownTestSuite(&testing.T{})

	alice := suite.createTestClient(&testing.T{}, "bench_alice")
	bob := suite.createTestClient(&testing.T{}, "bench_bob")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		suite.sendMessage(&testing.T{}, alice, bob.Fingerprint, fmt.Sprintf("Benchmark message %d", i))
	}
}

func BenchmarkConcurrentClients(b *testing.B) {
	suite := SetupTestSuite(&testing.T{})
	defer suite.TeardownTestSuite(&testing.T{})

	const clientCount = 100

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		wg.Add(clientCount)

		for j := 0; j < clientCount; j++ {
			go func(index int) {
				defer wg.Done()
				client := suite.createTestClient(&testing.T{}, fmt.Sprintf("bench_client_%d_%d", i, index))
				suite.closeClient(client)
			}(j)
		}

		wg.Wait()
	}
}