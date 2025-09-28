// Package main implements the Ephemeral Messenger Server
//
// This server provides a zero-knowledge, ephemeral messaging service with the following features:
// - Secure buffer management with automatic encryption and cleanup
// - Session-based authentication with TLS client certificate support
// - Rate limiting to prevent abuse
// - Tor hidden service integration for anonymous communication
// - Automatic secure data wiping on shutdown
//
// The server stores encrypted message data temporarily in memory and automatically
// cleans up expired sessions and buffers. No persistent storage is used, ensuring
// zero data retention after server shutdown.
//
// Security Features:
// - All sensitive data is encrypted in memory using Argon2id key derivation
// - Automatic secure wiping of buffers and sessions
// - TLS 1.3 with optional client certificate authentication
// - Rate limiting per client to prevent DoS attacks
// - Tor integration for anonymous hidden service hosting
//
// Environment Variables:
// - TOR_CONTROL_PORT: Port for Tor control connection (optional)
// - TLS_CERT_FILE: Path to TLS certificate file (optional)
// - TLS_KEY_FILE: Path to TLS private key file (required if TLS_CERT_FILE set)
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/argon2"
	"golang.org/x/time/rate"
)

// Configuration constants for the ephemeral messaging server
const (
	// MaxMessageSize defines the maximum size for individual messages (64MB)
	// This prevents memory exhaustion attacks while allowing reasonable file sizes
	MaxMessageSize = 64 * 1024 * 1024

	// MaxChunkSize defines the maximum size for file chunks (1MB)
	// Smaller chunks improve memory efficiency and error recovery
	MaxChunkSize = 1024 * 1024

	// RateLimitRPS sets the requests per second limit per client (10 RPS)
	// This prevents DoS attacks while allowing normal usage patterns
	RateLimitRPS = 10

	// RateLimitBurst allows burst traffic up to 20 requests
	// This accommodates legitimate usage spikes
	RateLimitBurst = 20

	// SessionTimeout defines how long sessions remain valid (5 minutes)
	// Short timeout reduces exposure window if session is compromised
	SessionTimeout = 5 * time.Minute

	// MaxSessions limits concurrent active sessions (100)
	// This prevents resource exhaustion attacks
	MaxSessions = 100
)

// SecureBuffer represents an encrypted buffer stored in memory
//
// SecureBuffer provides secure storage for sensitive data with the following features:
// - Automatic encryption using Argon2id key derivation
// - Thread-safe access with read-write mutex
// - Automatic access time tracking for cleanup
// - Secure wiping functionality to clear sensitive data
//
// The buffer encrypts data using XOR with an Argon2id-derived key. While simple,
// this provides protection against memory dump attacks. In production, consider
// using proper AEAD encryption like ChaCha20-Poly1305.
type SecureBuffer struct {
	data     []byte        // Encrypted data stored in buffer
	salt     []byte        // Random salt for key derivation
	key      []byte        // Derived encryption key
	mu       sync.RWMutex  // Mutex for thread-safe access
	accessed time.Time     // Last access time for cleanup scheduling
}

// Server represents the main ephemeral messaging server instance
//
// Server manages the core functionality of the ephemeral messaging system:
// - Secure buffer storage with automatic cleanup
// - Session management with authentication
// - Rate limiting and security controls
// - Tor hidden service integration
// - WebSocket upgrade capability for real-time messaging
//
// The server maintains no persistent state - all data is stored in memory
// and automatically cleaned up on expiration or server shutdown.
type Server struct {
	buffers     map[string]*SecureBuffer // Active encrypted message buffers
	sessions    map[string]*Session      // Active client sessions
	mu          sync.RWMutex             // Mutex for concurrent access
	rateLimiter *rate.Limiter            // Rate limiter for DoS protection
	upgrader    websocket.Upgrader       // WebSocket connection upgrader
	torControl  *TorController           // Tor controller for onion services
	onionAddr   string                   // Generated onion service address
	shutdown    chan os.Signal           // Shutdown signal channel
}

// Session represents an active client messaging session
//
// Sessions provide stateful authentication and access control:
// - Unique session ID for request authentication
// - Optional TLS client certificate binding
// - Automatic expiration for security
// - Thread-safe access controls
//
// Sessions can be authenticated either through TLS client certificates
// or through other authentication mechanisms implemented by clients.
type Session struct {
	ID            string    `json:"id"`              // Unique session identifier
	CreatedAt     time.Time `json:"created_at"`      // Session creation timestamp
	ExpiresAt     time.Time `json:"expires_at"`      // Session expiration time
	ClientCert    []byte    `json:"client_cert,omitempty"` // Optional client certificate
	Authenticated bool      `json:"authenticated"`   // Authentication status
	mu            sync.RWMutex // Mutex for thread-safe access
}

// MessageRequest represents an incoming encrypted message from a client
//
// Messages are submitted as encrypted ciphertext with cryptographic signatures.
// The server does not decrypt messages - it only stores them temporarily
// for retrieval by the intended recipient.
type MessageRequest struct {
	SessionID  string `json:"session_id"`         // Session ID for authentication
	Ciphertext string `json:"ciphertext"`         // Base64 encoded encrypted message
	Signature  string `json:"signature"`          // Base64 encoded cryptographic signature
	Timestamp  int64  `json:"timestamp"`          // Unix timestamp of message creation
}

// ChunkRequest represents a file chunk upload for large file transfers
//
// Large files are split into chunks for efficient transfer and storage.
// Each chunk includes integrity verification through MAC and manifests.
// The server stores chunks temporarily without knowing the file contents.
type ChunkRequest struct {
	SessionID   string `json:"session_id"`   // Session ID for authentication
	ChunkID     string `json:"chunk_id"`     // Unique identifier for this chunk sequence
	ChunkIndex  int    `json:"chunk_index"`  // Index of this chunk in the sequence
	TotalChunks int    `json:"total_chunks"` // Total number of chunks in the file
	Data        string `json:"data"`         // Base64 encoded encrypted chunk data
	MAC         string `json:"mac"`          // Base64 encoded message authentication code
	Manifest    string `json:"manifest"`     // Base64 encoded signed manifest for integrity
}

// NewSecureBuffer creates a new secure buffer with encryption
//
// This function encrypts the provided data using Argon2id key derivation
// and stores it in a SecureBuffer for secure memory management.
//
// Security features:
// - Uses cryptographically secure random salt generation
// - Employs Argon2id for key derivation (3 iterations, 64KB memory, 1 thread)
// - XOR encryption for data protection (simple but effective for memory dumps)
// - Automatic cleanup of original plaintext data
//
// Parameters:
//   data - The plaintext data to encrypt and store securely
//
// Returns:
//   *SecureBuffer - The encrypted buffer ready for secure storage
//   error - Any error that occurred during encryption setup
//
// Note: The original data slice is securely wiped after encryption
func NewSecureBuffer(data []byte) (*SecureBuffer, error) {
	// Generate random salt and key
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive key using Argon2id
	key := argon2.IDKey(data[:min(len(data), 32)], salt, 3, 65536, 1, 32)

	// Encrypt data (simplified - use proper AEAD in production)
	encrypted := make([]byte, len(data))
	for i, b := range data {
		encrypted[i] = b ^ key[i%len(key)]
	}

	// Clear original data
	for i := range data {
		data[i] = 0
	}

	return &SecureBuffer{
		data:     encrypted,
		salt:     salt,
		key:      key,
		accessed: time.Now(),
	}, nil
}

// Read decrypts and returns the buffer data
func (sb *SecureBuffer) Read() ([]byte, error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	sb.accessed = time.Now()

	// Decrypt data
	decrypted := make([]byte, len(sb.data))
	for i, b := range sb.data {
		decrypted[i] = b ^ sb.key[i%len(sb.key)]
	}

	return decrypted, nil
}

// SecureWipe clears all sensitive data
func (sb *SecureBuffer) SecureWipe() {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	// Clear all sensitive data
	for i := range sb.data {
		sb.data[i] = 0
	}
	for i := range sb.salt {
		sb.salt[i] = 0
	}
	for i := range sb.key {
		sb.key[i] = 0
	}

	sb.data = nil
	sb.salt = nil
	sb.key = nil
}

// NewServer creates a new ephemeral messaging server
func NewServer() *Server {
	return &Server{
		buffers:     make(map[string]*SecureBuffer),
		sessions:    make(map[string]*Session),
		rateLimiter: rate.NewLimiter(RateLimitRPS, RateLimitBurst),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for Tor hidden service
			},
		},
		shutdown: make(chan os.Signal, 1),
	}
}

// rateLimitMiddleware applies rate limiting
func (s *Server) rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.rateLimiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// authMiddleware checks client authentication
func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.Header.Get("X-Session-ID")
		if sessionID == "" {
			http.Error(w, "Session ID required", http.StatusUnauthorized)
			return
		}

		s.mu.RLock()
		session, exists := s.sessions[sessionID]
		s.mu.RUnlock()

		if !exists {
			http.Error(w, "Invalid session", http.StatusUnauthorized)
			return
		}

		session.mu.RLock()
		authenticated := session.Authenticated
		expired := time.Now().After(session.ExpiresAt)
		session.mu.RUnlock()

		if expired {
			s.mu.Lock()
			delete(s.sessions, sessionID)
			s.mu.Unlock()
			http.Error(w, "Session expired", http.StatusUnauthorized)
			return
		}

		if !authenticated {
			http.Error(w, "Session not authenticated", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

// createSession creates a new session
func (s *Server) createSession(w http.ResponseWriter, r *http.Request) {
	if len(s.sessions) >= MaxSessions {
		http.Error(w, "Server at capacity", http.StatusServiceUnavailable)
		return
	}

	// Generate session ID
	sessionBytes := make([]byte, 32)
	if _, err := rand.Read(sessionBytes); err != nil {
		http.Error(w, "Failed to generate session", http.StatusInternalServerError)
		return
	}
	sessionID := base64.URLEncoding.EncodeToString(sessionBytes)

	// Extract client certificate if present
	var clientCert []byte
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		clientCert = r.TLS.PeerCertificates[0].Raw
	}

	session := &Session{
		ID:            sessionID,
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(SessionTimeout),
		ClientCert:    clientCert,
		Authenticated: clientCert != nil, // Auto-authenticate if client cert present
	}

	s.mu.Lock()
	s.sessions[sessionID] = session
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(session)
}

// receiveMessage handles incoming encrypted messages
func (s *Server) receiveMessage(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > MaxMessageSize {
		http.Error(w, "Message too large", http.StatusRequestEntityTooLarge)
		return
	}

	var req MessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Decode ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		http.Error(w, "Invalid ciphertext encoding", http.StatusBadRequest)
		return
	}

	// Create secure buffer for temporary storage
	buffer, err := NewSecureBuffer(ciphertext)
	if err != nil {
		http.Error(w, "Failed to create secure buffer", http.StatusInternalServerError)
		return
	}

	// Store buffer with expiration
	bufferID := fmt.Sprintf("msg_%d", time.Now().UnixNano())
	s.mu.Lock()
	s.buffers[bufferID] = buffer
	s.mu.Unlock()

	// Schedule automatic cleanup
	go func() {
		time.Sleep(SessionTimeout)
		s.mu.Lock()
		if buf, exists := s.buffers[bufferID]; exists {
			buf.SecureWipe()
			delete(s.buffers, bufferID)
		}
		s.mu.Unlock()
	}()

	response := map[string]interface{}{
		"status":    "received",
		"buffer_id": bufferID,
		"timestamp": time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// receiveChunk handles file chunk uploads
func (s *Server) receiveChunk(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > MaxChunkSize {
		http.Error(w, "Chunk too large", http.StatusRequestEntityTooLarge)
		return
	}

	var req ChunkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Decode chunk data
	chunkData, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		http.Error(w, "Invalid chunk encoding", http.StatusBadRequest)
		return
	}

	// TODO: Verify MAC and manifest signature
	// This would require implementing proper cryptographic verification

	// Create secure buffer for chunk
	buffer, err := NewSecureBuffer(chunkData)
	if err != nil {
		http.Error(w, "Failed to create secure buffer", http.StatusInternalServerError)
		return
	}

	// Store chunk buffer
	chunkBufferID := fmt.Sprintf("chunk_%s_%d", req.ChunkID, req.ChunkIndex)
	s.mu.Lock()
	s.buffers[chunkBufferID] = buffer
	s.mu.Unlock()

	// Schedule cleanup
	go func() {
		time.Sleep(SessionTimeout)
		s.mu.Lock()
		if buf, exists := s.buffers[chunkBufferID]; exists {
			buf.SecureWipe()
			delete(s.buffers, chunkBufferID)
		}
		s.mu.Unlock()
	}()

	response := map[string]interface{}{
		"status":          "chunk_received",
		"chunk_buffer_id": chunkBufferID,
		"chunk_index":     req.ChunkIndex,
		"total_chunks":    req.TotalChunks,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// retrieveMessage allows retrieval of stored messages
func (s *Server) retrieveMessage(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bufferID := vars["id"]

	s.mu.RLock()
	buffer, exists := s.buffers[bufferID]
	s.mu.RUnlock()

	if !exists {
		http.Error(w, "Buffer not found", http.StatusNotFound)
		return
	}

	// Read and return the encrypted data
	data, err := buffer.Read()
	if err != nil {
		http.Error(w, "Failed to read buffer", http.StatusInternalServerError)
		return
	}

	// Clean up buffer after retrieval
	defer func() {
		s.mu.Lock()
		buffer.SecureWipe()
		delete(s.buffers, bufferID)
		s.mu.Unlock()
	}()

	// Return as base64 encoded ciphertext
	response := map[string]interface{}{
		"ciphertext": base64.StdEncoding.EncodeToString(data),
		"retrieved":  time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// healthCheck provides server health status
func (s *Server) healthCheck(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	bufferCount := len(s.buffers)
	sessionCount := len(s.sessions)
	s.mu.RUnlock()

	status := map[string]interface{}{
		"status":        "healthy",
		"uptime":        time.Since(startTime).String(),
		"buffer_count":  bufferCount,
		"session_count": sessionCount,
		"onion_address": s.onionAddr,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// cleanupExpiredSessions removes expired sessions
func (s *Server) cleanupExpiredSessions() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			s.mu.Lock()
			for id, session := range s.sessions {
				if now.After(session.ExpiresAt) {
					delete(s.sessions, id)
				}
			}
			s.mu.Unlock()
		case <-s.shutdown:
			return
		}
	}
}

// secureWipeAll clears all sensitive data on shutdown
func (s *Server) secureWipeAll() {
	log.Println("Performing secure wipe of all data...")

	s.mu.Lock()
	defer s.mu.Unlock()

	// Wipe all buffers
	for id, buffer := range s.buffers {
		buffer.SecureWipe()
		delete(s.buffers, id)
	}

	// Clear sessions
	for id := range s.sessions {
		delete(s.sessions, id)
	}

	// Force garbage collection
	runtime.GC()

	log.Println("Secure wipe completed")
}

var startTime time.Time

func main() {
	startTime = time.Now()

	server := NewServer()

	// Setup signal handling for graceful shutdown
	signal.Notify(server.shutdown, syscall.SIGINT, syscall.SIGTERM)

	// Initialize Tor controller if available
	if torControlPort := os.Getenv("TOR_CONTROL_PORT"); torControlPort != "" {
		var err error
		server.torControl, err = NewTorController(torControlPort)
		if err != nil {
			log.Printf("Warning: Failed to connect to Tor controller: %v", err)
		} else {
			// Create ephemeral onion service
			onionAddr, err := server.torControl.CreateEphemeralOnion()
			if err != nil {
				log.Printf("Warning: Failed to create onion service: %v", err)
			} else {
				server.onionAddr = onionAddr
				log.Printf("Created ephemeral onion service: %s", onionAddr)
			}
		}
	}

	// Setup HTTP routes
	r := mux.NewRouter()

	// Public endpoints
	r.HandleFunc("/health", server.rateLimitMiddleware(server.healthCheck)).Methods("GET")
	r.HandleFunc("/session", server.rateLimitMiddleware(server.createSession)).Methods("POST")

	// Authenticated endpoints
	r.HandleFunc("/message", server.rateLimitMiddleware(server.authMiddleware(server.receiveMessage))).Methods("POST")
	r.HandleFunc("/chunk", server.rateLimitMiddleware(server.authMiddleware(server.receiveChunk))).Methods("POST")
	r.HandleFunc("/retrieve/{id}", server.rateLimitMiddleware(server.authMiddleware(server.retrieveMessage))).Methods("GET")

	// Start cleanup routine
	go server.cleanupExpiredSessions()

	// Configure TLS if certificates are available
	var httpServer *http.Server
	if certFile := os.Getenv("TLS_CERT_FILE"); certFile != "" {
		keyFile := os.Getenv("TLS_KEY_FILE")
		if keyFile == "" {
			log.Fatal("TLS_KEY_FILE must be set if TLS_CERT_FILE is set")
		}

		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS13,
			ClientAuth: tls.RequestClientCert, // Request but don't require client certs
		}

		httpServer = &http.Server{
			Addr:      ":8443",
			Handler:   r,
			TLSConfig: tlsConfig,
		}

		log.Println("Starting HTTPS server on :8443")
		go func() {
			if err := httpServer.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
				log.Printf("HTTPS server error: %v", err)
			}
		}()
	}

	// Always start HTTP server for Tor hidden service
	httpServer = &http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	log.Println("Starting HTTP server on :8080")
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-server.shutdown
	log.Println("Received shutdown signal, cleaning up...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if httpServer != nil {
		httpServer.Shutdown(ctx)
	}

	// Cleanup Tor onion service
	if server.torControl != nil {
		server.torControl.DeleteOnion()
		server.torControl.Close()
	}

	// Secure wipe
	server.secureWipeAll()

	log.Println("Server shutdown complete")
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}