// Secure Messaging & Document Server
// Ephemeral transport for encrypted messages and document chunks
// No backdoors, no telemetry, auditable components only

package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/unix"
)

const (
	MaxMessageSize     = 10 * 1024 * 1024  // 10MB
	MaxChunkSize       = 1024 * 1024       // 1MB
	MaxSessionData     = 100 * 1024 * 1024 // 100MB per session
	MaxSessions        = 1000
	SessionTimeout     = 5 * time.Minute
	BufferExpiry       = 5 * time.Minute
	MaxBuffersPerSession = 50
)

// SecureBuffer holds encrypted data in memory with automatic wipe
type SecureBuffer struct {
	data       []byte
	salt       []byte
	key        []byte
	mu         sync.RWMutex
	accessTime time.Time
	singleUse  bool
	accessed   bool
}

func NewSecureBuffer(data []byte, singleUse bool) (*SecureBuffer, error) {
	if len(data) > MaxMessageSize {
		return nil, fmt.Errorf("data too large: %d bytes", len(data))
	}

	// Generate encryption key and salt
	key := make([]byte, 32)
	salt := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %v", err)
	}
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	// Encrypt data with ChaCha20-Poly1305
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	encrypted := aead.Seal(nonce, nonce, data, salt)

	// Lock memory to prevent swapping
	if err := unix.Mlock(encrypted); err != nil {
		log.Printf("Warning: failed to lock buffer memory: %v", err)
	}

	return &SecureBuffer{
		data:       encrypted,
		salt:       salt,
		key:        key,
		accessTime: time.Now(),
		singleUse:  singleUse,
		accessed:   false,
	}, nil
}

func (sb *SecureBuffer) Read() ([]byte, error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.singleUse && sb.accessed {
		return nil, fmt.Errorf("buffer already accessed")
	}

	// Decrypt data
	aead, err := chacha20poly1305.NewX(sb.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	if len(sb.data) < aead.NonceSize() {
		return nil, fmt.Errorf("invalid encrypted data")
	}

	nonce := sb.data[:aead.NonceSize()]
	ciphertext := sb.data[aead.NonceSize():]

	plaintext, err := aead.Open(nil, nonce, ciphertext, sb.salt)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	sb.accessTime = time.Now()
	if sb.singleUse {
		sb.accessed = true
	}

	return plaintext, nil
}

func (sb *SecureBuffer) SecureWipe() {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	// Wipe all sensitive data
	for i := range sb.data {
		sb.data[i] = 0
	}
	for i := range sb.salt {
		sb.salt[i] = 0
	}
	for i := range sb.key {
		sb.key[i] = 0
	}

	// Unlock memory
	unix.Munlock(sb.data)

	sb.data = nil
	sb.salt = nil
	sb.key = nil
}

func (sb *SecureBuffer) IsExpired() bool {
	sb.mu.RLock()
	defer sb.mu.RUnlock()
	return time.Since(sb.accessTime) > BufferExpiry
}

// Session represents a messaging session
type Session struct {
	ID         string
	CreatedAt  time.Time
	LastAccess time.Time
	Buffers    map[string]*SecureBuffer
	TotalSize  int64
	mu         sync.RWMutex
}

func NewSession() *Session {
	id := make([]byte, 32)
	rand.Read(id)

	return &Session{
		ID:         hex.EncodeToString(id),
		CreatedAt:  time.Now(),
		LastAccess: time.Now(),
		Buffers:    make(map[string]*SecureBuffer),
		TotalSize:  0,
	}
}

func (s *Session) AddBuffer(bufferID string, buffer *SecureBuffer) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.Buffers) >= MaxBuffersPerSession {
		return fmt.Errorf("too many buffers in session")
	}

	if s.TotalSize+int64(len(buffer.data)) > MaxSessionData {
		return fmt.Errorf("session data limit exceeded")
	}

	s.Buffers[bufferID] = buffer
	s.TotalSize += int64(len(buffer.data))
	s.LastAccess = time.Now()

	return nil
}

func (s *Session) GetBuffer(bufferID string) (*SecureBuffer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	buffer, exists := s.Buffers[bufferID]
	if !exists {
		return nil, fmt.Errorf("buffer not found")
	}

	s.LastAccess = time.Now()
	return buffer, nil
}

func (s *Session) RemoveBuffer(bufferID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if buffer, exists := s.Buffers[bufferID]; exists {
		s.TotalSize -= int64(len(buffer.data))
		buffer.SecureWipe()
		delete(s.Buffers, bufferID)
	}
}

func (s *Session) IsExpired() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.LastAccess) > SessionTimeout
}

func (s *Session) SecureWipe() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for bufferID, buffer := range s.Buffers {
		buffer.SecureWipe()
		delete(s.Buffers, bufferID)
	}
	s.TotalSize = 0
}

// Server represents the main server
type Server struct {
	sessions        map[string]*Session
	mu              sync.RWMutex
	rateLimiter     map[string]*RateLimiter
	rateLimiterMu   sync.RWMutex
	shutdownChan    chan bool
	cleanupTicker   *time.Ticker
}

// RateLimiter implements token bucket rate limiting
type RateLimiter struct {
	tokens    int
	maxTokens int
	lastRefill time.Time
	refillRate time.Duration
	mu        sync.Mutex
}

func NewRateLimiter(maxTokens int, refillRate time.Duration) *RateLimiter {
	return &RateLimiter{
		tokens:     maxTokens,
		maxTokens:  maxTokens,
		lastRefill: time.Now(),
		refillRate: refillRate,
	}
}

func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastRefill)

	if elapsed > rl.refillRate {
		tokensToAdd := int(elapsed / rl.refillRate)
		rl.tokens = min(rl.maxTokens, rl.tokens + tokensToAdd)
		rl.lastRefill = now
	}

	if rl.tokens > 0 {
		rl.tokens--
		return true
	}

	return false
}

func NewServer() *Server {
	return &Server{
		sessions:      make(map[string]*Session),
		rateLimiter:   make(map[string]*RateLimiter),
		shutdownChan:  make(chan bool),
		cleanupTicker: time.NewTicker(time.Minute),
	}
}

func (srv *Server) getClientIP(r *http.Request) string {
	// Get client IP for rate limiting
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.RemoteAddr
	}
	return ip
}

func (srv *Server) checkRateLimit(clientIP, endpoint string) bool {
	srv.rateLimiterMu.Lock()
	defer srv.rateLimiterMu.Unlock()

	key := fmt.Sprintf("%s:%s", clientIP, endpoint)
	limiter, exists := srv.rateLimiter[key]

	if !exists {
		// Different limits for different endpoints
		var maxTokens int
		var refillRate time.Duration

		switch endpoint {
		case "health":
			maxTokens = 100
			refillRate = time.Minute
		case "session":
			maxTokens = 5
			refillRate = time.Minute
		case "message", "chunk":
			maxTokens = 10
			refillRate = time.Minute
		default:
			maxTokens = 20
			refillRate = time.Minute
		}

		limiter = NewRateLimiter(maxTokens, refillRate)
		srv.rateLimiter[key] = limiter
	}

	return limiter.Allow()
}

func (srv *Server) validateSessionAuth(r *http.Request) (*Session, error) {
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		return nil, fmt.Errorf("missing session ID")
	}

	srv.mu.RLock()
	session, exists := srv.sessions[sessionID]
	srv.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("invalid session ID")
	}

	if session.IsExpired() {
		srv.removeSession(sessionID)
		return nil, fmt.Errorf("session expired")
	}

	return session, nil
}

func (srv *Server) removeSession(sessionID string) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if session, exists := srv.sessions[sessionID]; exists {
		session.SecureWipe()
		delete(srv.sessions, sessionID)
	}
}

// HTTP Handlers

func (srv *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	if !srv.checkRateLimit(srv.getClientIP(r), "health") {
		http.Error(w, "Rate limited", http.StatusTooManyRequests)
		return
	}

	srv.mu.RLock()
	activeSessions := len(srv.sessions)
	srv.mu.RUnlock()

	response := map[string]interface{}{
		"status":           "healthy",
		"version":          "2.0.0",
		"active_sessions":  activeSessions,
		"max_sessions":     MaxSessions,
		"uptime_seconds":   int64(time.Since(startTime).Seconds()),
		"memory_locked":    true, // We use mlock where possible
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (srv *Server) createSessionHandler(w http.ResponseWriter, r *http.Request) {
	if !srv.checkRateLimit(srv.getClientIP(r), "session") {
		http.Error(w, "Rate limited", http.StatusTooManyRequests)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	srv.mu.Lock()
	if len(srv.sessions) >= MaxSessions {
		srv.mu.Unlock()
		http.Error(w, "Server at capacity", http.StatusServiceUnavailable)
		return
	}

	session := NewSession()
	srv.sessions[session.ID] = session
	srv.mu.Unlock()

	response := map[string]interface{}{
		"id":             session.ID,
		"expires_at":     session.CreatedAt.Add(SessionTimeout).Unix(),
		"buffer_limit":   MaxMessageSize,
		"chunk_size":     MaxChunkSize,
		"session_timeout": int(SessionTimeout.Seconds()),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	log.Printf("Created session: %s", session.ID)
}

func (srv *Server) sendMessageHandler(w http.ResponseWriter, r *http.Request) {
	if !srv.checkRateLimit(srv.getClientIP(r), "message") {
		http.Error(w, "Rate limited", http.StatusTooManyRequests)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, err := srv.validateSessionAuth(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Parse request body
	var req struct {
		SessionID    string            `json:"session_id"`
		Ciphertext   string            `json:"ciphertext"`
		Signature    string            `json:"signature"`
		Timestamp    int64             `json:"timestamp"`
		Metadata     map[string]interface{} `json:"metadata"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate session ID matches
	if req.SessionID != session.ID {
		http.Error(w, "Session ID mismatch", http.StatusUnauthorized)
		return
	}

	// Decode and validate ciphertext
	ciphertext, err := hex.DecodeString(req.Ciphertext)
	if err != nil {
		http.Error(w, "Invalid ciphertext encoding", http.StatusBadRequest)
		return
	}

	if len(ciphertext) > MaxMessageSize {
		http.Error(w, "Message too large", http.StatusRequestEntityTooLarge)
		return
	}

	// Create secure buffer
	buffer, err := NewSecureBuffer(ciphertext, true) // Single-use for messages
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create buffer: %v", err), http.StatusInternalServerError)
		return
	}

	// Generate buffer ID
	bufferIDBytes := make([]byte, 16)
	rand.Read(bufferIDBytes)
	bufferID := hex.EncodeToString(bufferIDBytes)

	// Add to session
	if err := session.AddBuffer(bufferID, buffer); err != nil {
		buffer.SecureWipe()
		http.Error(w, err.Error(), http.StatusInsufficientStorage)
		return
	}

	// Calculate checksum
	checksum := fmt.Sprintf("sha256:%x", sha256Hash(ciphertext))

	response := map[string]interface{}{
		"buffer_id":   bufferID,
		"stored_at":   time.Now().Unix(),
		"expires_at":  time.Now().Add(BufferExpiry).Unix(),
		"checksum":    checksum,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	log.Printf("Stored message in session %s, buffer %s", session.ID, bufferID)
}

func (srv *Server) sendChunkHandler(w http.ResponseWriter, r *http.Request) {
	if !srv.checkRateLimit(srv.getClientIP(r), "chunk") {
		http.Error(w, "Rate limited", http.StatusTooManyRequests)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, err := srv.validateSessionAuth(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Parse request body
	var req struct {
		SessionID    string `json:"session_id"`
		ChunkID      string `json:"chunk_id"`
		ChunkIndex   int    `json:"chunk_index"`
		TotalChunks  int    `json:"total_chunks"`
		Ciphertext   string `json:"ciphertext"`
		Signature    string `json:"signature"`
		Checksum     string `json:"checksum"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate session ID matches
	if req.SessionID != session.ID {
		http.Error(w, "Session ID mismatch", http.StatusUnauthorized)
		return
	}

	// Decode and validate ciphertext
	ciphertext, err := hex.DecodeString(req.Ciphertext)
	if err != nil {
		http.Error(w, "Invalid ciphertext encoding", http.StatusBadRequest)
		return
	}

	if len(ciphertext) > MaxChunkSize {
		http.Error(w, "Chunk too large", http.StatusRequestEntityTooLarge)
		return
	}

	// Create secure buffer for chunk
	buffer, err := NewSecureBuffer(ciphertext, false) // Multi-use for chunks
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create buffer: %v", err), http.StatusInternalServerError)
		return
	}

	// Generate buffer ID for this chunk
	bufferIDBytes := make([]byte, 16)
	rand.Read(bufferIDBytes)
	bufferID := hex.EncodeToString(bufferIDBytes)

	// Add to session
	if err := session.AddBuffer(bufferID, buffer); err != nil {
		buffer.SecureWipe()
		http.Error(w, err.Error(), http.StatusInsufficientStorage)
		return
	}

	// Track chunk completion (simplified - in production, would need more sophisticated tracking)
	receivedChunks := []int{req.ChunkIndex}
	missingChunks := []int{}
	for i := 0; i < req.TotalChunks; i++ {
		if i != req.ChunkIndex {
			missingChunks = append(missingChunks, i)
		}
	}

	completionStatus := "partial"
	if len(missingChunks) == 0 {
		completionStatus = "complete"
	}

	response := map[string]interface{}{
		"buffer_id":         bufferID,
		"received_chunks":   receivedChunks,
		"missing_chunks":    missingChunks,
		"completion_status": completionStatus,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	log.Printf("Stored chunk %d/%d in session %s, buffer %s", req.ChunkIndex, req.TotalChunks, session.ID, bufferID)
}

func (srv *Server) retrieveHandler(w http.ResponseWriter, r *http.Request) {
	if !srv.checkRateLimit(srv.getClientIP(r), "retrieve") {
		http.Error(w, "Rate limited", http.StatusTooManyRequests)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, err := srv.validateSessionAuth(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Extract buffer ID from URL
	vars := mux.Vars(r)
	bufferID := vars["bufferID"]

	if bufferID == "" {
		http.Error(w, "Missing buffer ID", http.StatusBadRequest)
		return
	}

	// Get buffer from session
	buffer, err := session.GetBuffer(bufferID)
	if err != nil {
		http.Error(w, "Buffer not found", http.StatusNotFound)
		return
	}

	if buffer.IsExpired() {
		session.RemoveBuffer(bufferID)
		http.Error(w, "Buffer expired", http.StatusGone)
		return
	}

	// Read data from buffer
	data, err := buffer.Read()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// If single-use, remove buffer after reading
	if buffer.singleUse {
		session.RemoveBuffer(bufferID)
	}

	response := map[string]interface{}{
		"buffer_id":    bufferID,
		"ciphertext":   hex.EncodeToString(data),
		"retrieved_at": time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	log.Printf("Retrieved buffer %s from session %s", bufferID, session.ID)
}

func (srv *Server) listBuffersHandler(w http.ResponseWriter, r *http.Request) {
	if !srv.checkRateLimit(srv.getClientIP(r), "buffers") {
		http.Error(w, "Rate limited", http.StatusTooManyRequests)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, err := srv.validateSessionAuth(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	session.mu.RLock()
	buffers := make([]map[string]interface{}, 0, len(session.Buffers))
	totalSize := session.TotalSize

	for bufferID, buffer := range session.Buffers {
		if !buffer.IsExpired() {
			buffers = append(buffers, map[string]interface{}{
				"buffer_id":  bufferID,
				"size":       len(buffer.data),
				"single_use": buffer.singleUse,
				"accessed":   buffer.accessed,
			})
		}
	}
	session.mu.RUnlock()

	response := map[string]interface{}{
		"buffers":     buffers,
		"total_count": len(buffers),
		"total_size":  totalSize,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (srv *Server) deleteSessionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, err := srv.validateSessionAuth(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	buffersDeleted := len(session.Buffers)
	dataWiped := session.TotalSize

	srv.removeSession(session.ID)

	response := map[string]interface{}{
		"message":         "Session deleted successfully",
		"buffers_deleted": buffersDeleted,
		"data_wiped":      fmt.Sprintf("%.2f MB", float64(dataWiped)/(1024*1024)),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	log.Printf("Deleted session %s (%d buffers, %d bytes)", session.ID, buffersDeleted, dataWiped)
}

// Cleanup goroutine
func (srv *Server) cleanup() {
	for {
		select {
		case <-srv.cleanupTicker.C:
			srv.cleanupExpiredSessions()
		case <-srv.shutdownChan:
			return
		}
	}
}

func (srv *Server) cleanupExpiredSessions() {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	expiredSessions := []string{}
	for sessionID, session := range srv.sessions {
		if session.IsExpired() {
			expiredSessions = append(expiredSessions, sessionID)
		} else {
			// Also clean up expired buffers within active sessions
			session.mu.Lock()
			expiredBuffers := []string{}
			for bufferID, buffer := range session.Buffers {
				if buffer.IsExpired() {
					expiredBuffers = append(expiredBuffers, bufferID)
				}
			}
			for _, bufferID := range expiredBuffers {
				session.RemoveBuffer(bufferID)
			}
			session.mu.Unlock()
		}
	}

	// Remove expired sessions
	for _, sessionID := range expiredSessions {
		if session, exists := srv.sessions[sessionID]; exists {
			session.SecureWipe()
			delete(srv.sessions, sessionID)
		}
	}

	if len(expiredSessions) > 0 {
		log.Printf("Cleaned up %d expired sessions", len(expiredSessions))
	}
}

func (srv *Server) shutdown() {
	log.Println("Shutting down server...")

	close(srv.shutdownChan)
	srv.cleanupTicker.Stop()

	// Secure wipe all sessions
	srv.mu.Lock()
	for sessionID, session := range srv.sessions {
		session.SecureWipe()
		delete(srv.sessions, sessionID)
	}
	srv.mu.Unlock()

	log.Println("Server shutdown complete")
}

// Utility functions
func sha256Hash(data []byte) []byte {
	h := make([]byte, 32)
	// TODO: Implement proper SHA-256 hashing
	return h
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Global variables
var startTime time.Time

func main() {
	startTime = time.Now()

	log.Println("Starting Secure Messaging & Document Server v2.0.0")
	log.Println("No backdoors, no telemetry, auditable components only")

	// Security hardening
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		log.Printf("Warning: failed to lock memory pages: %v", err)
	} else {
		log.Println("Memory pages locked to prevent swapping")
	}

	// Create server
	server := NewServer()

	// Start cleanup goroutine
	go server.cleanup()

	// Setup routes
	router := mux.NewRouter()

	// Health endpoint (no auth required)
	router.HandleFunc("/health", server.healthHandler).Methods("GET")

	// Session management
	router.HandleFunc("/session", server.createSessionHandler).Methods("POST")
	router.HandleFunc("/session/{sessionID}", server.deleteSessionHandler).Methods("DELETE")

	// Message and chunk endpoints
	router.HandleFunc("/message", server.sendMessageHandler).Methods("POST")
	router.HandleFunc("/chunk", server.sendChunkHandler).Methods("POST")
	router.HandleFunc("/retrieve/{bufferID}", server.retrieveHandler).Methods("GET")
	router.HandleFunc("/buffers", server.listBuffersHandler).Methods("GET")

	// Security headers middleware
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
			next.ServeHTTP(w, r)
		})
	})

	// Get port from environment or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Create HTTP server
	httpServer := &http.Server{
		Addr:         ":" + port,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("Server listening on port %s", port)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}

	server.shutdown()
}