package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/ed25519"
)

type SessionManager struct {
	sessions map[string]*Session
	mutex    sync.RWMutex
}

type Session struct {
	ID           string
	UserA        string
	UserB        string
	KeyA         []byte
	KeyB         []byte
	ShuttleKey   []byte
	CreatedAt    time.Time
	LastActivity time.Time
	Messages     []EncryptedMessage
	ConnA        *websocket.Conn
	ConnB        *websocket.Conn
	mutex        sync.RWMutex
}

type EncryptedMessage struct {
	ID          string    `json:"id"`
	FromUser    string    `json:"from_user"`
	ToUser      string    `json:"to_user"`
	Layer1Data  string    `json:"layer1_data"` // User encryption
	Layer2Data  string    `json:"layer2_data"` // Go server encryption
	Layer3Data  string    `json:"layer3_data"` // Shuttle website encryption
	Timestamp   time.Time `json:"timestamp"`
	Signature   string    `json:"signature"`
	DeadManTime *time.Time `json:"dead_man_time,omitempty"`
}

type HandshakeRequest struct {
	UserID    string `json:"user_id"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
	Timestamp int64  `json:"timestamp"`
}

type MessageRequest struct {
	SessionID   string `json:"session_id"`
	ToUser      string `json:"to_user"`
	Layer1Data  string `json:"layer1_data"`
	Signature   string `json:"signature"`
	DeadManTime *int64 `json:"dead_man_time,omitempty"`
}

var (
	sessionManager = &SessionManager{
		sessions: make(map[string]*Session),
	}
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins for now
		},
	}
	shuttleEndpoint = "https://shuttle-website.com/api/messages" // Configuration
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	r := mux.NewRouter()

	// API routes
	r.HandleFunc("/api/handshake", handleHandshake).Methods("POST")
	r.HandleFunc("/api/session/create", handleCreateSession).Methods("POST")
	r.HandleFunc("/api/message/send", handleSendMessage).Methods("POST")
	r.HandleFunc("/api/messages/{sessionId}", handleGetMessages).Methods("GET")
	r.HandleFunc("/api/session/{sessionId}/join", handleJoinSession).Methods("GET")

	// WebSocket endpoint
	r.HandleFunc("/ws/{sessionId}", handleWebSocket)

	// Health check
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	})

	// Start cleanup routine
	go cleanupExpiredSessions()

	log.Printf("JESUS IS KING - Secure Messaging Server starting on port %s", port)
	log.Printf("Triple encryption architecture: User → Go Server → Shuttle → Receiver's Go Server")

	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}

func handleHandshake(w http.ResponseWriter, r *http.Request) {
	var req HandshakeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Verify timestamp (within 5 minutes)
	if time.Now().Unix()-req.Timestamp > 300 {
		http.Error(w, "Timestamp expired", http.StatusUnauthorized)
		return
	}

	// Verify Ed25519 signature
	publicKey, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		http.Error(w, "Invalid public key", http.StatusBadRequest)
		return
	}

	signature, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		http.Error(w, "Invalid signature", http.StatusBadRequest)
		return
	}

	message := fmt.Sprintf("%s:%d", req.UserID, req.Timestamp)
	if !ed25519.Verify(publicKey, []byte(message), signature) {
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	// Generate session key for this user
	sessionKey := make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		http.Error(w, "Key generation failed", http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"status":      "authenticated",
		"user_id":     req.UserID,
		"session_key": base64.StdEncoding.EncodeToString(sessionKey),
		"server_time": fmt.Sprintf("%d", time.Now().Unix()),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleCreateSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserA     string `json:"user_a"`
		UserB     string `json:"user_b"`
		KeyA      string `json:"key_a"`
		KeyB      string `json:"key_b"`
		Signature string `json:"signature"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Generate session ID
	sessionID := generateSessionID()

	// Generate shuttle encryption key
	shuttleKey := make([]byte, 32)
	if _, err := rand.Read(shuttleKey); err != nil {
		http.Error(w, "Key generation failed", http.StatusInternalServerError)
		return
	}

	keyA, _ := base64.StdEncoding.DecodeString(req.KeyA)
	keyB, _ := base64.StdEncoding.DecodeString(req.KeyB)

	session := &Session{
		ID:           sessionID,
		UserA:        req.UserA,
		UserB:        req.UserB,
		KeyA:         keyA,
		KeyB:         keyB,
		ShuttleKey:   shuttleKey,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		Messages:     make([]EncryptedMessage, 0),
	}

	sessionManager.mutex.Lock()
	sessionManager.sessions[sessionID] = session
	sessionManager.mutex.Unlock()

	response := map[string]string{
		"session_id":  sessionID,
		"shuttle_key": base64.StdEncoding.EncodeToString(shuttleKey),
		"status":      "session_created",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleSendMessage(w http.ResponseWriter, r *http.Request) {
	var req MessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	sessionManager.mutex.RLock()
	session, exists := sessionManager.sessions[req.SessionID]
	sessionManager.mutex.RUnlock()

	if !exists {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	// Apply Layer 2 encryption (Go server encryption)
	layer2Data, err := encryptWithChaCha20([]byte(req.Layer1Data), session.ShuttleKey)
	if err != nil {
		http.Error(w, "Layer 2 encryption failed", http.StatusInternalServerError)
		return
	}

	// Apply Layer 3 encryption for shuttle transport
	layer3Data, err := encryptForShuttle(layer2Data)
	if err != nil {
		http.Error(w, "Layer 3 encryption failed", http.StatusInternalServerError)
		return
	}

	message := EncryptedMessage{
		ID:         generateMessageID(),
		FromUser:   getUserFromSession(session, req.SessionID),
		ToUser:     req.ToUser,
		Layer1Data: req.Layer1Data,
		Layer2Data: base64.StdEncoding.EncodeToString(layer2Data),
		Layer3Data: base64.StdEncoding.EncodeToString(layer3Data),
		Timestamp:  time.Now(),
		Signature:  req.Signature,
	}

	if req.DeadManTime != nil {
		deadManTime := time.Unix(*req.DeadManTime, 0)
		message.DeadManTime = &deadManTime
	}

	// Store message in session
	session.mutex.Lock()
	session.Messages = append(session.Messages, message)
	session.LastActivity = time.Now()
	session.mutex.Unlock()

	// Send to shuttle website
	go sendToShuttle(message)

	// Notify connected clients
	notifySessionClients(session, message)

	response := map[string]interface{}{
		"status":     "message_sent",
		"message_id": message.ID,
		"layers":     3,
		"timestamp":  message.Timestamp.Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleGetMessages(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["sessionId"]

	sessionManager.mutex.RLock()
	session, exists := sessionManager.sessions[sessionID]
	sessionManager.mutex.RUnlock()

	if !exists {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	session.mutex.RLock()
	messages := make([]EncryptedMessage, len(session.Messages))
	copy(messages, session.Messages)
	session.mutex.RUnlock()

	// Check for dead man switch
	now := time.Now()
	activeMessages := make([]EncryptedMessage, 0)
	for _, msg := range messages {
		if msg.DeadManTime == nil || now.Before(*msg.DeadManTime) {
			activeMessages = append(activeMessages, msg)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"messages": activeMessages,
		"session":  sessionID,
		"count":    len(activeMessages),
	})
}

func handleJoinSession(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["sessionId"]

	sessionManager.mutex.RLock()
	session, exists := sessionManager.sessions[sessionID]
	sessionManager.mutex.RUnlock()

	if !exists {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"session_id": sessionID,
		"user_a":     session.UserA,
		"user_b":     session.UserB,
		"created_at": session.CreatedAt.Unix(),
		"status":     "joined",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["sessionId"]

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	sessionManager.mutex.RLock()
	session, exists := sessionManager.sessions[sessionID]
	sessionManager.mutex.RUnlock()

	if !exists {
		conn.WriteJSON(map[string]string{"error": "Session not found"})
		return
	}

	// Add connection to session
	session.mutex.Lock()
	if session.ConnA == nil {
		session.ConnA = conn
	} else if session.ConnB == nil {
		session.ConnB = conn
	} else {
		session.mutex.Unlock()
		conn.WriteJSON(map[string]string{"error": "Session full"})
		return
	}
	session.mutex.Unlock()

	// Send welcome message
	conn.WriteJSON(map[string]interface{}{
		"type":       "connected",
		"session_id": sessionID,
		"timestamp":  time.Now().Unix(),
	})

	// Listen for messages
	for {
		var msg map[string]interface{}
		if err := conn.ReadJSON(&msg); err != nil {
			break
		}

		// Handle ping/pong for keepalive
		if msgType, ok := msg["type"].(string); ok && msgType == "ping" {
			conn.WriteJSON(map[string]string{"type": "pong"})
		}
	}

	// Remove connection from session
	session.mutex.Lock()
	if session.ConnA == conn {
		session.ConnA = nil
	} else if session.ConnB == conn {
		session.ConnB = nil
	}
	session.mutex.Unlock()
}

func encryptWithChaCha20(data, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, data, nil)

	// Prepend nonce to ciphertext
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result[:len(nonce)], nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

func encryptForShuttle(data []byte) ([]byte, error) {
	// Implement shuttle-specific encryption
	// This would use the shuttle website's public key
	// For now, using a placeholder encryption
	return encryptWithChaCha20(data, []byte("shuttle_key_32_bytes_placeholder"))
}

func sendToShuttle(message EncryptedMessage) {
	// Send Layer 3 encrypted data to shuttle website
	payload := map[string]interface{}{
		"message_id":   message.ID,
		"encrypted_data": message.Layer3Data,
		"timestamp":    message.Timestamp.Unix(),
		"from_server":  "go_server",
	}

	// HTTP POST to shuttle endpoint (implementation would depend on shuttle API)
	log.Printf("Sending message %s to shuttle website", message.ID)
}

func notifySessionClients(session *Session, message EncryptedMessage) {
	notification := map[string]interface{}{
		"type":       "new_message",
		"message_id": message.ID,
		"from_user":  message.FromUser,
		"timestamp":  message.Timestamp.Unix(),
	}

	session.mutex.RLock()
	if session.ConnA != nil {
		session.ConnA.WriteJSON(notification)
	}
	if session.ConnB != nil {
		session.ConnB.WriteJSON(notification)
	}
	session.mutex.RUnlock()
}

func cleanupExpiredSessions() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		sessionManager.mutex.Lock()

		for id, session := range sessionManager.sessions {
			// Remove sessions inactive for more than 24 hours
			if now.Sub(session.LastActivity) > 24*time.Hour {
				// Close any open connections
				session.mutex.Lock()
				if session.ConnA != nil {
					session.ConnA.Close()
				}
				if session.ConnB != nil {
					session.ConnB.Close()
				}
				session.mutex.Unlock()

				delete(sessionManager.sessions, id)
				log.Printf("Cleaned up expired session: %s", id)
			}
		}

		sessionManager.mutex.Unlock()
	}
}

func generateSessionID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

func generateMessageID() string {
	bytes := make([]byte, 12)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

func getUserFromSession(session *Session, sessionID string) string {
	// This would be determined by the authentication context
	// For now, returning a placeholder
	return "user_authenticated"
}