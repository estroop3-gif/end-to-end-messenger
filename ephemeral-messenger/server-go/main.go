package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/rs/cors"
	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

// Configuration
const (
	// Server configuration
	DefaultPort = "8443"
	MaxMessageSize = 1024 * 1024 // 1MB max message size
	MessageTTL = 24 * time.Hour  // Messages expire after 24 hours
	CleanupInterval = 1 * time.Hour

	// Rate limiting
	RateLimit = 100 // requests per minute per IP
	BurstLimit = 10

	// WebSocket configuration
	ReadBufferSize = 1024
	WriteBufferSize = 1024
	PongWait = 60 * time.Second
	PingPeriod = 54 * time.Second
	WriteWait = 10 * time.Second
)

// Message represents an ephemeral message
type Message struct {
	ID           string    `json:"id"`
	From         string    `json:"from"`
	To           string    `json:"to"`
	Content      string    `json:"content"`
	Timestamp    time.Time `json:"timestamp"`
	ExpiresAt    time.Time `json:"expires_at"`
	DeliveryType string    `json:"delivery_type"` // "direct", "relay"
}

// Client represents a connected client
type Client struct {
	ID         string
	Fingerprint string
	Conn       *websocket.Conn
	Send       chan Message
	LastSeen   time.Time
	mutex      sync.RWMutex
}

// Hub maintains active clients and handles message routing
type Hub struct {
	clients    map[string]*Client
	register   chan *Client
	unregister chan *Client
	messages   map[string]*Message // Temporary message storage
	mutex      sync.RWMutex
	limiter    map[string]*rate.Limiter // Rate limiting per IP
	limiterMu  sync.RWMutex
}

// Server represents the ephemeral messaging server
type Server struct {
	hub            *Hub
	upgrader       websocket.Upgrader
	server         *http.Server
	torManager     *TorManager
	networkManager *NetworkManager
}

// NewHub creates a new message hub
func NewHub() *Hub {
	return &Hub{
		clients:    make(map[string]*Client),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		messages:   make(map[string]*Message),
		limiter:    make(map[string]*rate.Limiter),
	}
}

// Run starts the hub and handles client connections
func (h *Hub) Run() {
	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case client := <-h.register:
			h.registerClient(client)

		case client := <-h.unregister:
			h.unregisterClient(client)

		case <-ticker.C:
			h.cleanupExpiredMessages()
		}
	}
}

func (h *Hub) registerClient(client *Client) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	// Remove existing client with same fingerprint
	if existing, exists := h.clients[client.Fingerprint]; exists {
		close(existing.Send)
		delete(h.clients, client.Fingerprint)
	}

	h.clients[client.Fingerprint] = client
	log.Printf("Client registered: %s (total: %d)", client.Fingerprint[:8], len(h.clients))

	// Send any pending messages for this client
	h.deliverPendingMessages(client)
}

func (h *Hub) unregisterClient(client *Client) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if _, exists := h.clients[client.Fingerprint]; exists {
		delete(h.clients, client.Fingerprint)
		close(client.Send)
		log.Printf("Client unregistered: %s (total: %d)", client.Fingerprint[:8], len(h.clients))
	}
}

func (h *Hub) deliverPendingMessages(client *Client) {
	for _, msg := range h.messages {
		if msg.To == client.Fingerprint && time.Now().Before(msg.ExpiresAt) {
			select {
			case client.Send <- *msg:
				// Message delivered, remove from storage
				delete(h.messages, msg.ID)
			default:
				// Client channel full, keep message for later
			}
		}
	}
}

func (h *Hub) cleanupExpiredMessages() {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	now := time.Now()
	deleted := 0

	for id, msg := range h.messages {
		if now.After(msg.ExpiresAt) {
			delete(h.messages, id)
			deleted++
		}
	}

	if deleted > 0 {
		log.Printf("Cleaned up %d expired messages", deleted)
	}
}

func (h *Hub) storeMessage(msg *Message) {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	h.messages[msg.ID] = msg
}

func (h *Hub) routeMessage(msg *Message) bool {
	h.mutex.RLock()
	client, exists := h.clients[msg.To]
	h.mutex.RUnlock()

	if !exists {
		// Store for later delivery
		h.storeMessage(msg)
		return false
	}

	select {
	case client.Send <- *msg:
		return true
	default:
		// Client channel full, store for later
		h.storeMessage(msg)
		return false
	}
}

// Rate limiting
func (h *Hub) getRateLimiter(ip string) *rate.Limiter {
	h.limiterMu.Lock()
	defer h.limiterMu.Unlock()

	limiter, exists := h.limiter[ip]
	if !exists {
		limiter = rate.NewLimiter(rate.Every(time.Minute/RateLimit), BurstLimit)
		h.limiter[ip] = limiter
	}

	return limiter
}

// NewServer creates a new ephemeral messaging server
func NewServer() *Server {
	hub := NewHub()

	upgrader := websocket.Upgrader{
		ReadBufferSize:  ReadBufferSize,
		WriteBufferSize: WriteBufferSize,
		CheckOrigin: func(r *http.Request) bool {
			// Allow all origins in development
			// In production, implement proper origin checking
			return true
		},
	}

	// Initialize Tor configuration
	torConfig := TorConfig{
		DataDirectory:     "/tmp/ephemeral-tor",
		ControlPort:       9051,
		SOCKSPort:        9050,
		LogLevel:         "notice",
		LogFile:          "/tmp/ephemeral-tor/tor.log",
		CircuitTimeout:   10,
		StrictNodes:      false,
		BridgeMode:       false,
		HiddenServices:   []HiddenServiceConfig{},
	}

	// Create Tor manager
	torManager := NewTorManager(torConfig)

	// Create network manager
	networkConfig := NetworkConfig{
		SOCKSProxy:      "127.0.0.1:9050",
		IsolateStreams:  true,
		CircuitTimeout:  30 * time.Second,
		RequestTimeout:  60 * time.Second,
		MaxRetries:      3,
		RetryDelay:      5 * time.Second,
	}
	networkManager := NewNetworkManager(networkConfig, torManager)

	return &Server{
		hub:            hub,
		upgrader:       upgrader,
		torManager:     torManager,
		networkManager: networkManager,
	}
}

// WebSocket handler
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Rate limiting
	ip := r.RemoteAddr
	limiter := s.hub.getRateLimiter(ip)
	if !limiter.Allow() {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Get client fingerprint from query parameters
	fingerprint := r.URL.Query().Get("fingerprint")
	if fingerprint == "" {
		http.Error(w, "Missing fingerprint parameter", http.StatusBadRequest)
		return
	}

	// Upgrade connection
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	// Create client
	client := &Client{
		ID:          uuid.New().String(),
		Fingerprint: fingerprint,
		Conn:        conn,
		Send:        make(chan Message, 256),
		LastSeen:    time.Now(),
	}

	// Register client
	s.hub.register <- client

	// Start goroutines for reading and writing
	go s.readPump(client)
	go s.writePump(client)
}

func (s *Server) readPump(client *Client) {
	defer func() {
		s.hub.unregister <- client
		client.Conn.Close()
	}()

	client.Conn.SetReadLimit(MaxMessageSize)
	client.Conn.SetReadDeadline(time.Now().Add(PongWait))
	client.Conn.SetPongHandler(func(string) error {
		client.Conn.SetReadDeadline(time.Now().Add(PongWait))
		return nil
	})

	for {
		var msg Message
		err := client.Conn.ReadJSON(&msg)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}

		// Validate and process message
		if err := s.validateMessage(&msg); err != nil {
			log.Printf("Invalid message from %s: %v", client.Fingerprint[:8], err)
			continue
		}

		// Set message metadata
		msg.ID = uuid.New().String()
		msg.From = client.Fingerprint
		msg.Timestamp = time.Now()
		msg.ExpiresAt = time.Now().Add(MessageTTL)

		// Route message
		delivered := s.hub.routeMessage(&msg)

		// Send delivery confirmation
		confirmation := Message{
			ID:        uuid.New().String(),
			From:      "server",
			To:        client.Fingerprint,
			Content:   fmt.Sprintf(`{"type":"delivery_status","message_id":"%s","delivered":%t}`, msg.ID, delivered),
			Timestamp: time.Now(),
		}

		select {
		case client.Send <- confirmation:
		default:
			// Client channel full
		}

		client.mutex.Lock()
		client.LastSeen = time.Now()
		client.mutex.Unlock()
	}
}

func (s *Server) writePump(client *Client) {
	ticker := time.NewTicker(PingPeriod)
	defer func() {
		ticker.Stop()
		client.Conn.Close()
	}()

	for {
		select {
		case message, ok := <-client.Send:
			client.Conn.SetWriteDeadline(time.Now().Add(WriteWait))
			if !ok {
				client.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := client.Conn.WriteJSON(message); err != nil {
				log.Printf("Write error: %v", err)
				return
			}

		case <-ticker.C:
			client.Conn.SetWriteDeadline(time.Now().Add(WriteWait))
			if err := client.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (s *Server) validateMessage(msg *Message) error {
	if msg.To == "" {
		return fmt.Errorf("missing recipient")
	}
	if msg.Content == "" {
		return fmt.Errorf("empty message content")
	}
	if len(msg.Content) > MaxMessageSize {
		return fmt.Errorf("message too large")
	}
	return nil
}

// Health check endpoint
func (s *Server) healthCheck(w http.ResponseWriter, r *http.Request) {
	s.hub.mutex.RLock()
	clientCount := len(s.hub.clients)
	messageCount := len(s.hub.messages)
	s.hub.mutex.RUnlock()

	status := map[string]interface{}{
		"status":         "healthy",
		"timestamp":      time.Now(),
		"clients":        clientCount,
		"pending_messages": messageCount,
		"version":        "1.0.0",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// Statistics endpoint
func (s *Server) getStats(w http.ResponseWriter, r *http.Request) {
	s.hub.mutex.RLock()
	clients := make([]map[string]interface{}, 0, len(s.hub.clients))
	for _, client := range s.hub.clients {
		client.mutex.RLock()
		clients = append(clients, map[string]interface{}{
			"fingerprint": client.Fingerprint[:8] + "...",
			"last_seen":   client.LastSeen,
			"connected":   time.Since(client.LastSeen) < time.Minute,
		})
		client.mutex.RUnlock()
	}

	messageCount := len(s.hub.messages)
	s.hub.mutex.RUnlock()

	stats := map[string]interface{}{
		"server": map[string]interface{}{
			"uptime":           time.Since(time.Now()), // This would be tracked properly
			"total_clients":    len(clients),
			"pending_messages": messageCount,
			"message_ttl":      MessageTTL.String(),
		},
		"clients": clients,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// Generate server key for Tor hidden service
func generateTorKey() (string, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

func (s *Server) Start(port string) error {
	// Initialize Tor first
	log.Println("Starting Tor manager...")
	if err := s.torManager.Start(); err != nil {
		log.Printf("Warning: Tor manager failed to start: %v", err)
		log.Println("Server will continue without Tor integration")
	} else {
		log.Println("Tor manager started successfully")

		// Create hidden service for the server
		hiddenService, err := s.torManager.CreateHiddenService("ephemeral-messenger", []PortMap{
			{VirtualPort: 80, TargetHost: "127.0.0.1", TargetPort: port},
		}, 3)

		if err != nil {
			log.Printf("Warning: Failed to create hidden service: %v", err)
		} else {
			log.Printf("Hidden service created: %s", hiddenService.OnionAddress)
		}
	}

	// Initialize network manager
	log.Println("Starting network manager...")
	if err := s.networkManager.Start(); err != nil {
		log.Printf("Warning: Network manager failed to start: %v", err)
	} else {
		log.Println("Network manager started successfully")
	}

	router := mux.NewRouter()

	// WebSocket endpoint
	router.HandleFunc("/ws", s.handleWebSocket)

	// Health and stats endpoints
	router.HandleFunc("/health", s.healthCheck).Methods("GET")
	router.HandleFunc("/stats", s.getStats).Methods("GET")

	// Tor management endpoints
	router.HandleFunc("/tor/status", s.getTorStatus).Methods("GET")
	router.HandleFunc("/tor/circuits", s.getTorCircuits).Methods("GET")
	router.HandleFunc("/tor/newcircuit", s.createNewCircuit).Methods("POST")
	router.HandleFunc("/tor/config", s.getTorConfig).Methods("GET")
	router.HandleFunc("/tor/config", s.updateTorConfig).Methods("PUT")
	router.HandleFunc("/tor/services", s.getHiddenServices).Methods("GET")
	router.HandleFunc("/tor/services", s.createHiddenService).Methods("POST")
	router.HandleFunc("/tor/services", s.deleteHiddenService).Methods("DELETE")
	router.HandleFunc("/tor/test", s.testConnection).Methods("GET")

	// CORS middleware
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"}, // Configure appropriately for production
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"*"},
	})

	handler := c.Handler(router)

	s.server = &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start the hub
	go s.hub.Run()

	log.Printf("Ephemeral messaging server starting on port %s", port)
	log.Printf("WebSocket endpoint: ws://localhost:%s/ws", port)
	log.Printf("Health check: http://localhost:%s/health", port)
	log.Printf("Stats: http://localhost:%s/stats", port)
	log.Printf("Tor status: http://localhost:%s/tor/status", port)

	return s.server.ListenAndServe()
}

func (s *Server) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log.Println("Shutting down server...")

	// Stop Tor manager
	if s.torManager != nil {
		log.Println("Stopping Tor manager...")
		s.torManager.Stop()
	}

	// Stop network manager
	if s.networkManager != nil {
		log.Println("Stopping network manager...")
		s.networkManager.Stop()
	}

	return s.server.Shutdown(ctx)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = DefaultPort
	}

	server := NewServer()

	// Handle graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		if err := server.Stop(); err != nil {
			log.Printf("Server shutdown error: %v", err)
		}
		os.Exit(0)
	}()

	// Start server
	if err := server.Start(port); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed to start: %v", err)
	}
}