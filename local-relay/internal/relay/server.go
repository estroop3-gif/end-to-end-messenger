package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"local-relay/internal/config"
	"local-relay/internal/crypto"
	"local-relay/internal/shuttle"
	"local-relay/internal/wire"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Server represents the local relay server
type Server struct {
	config        *config.Config
	shuttleClient *shuttle.Client
	logger        *zap.Logger
	layerCCtx     *crypto.LayerCContext
	upgrader      websocket.Upgrader
	sessions      map[string]*Session
	sessionsMu    sync.RWMutex
	stats         ServerStats
	statsMu       sync.RWMutex
}

// Session represents a client session
type Session struct {
	ID        string
	ClientID  string
	Conn      *websocket.Conn
	CreatedAt time.Time
	LastSeen  time.Time
	mu        sync.Mutex
}

// ServerStats contains server statistics
type ServerStats struct {
	TotalSessions     int64  `json:"total_sessions"`
	ActiveSessions    int64  `json:"active_sessions"`
	MessagesProcessed int64  `json:"messages_processed"`
	ErrorsCount       int64  `json:"errors_count"`
	BytesProcessed    int64  `json:"bytes_processed"`
	UptimeSeconds     int64  `json:"uptime_seconds"`
	StartTime         int64  `json:"start_time"`
}

// NewServer creates a new relay server
func NewServer(config *config.Config, shuttleClient *shuttle.Client, logger *zap.Logger) *Server {
	// Initialize Layer C context
	layerCCtx, err := crypto.NewLayerCContextFromHex(
		config.Crypto.LayerCPrivateKey,
		config.Crypto.LayerCPublicKey,
	)
	if err != nil {
		logger.Fatal("Failed to initialize Layer C context", zap.Error(err))
	}

	// Log the public key for clients to use
	pubKeyHex := layerCCtx.GetPublicKeyHex()
	logger.Info("Layer C public key", zap.String("public_key", pubKeyHex))

	// Save keys to config if they were generated
	if config.Crypto.LayerCPrivateKey == "" {
		config.Crypto.LayerCPrivateKey = layerCCtx.GetPrivateKeyHex()
		config.Crypto.LayerCPublicKey = pubKeyHex

		// Save updated config
		if err := config.Save(config, "config.json"); err != nil {
			logger.Warn("Failed to save updated config", zap.Error(err))
		}
	}

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			// Check CORS origins
			if len(config.Server.CORSOrigins) == 0 {
				return true // Allow all if no origins specified
			}

			origin := r.Header.Get("Origin")
			for _, allowed := range config.Server.CORSOrigins {
				if origin == allowed {
					return true
				}
			}
			return false
		},
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	server := &Server{
		config:        config,
		shuttleClient: shuttleClient,
		logger:        logger,
		layerCCtx:     layerCCtx,
		upgrader:      upgrader,
		sessions:      make(map[string]*Session),
		stats: ServerStats{
			StartTime: time.Now().Unix(),
		},
	}

	// Start background tasks
	go server.sessionCleanupLoop()
	go server.keyRotationLoop()

	return server
}

// Handler returns the HTTP handler for the server
func (s *Server) Handler() http.Handler {
	r := mux.NewRouter()

	// WebSocket endpoint for clients
	r.HandleFunc("/ws", s.handleWebSocket)

	// HTTP API endpoints
	api := r.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/health", s.handleHealth).Methods("GET")
	api.HandleFunc("/stats", s.handleStats).Methods("GET")
	api.HandleFunc("/sessions", s.handleSessions).Methods("GET")
	api.HandleFunc("/config", s.handleConfig).Methods("GET")

	// Add middleware
	r.Use(s.loggingMiddleware)
	r.Use(s.corsMiddleware)

	return r
}

// handleWebSocket handles WebSocket connections from clients
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Error("Failed to upgrade connection", zap.Error(err))
		return
	}

	// Create session
	session := &Session{
		ID:        uuid.New().String(),
		ClientID:  r.Header.Get("X-Client-ID"),
		Conn:      conn,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	if session.ClientID == "" {
		session.ClientID = "unknown"
	}

	// Register session
	s.sessionsMu.Lock()
	s.sessions[session.ID] = session
	s.updateStats(func(stats *ServerStats) {
		stats.TotalSessions++
		stats.ActiveSessions++
	})
	s.sessionsMu.Unlock()

	s.logger.Info("New client session",
		zap.String("session_id", session.ID),
		zap.String("client_id", session.ClientID),
		zap.String("remote_addr", r.RemoteAddr))

	// Handle session
	s.handleSession(session)
}

// handleSession handles a client session
func (s *Server) handleSession(session *Session) {
	defer func() {
		session.Conn.Close()

		// Unregister session
		s.sessionsMu.Lock()
		delete(s.sessions, session.ID)
		s.updateStats(func(stats *ServerStats) {
			stats.ActiveSessions--
		})
		s.sessionsMu.Unlock()

		s.logger.Info("Client session ended",
			zap.String("session_id", session.ID),
			zap.String("client_id", session.ClientID))
	}()

	// Set connection limits
	session.Conn.SetReadLimit(int64(s.config.Security.MaxFrameSize))
	session.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	session.Conn.SetPongHandler(func(string) error {
		session.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	// Start ping ticker
	ticker := time.NewTicker(54 * time.Second)
	defer ticker.Stop()

	go func() {
		for {
			select {
			case <-ticker.C:
				session.mu.Lock()
				if err := session.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					session.mu.Unlock()
					return
				}
				session.mu.Unlock()
			}
		}
	}()

	// Handle messages
	for {
		messageType, data, err := session.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				s.logger.Error("WebSocket error", zap.Error(err))
			}
			break
		}

		session.LastSeen = time.Now()

		if messageType == websocket.BinaryMessage {
			s.handleBinaryMessage(session, data)
		} else if messageType == websocket.TextMessage {
			s.handleTextMessage(session, data)
		}
	}
}

// handleBinaryMessage handles binary onion frame messages
func (s *Server) handleBinaryMessage(session *Session, data []byte) {
	s.updateStats(func(stats *ServerStats) {
		stats.MessagesProcessed++
		stats.BytesProcessed += int64(len(data))
	})

	// Check if it's a heartbeat
	if wire.IsHeartbeat(data) {
		s.logger.Debug("Received heartbeat", zap.String("session_id", session.ID))
		return
	}

	// Deserialize onion frame
	frame, err := wire.DeserializeFrame(data)
	if err != nil {
		s.logger.Error("Failed to deserialize frame",
			zap.String("session_id", session.ID),
			zap.Error(err))
		s.updateStats(func(stats *ServerStats) { stats.ErrorsCount++ })
		s.sendError(session, "INVALID_FRAME", err.Error())
		return
	}

	// Validate frame
	if err := wire.ValidateFrame(frame); err != nil {
		s.logger.Error("Invalid frame",
			zap.String("session_id", session.ID),
			zap.Error(err))
		s.updateStats(func(stats *ServerStats) { stats.ErrorsCount++ })
		s.sendError(session, "FRAME_VALIDATION_FAILED", err.Error())
		return
	}

	// Process onion frame
	if err := s.processOnionFrame(session, frame); err != nil {
		s.logger.Error("Failed to process onion frame",
			zap.String("session_id", session.ID),
			zap.Error(err))
		s.updateStats(func(stats *ServerStats) { stats.ErrorsCount++ })
		s.sendError(session, "PROCESSING_FAILED", err.Error())
		return
	}
}

// handleTextMessage handles text control messages
func (s *Server) handleTextMessage(session *Session, data []byte) {
	var msg map[string]interface{}
	if err := json.Unmarshal(data, &msg); err != nil {
		s.logger.Error("Invalid JSON message",
			zap.String("session_id", session.ID),
			zap.Error(err))
		s.sendError(session, "INVALID_JSON", err.Error())
		return
	}

	msgType, ok := msg["type"].(string)
	if !ok {
		s.sendError(session, "MISSING_TYPE", "Message type is required")
		return
	}

	switch msgType {
	case "ping":
		s.sendResponse(session, map[string]interface{}{
			"type": "pong",
			"timestamp": time.Now().Unix(),
		})
	case "status":
		s.sendResponse(session, map[string]interface{}{
			"type": "status",
			"session_id": session.ID,
			"uptime": time.Since(session.CreatedAt).Seconds(),
			"healthy": s.shuttleClient.IsHealthy(),
		})
	default:
		s.sendError(session, "UNKNOWN_TYPE", fmt.Sprintf("Unknown message type: %s", msgType))
	}
}

// processOnionFrame processes an onion frame by decrypting Layer C and forwarding to shuttle
func (s *Server) processOnionFrame(session *Session, frame *wire.OnionFrame) error {
	// Serialize AAD for decryption
	aadBytes, err := json.Marshal(map[string]interface{}{
		"route": frame.CEnvelope.Route,
		"aad":   frame.CEnvelope.AAD,
	})
	if err != nil {
		return fmt.Errorf("failed to serialize AAD: %w", err)
	}

	// Decrypt Layer C
	layerBData, err := s.layerCCtx.Decrypt(frame.CEnvelope.Ciphertext, aadBytes)
	if err != nil {
		return fmt.Errorf("Layer C decryption failed: %w", err)
	}

	s.logger.Debug("Layer C decrypted successfully",
		zap.String("session_id", session.ID),
		zap.String("route_session", frame.CEnvelope.Route.SessionID),
		zap.Int("payload_size", len(layerBData)))

	// Forward Layer B data to shuttle service
	offerReq := &shuttle.OfferRequest{
		MessageID: uuid.New().String(),
		Recipient: frame.CEnvelope.Route.DstHint,
		Payload:   json.RawMessage(layerBData),
		TTL:       3600, // 1 hour
		Priority:  1,
		Metadata: shuttle.OfferMetadata{
			SenderHint:  session.ClientID,
			ContentType: "application/onion-layer-b",
			FrameSize:   len(layerBData),
			TimestampMs: time.Now().UnixMilli(),
			RetryCount:  0,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	offerResp, err := s.shuttleClient.Offer(ctx, offerReq)
	if err != nil {
		return fmt.Errorf("shuttle offer failed: %w", err)
	}

	if !offerResp.Accepted {
		return fmt.Errorf("shuttle rejected message: %s", offerResp.ErrorMessage)
	}

	s.logger.Info("Message forwarded to shuttle",
		zap.String("session_id", session.ID),
		zap.String("message_id", offerReq.MessageID),
		zap.String("recipient", offerReq.Recipient))

	// Send success response to client
	s.sendResponse(session, map[string]interface{}{
		"type": "message_accepted",
		"message_id": offerReq.MessageID,
		"queued_until": offerResp.QueuedUntil,
	})

	return nil
}

// sendError sends an error message to the client
func (s *Server) sendError(session *Session, code, message string) {
	response := map[string]interface{}{
		"type": "error",
		"error_code": code,
		"error_message": message,
		"timestamp": time.Now().Unix(),
	}
	s.sendResponse(session, response)
}

// sendResponse sends a JSON response to the client
func (s *Server) sendResponse(session *Session, response map[string]interface{}) {
	data, err := json.Marshal(response)
	if err != nil {
		s.logger.Error("Failed to marshal response", zap.Error(err))
		return
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if err := session.Conn.WriteMessage(websocket.TextMessage, data); err != nil {
		s.logger.Error("Failed to send response", zap.Error(err))
	}
}