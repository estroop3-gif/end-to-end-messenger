package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"time"

	"shuttle-service/internal/config"
	"shuttle-service/internal/queue"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

// Server represents the HTTP server for the shuttle service
type Server struct {
	config       *config.Config
	queue        *queue.MessageQueue
	logger       *zap.Logger
	rateLimiters map[string]*rate.Limiter
	rateMu       sync.RWMutex
	stats        ServerStats
	statsMu      sync.RWMutex
	startTime    time.Time
}

// ServerStats contains server statistics
type ServerStats struct {
	RequestsTotal     int64 `json:"requests_total"`
	RequestsSucceeded int64 `json:"requests_succeeded"`
	RequestsFailed    int64 `json:"requests_failed"`
	OffersReceived    int64 `json:"offers_received"`
	OffersAccepted    int64 `json:"offers_accepted"`
	OffersRejected    int64 `json:"offers_rejected"`
	ClaimsReceived    int64 `json:"claims_received"`
	MessagesDelivered int64 `json:"messages_delivered"`
	AcksReceived      int64 `json:"acks_received"`
	ErrorsTotal       int64 `json:"errors_total"`
}

// NewServer creates a new HTTP server
func NewServer(config *config.Config, queue *queue.MessageQueue, logger *zap.Logger) *Server {
	return &Server{
		config:       config,
		queue:        queue,
		logger:       logger,
		rateLimiters: make(map[string]*rate.Limiter),
		startTime:    time.Now(),
	}
}

// Handler returns the HTTP handler for the server
func (s *Server) Handler() http.Handler {
	r := mux.NewRouter()

	// API v1 routes
	api := r.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/offer", s.handleOffer).Methods("POST")
	api.HandleFunc("/claim", s.handleClaim).Methods("POST")
	api.HandleFunc("/ack", s.handleAck).Methods("POST")
	api.HandleFunc("/health", s.handleHealth).Methods("GET")
	api.HandleFunc("/stats", s.handleStats).Methods("GET")
	api.HandleFunc("/queue/{recipient}", s.handleQueueInfo).Methods("GET")

	// Add middleware
	r.Use(s.loggingMiddleware)
	r.Use(s.corsMiddleware)
	r.Use(s.rateLimitingMiddleware)
	r.Use(s.authMiddleware)
	r.Use(s.metricsMiddleware)

	return r
}

// handleOffer handles message offer requests
func (s *Server) handleOffer(w http.ResponseWriter, r *http.Request) {
	var req queue.OfferRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.updateStats(func(stats *ServerStats) { stats.ErrorsTotal++ })
		s.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON payload")
		return
	}

	s.updateStats(func(stats *ServerStats) { stats.OffersReceived++ })

	resp, err := s.queue.Offer(r.Context(), &req)
	if err != nil {
		s.updateStats(func(stats *ServerStats) {
			stats.ErrorsTotal++
			stats.OffersRejected++
		})
		s.logger.Error("Offer failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to process offer")
		return
	}

	if resp.Accepted {
		s.updateStats(func(stats *ServerStats) { stats.OffersAccepted++ })
		s.logger.Info("Message offer accepted",
			zap.String("message_id", req.MessageID),
			zap.String("recipient", req.Recipient))
	} else {
		s.updateStats(func(stats *ServerStats) { stats.OffersRejected++ })
		s.logger.Warn("Message offer rejected",
			zap.String("message_id", req.MessageID),
			zap.String("recipient", req.Recipient),
			zap.String("error_code", resp.ErrorCode))
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// handleClaim handles message claim requests
func (s *Server) handleClaim(w http.ResponseWriter, r *http.Request) {
	var req queue.ClaimRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.updateStats(func(stats *ServerStats) { stats.ErrorsTotal++ })
		s.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON payload")
		return
	}

	s.updateStats(func(stats *ServerStats) { stats.ClaimsReceived++ })

	resp, err := s.queue.Claim(r.Context(), &req)
	if err != nil {
		s.updateStats(func(stats *ServerStats) { stats.ErrorsTotal++ })
		s.logger.Error("Claim failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to process claim")
		return
	}

	s.updateStats(func(stats *ServerStats) {
		stats.MessagesDelivered += int64(len(resp.Messages))
	})

	s.logger.Info("Messages claimed",
		zap.String("client_id", req.ClientID),
		zap.Int("count", len(resp.Messages)))

	s.writeJSON(w, http.StatusOK, resp)
}

// handleAck handles message acknowledgment requests
func (s *Server) handleAck(w http.ResponseWriter, r *http.Request) {
	var req queue.AckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.updateStats(func(stats *ServerStats) { stats.ErrorsTotal++ })
		s.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON payload")
		return
	}

	s.updateStats(func(stats *ServerStats) { stats.AcksReceived++ })

	if err := s.queue.Ack(r.Context(), &req); err != nil {
		s.updateStats(func(stats *ServerStats) { stats.ErrorsTotal++ })
		s.logger.Error("Ack failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to process ack")
		return
	}

	s.logger.Debug("Message acknowledged",
		zap.String("message_id", req.MessageID),
		zap.Bool("success", req.Success))

	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	health := map[string]interface{}{
		"status":       "healthy",
		"version":      "1.0.0",
		"timestamp":    time.Now().Unix(),
		"uptime":       time.Since(s.startTime).Seconds(),
		"memory_mb":    memStats.Alloc / 1024 / 1024,
		"goroutines":   runtime.NumGoroutine(),
	}

	// Add queue health info
	queueStats, err := s.queue.GetStats(r.Context())
	if err != nil {
		s.logger.Error("Failed to get queue stats for health check", zap.Error(err))
		health["queue_status"] = "error"
	} else {
		health["queue_status"] = "healthy"
		health["queue_length"] = queueStats["total_messages"]
	}

	s.writeJSON(w, http.StatusOK, health)
}

// handleStats handles statistics requests
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	s.statsMu.RLock()
	serverStats := s.stats
	s.statsMu.RUnlock()

	queueStats, err := s.queue.GetStats(r.Context())
	if err != nil {
		s.logger.Error("Failed to get queue stats", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "STATS_ERROR", "Failed to get queue statistics")
		return
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	combined := map[string]interface{}{
		"server": map[string]interface{}{
			"uptime_seconds":      time.Since(s.startTime).Seconds(),
			"requests_total":      serverStats.RequestsTotal,
			"requests_succeeded":  serverStats.RequestsSucceeded,
			"requests_failed":     serverStats.RequestsFailed,
			"offers_received":     serverStats.OffersReceived,
			"offers_accepted":     serverStats.OffersAccepted,
			"offers_rejected":     serverStats.OffersRejected,
			"claims_received":     serverStats.ClaimsReceived,
			"messages_delivered":  serverStats.MessagesDelivered,
			"acks_received":       serverStats.AcksReceived,
			"errors_total":        serverStats.ErrorsTotal,
		},
		"system": map[string]interface{}{
			"memory_alloc_mb":     memStats.Alloc / 1024 / 1024,
			"memory_total_mb":     memStats.TotalAlloc / 1024 / 1024,
			"memory_sys_mb":       memStats.Sys / 1024 / 1024,
			"gc_runs":             memStats.NumGC,
			"goroutines":          runtime.NumGoroutine(),
		},
		"queue": queueStats,
	}

	s.writeJSON(w, http.StatusOK, combined)
}

// handleQueueInfo handles queue information requests
func (s *Server) handleQueueInfo(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	recipient := vars["recipient"]

	if recipient == "" {
		s.writeError(w, http.StatusBadRequest, "MISSING_RECIPIENT", "Recipient parameter is required")
		return
	}

	info, err := s.queue.GetQueueInfo(r.Context(), recipient)
	if err != nil {
		s.logger.Error("Failed to get queue info", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "QUEUE_ERROR", "Failed to get queue information")
		return
	}

	s.writeJSON(w, http.StatusOK, info)
}

// writeJSON writes a JSON response
func (s *Server) writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

// writeError writes an error response
func (s *Server) writeError(w http.ResponseWriter, statusCode int, errorCode, message string) {
	s.writeJSON(w, statusCode, map[string]interface{}{
		"error": map[string]interface{}{
			"code":    errorCode,
			"message": message,
		},
		"timestamp": time.Now().Unix(),
	})
}

// updateStats safely updates server statistics
func (s *Server) updateStats(updateFn func(*ServerStats)) {
	s.statsMu.Lock()
	updateFn(&s.stats)
	s.statsMu.Unlock()
}

// getRateLimiter gets or creates a rate limiter for a key
func (s *Server) getRateLimiter(key string) *rate.Limiter {
	s.rateMu.RLock()
	limiter, exists := s.rateLimiters[key]
	s.rateMu.RUnlock()

	if !exists {
		s.rateMu.Lock()
		// Double-check after acquiring write lock
		if limiter, exists = s.rateLimiters[key]; !exists {
			rps := rate.Every(time.Minute / time.Duration(s.config.Limits.RateLimit.RequestsPerMin))
			limiter = rate.NewLimiter(rps, s.config.Limits.RateLimit.BurstSize)
			s.rateLimiters[key] = limiter
		}
		s.rateMu.Unlock()
	}

	return limiter
}

// getClientIP extracts the client IP from the request
func (s *Server) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}