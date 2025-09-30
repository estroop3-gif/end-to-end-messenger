package relay

import (
	"encoding/json"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":     "healthy",
		"version":    "1.0.0",
		"timestamp":  time.Now().Unix(),
		"uptime":     time.Now().Unix() - s.stats.StartTime,
		"shuttle_healthy": s.shuttleClient.IsHealthy(),
		"layer_c_generation": s.layerCCtx.GetKeyGeneration(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// handleStats handles statistics requests
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	s.statsMu.RLock()
	stats := s.stats
	stats.UptimeSeconds = time.Now().Unix() - s.stats.StartTime
	s.statsMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleSessions handles session listing requests
func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	s.sessionsMu.RLock()
	sessions := make([]map[string]interface{}, 0, len(s.sessions))

	for _, session := range s.sessions {
		sessions = append(sessions, map[string]interface{}{
			"id":         session.ID,
			"client_id":  session.ClientID,
			"created_at": session.CreatedAt.Unix(),
			"last_seen":  session.LastSeen.Unix(),
			"uptime":     time.Since(session.CreatedAt).Seconds(),
		})
	}
	s.sessionsMu.RUnlock()

	response := map[string]interface{}{
		"sessions": sessions,
		"count":    len(sessions),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleConfig handles configuration requests (sanitized)
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	config := map[string]interface{}{
		"server": map[string]interface{}{
			"port":           s.config.Server.Port,
			"max_frame_size": s.config.Security.MaxFrameSize,
			"cors_origins":   s.config.Server.CORSOrigins,
		},
		"crypto": map[string]interface{}{
			"public_key":            s.layerCCtx.GetPublicKeyHex(),
			"key_generation":        s.layerCCtx.GetKeyGeneration(),
			"key_rotation_interval": s.config.Crypto.KeyRotationInterval.String(),
			"session_timeout":       s.config.Crypto.SessionTimeout.String(),
		},
		"shuttle": map[string]interface{}{
			"url":     s.config.Shuttle.URL,
			"healthy": s.shuttleClient.IsHealthy(),
			"timeout": s.config.Shuttle.Timeout.String(),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

// updateStats safely updates server statistics
func (s *Server) updateStats(updateFn func(*ServerStats)) {
	s.statsMu.Lock()
	updateFn(&s.stats)
	s.statsMu.Unlock()
}

// sessionCleanupLoop periodically cleans up stale sessions
func (s *Server) sessionCleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		cutoff := time.Now().Add(-s.config.Crypto.SessionTimeout)

		s.sessionsMu.Lock()
		cleaned := 0
		for id, session := range s.sessions {
			if session.LastSeen.Before(cutoff) {
				session.Conn.Close()
				delete(s.sessions, id)
				cleaned++
			}
		}
		if cleaned > 0 {
			s.updateStats(func(stats *ServerStats) {
				stats.ActiveSessions -= int64(cleaned)
			})
		}
		s.sessionsMu.Unlock()

		if cleaned > 0 {
			s.logger.Info("Cleaned up stale sessions", zap.Int("count", cleaned))
		}
	}
}

// keyRotationLoop periodically rotates Layer C keys
func (s *Server) keyRotationLoop() {
	ticker := time.NewTicker(s.config.Crypto.KeyRotationInterval)
	defer ticker.Stop()

	for range ticker.C {
		if err := s.layerCCtx.RotateKeys(); err != nil {
			s.logger.Error("Failed to rotate Layer C keys", zap.Error(err))
		} else {
			s.logger.Info("Layer C keys rotated",
				zap.Uint32("generation", s.layerCCtx.GetKeyGeneration()))
		}
	}
}

// loggingMiddleware logs HTTP requests
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		next.ServeHTTP(w, r)

		s.logger.Debug("HTTP request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("remote_addr", r.RemoteAddr),
			zap.Duration("duration", time.Since(start)))
	})
}

// corsMiddleware handles CORS headers
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Check if origin is allowed
		allowed := len(s.config.Server.CORSOrigins) == 0 // Allow all if none specified
		if !allowed {
			for _, allowedOrigin := range s.config.Server.CORSOrigins {
				if origin == allowedOrigin {
					allowed = true
					break
				}
			}
		}

		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Client-ID")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}