package server

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// loggingMiddleware logs HTTP requests
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap the response writer to capture status code
		wrapped := &responseWrapper{ResponseWriter: w, statusCode: http.StatusOK}

		// Update request count
		s.updateStats(func(stats *ServerStats) {
			stats.RequestsTotal++
		})

		// Process request
		next.ServeHTTP(wrapped, r)

		// Log request
		duration := time.Since(start)
		s.logger.Info("HTTP request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("remote_addr", s.getClientIP(r)),
			zap.Int("status", wrapped.statusCode),
			zap.Duration("duration", duration),
			zap.String("user_agent", r.Header.Get("User-Agent")))

		// Update success/failure stats
		if wrapped.statusCode >= 200 && wrapped.statusCode < 400 {
			s.updateStats(func(stats *ServerStats) {
				stats.RequestsSucceeded++
			})
		} else {
			s.updateStats(func(stats *ServerStats) {
				stats.RequestsFailed++
			})
		}
	})
}

// corsMiddleware handles CORS headers
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Check if origin is allowed
		allowedOrigin := "*"
		if len(s.config.Server.CORSOrigins) > 0 {
			for _, allowed := range s.config.Server.CORSOrigins {
				if allowed == "*" || allowed == origin {
					allowedOrigin = allowed
					break
				}
			}
		}

		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
		w.Header().Set("Access-Control-Max-Age", "86400")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// rateLimitingMiddleware implements rate limiting
func (s *Server) rateLimitingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.config.Limits.RateLimit.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		var key string
		if s.config.Limits.RateLimit.ByIP {
			key = "ip:" + s.getClientIP(r)
		} else if s.config.Limits.RateLimit.ByAPIKey {
			apiKey := r.Header.Get("X-API-Key")
			if apiKey != "" {
				key = "key:" + apiKey
			} else {
				key = "ip:" + s.getClientIP(r)
			}
		} else {
			key = "global"
		}

		limiter := s.getRateLimiter(key)
		if !limiter.Allow() {
			s.logger.Warn("Rate limit exceeded",
				zap.String("key", key),
				zap.String("path", r.URL.Path))

			s.updateStats(func(stats *ServerStats) {
				stats.ErrorsTotal++
			})

			s.writeError(w, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED", "Rate limit exceeded")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// authMiddleware handles authentication
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.config.Auth.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Skip auth for health endpoint
		if r.URL.Path == "/api/v1/health" {
			next.ServeHTTP(w, r)
			return
		}

		// Check API key authentication
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			// Check Authorization header for Bearer token
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				s.logger.Warn("Missing authentication",
					zap.String("path", r.URL.Path),
					zap.String("remote_addr", s.getClientIP(r)))

				s.writeError(w, http.StatusUnauthorized, "MISSING_AUTH", "Authentication required")
				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")
			if !s.validateJWT(token) {
				s.logger.Warn("Invalid JWT token",
					zap.String("path", r.URL.Path),
					zap.String("remote_addr", s.getClientIP(r)))

				s.writeError(w, http.StatusUnauthorized, "INVALID_TOKEN", "Invalid authentication token")
				return
			}
		} else {
			// Validate API key
			if !s.validateAPIKey(apiKey, r.URL.Path) {
				s.logger.Warn("Invalid API key",
					zap.String("path", r.URL.Path),
					zap.String("remote_addr", s.getClientIP(r)))

				s.writeError(w, http.StatusUnauthorized, "INVALID_API_KEY", "Invalid API key")
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// metricsMiddleware collects request metrics
func (s *Server) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Add request ID for tracing
		requestID := generateRequestID()
		ctx := context.WithValue(r.Context(), "request_id", requestID)
		r = r.WithContext(ctx)

		w.Header().Set("X-Request-ID", requestID)

		next.ServeHTTP(w, r)

		// Record request duration for monitoring
		duration := time.Since(start)
		if duration > 5*time.Second {
			s.logger.Warn("Slow request detected",
				zap.String("path", r.URL.Path),
				zap.Duration("duration", duration),
				zap.String("request_id", requestID))
		}
	})
}

// responseWrapper wraps http.ResponseWriter to capture status code
type responseWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWrapper) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// validateJWT validates JWT tokens
func (s *Server) validateJWT(token string) bool {
	// TODO: Implement JWT validation using s.config.Auth.JWTSecret
	// For now, return true if auth is enabled but no secret is set (development mode)
	return s.config.Auth.JWTSecret == ""
}

// validateAPIKey validates API keys and permissions
func (s *Server) validateAPIKey(key, path string) bool {
	for _, apiKey := range s.config.Auth.APIKeys {
		if apiKey.Key == key {
			// Check permissions for the path
			return s.hasPermission(apiKey.Permissions, path)
		}
	}
	return false
}

// hasPermission checks if the permissions allow access to the path
func (s *Server) hasPermission(permissions []string, path string) bool {
	if len(permissions) == 0 {
		return false
	}

	for _, perm := range permissions {
		switch perm {
		case "admin":
			return true
		case "offer":
			if strings.Contains(path, "/offer") {
				return true
			}
		case "claim":
			if strings.Contains(path, "/claim") {
				return true
			}
		case "ack":
			if strings.Contains(path, "/ack") {
				return true
			}
		case "read":
			if strings.Contains(path, "/health") || strings.Contains(path, "/stats") || strings.Contains(path, "/queue") {
				return true
			}
		}
	}

	return false
}

// generateRequestID generates a unique request ID
func generateRequestID() string {
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}