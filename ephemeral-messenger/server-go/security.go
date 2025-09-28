package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/time/rate"
)

// SecurityManager handles security operations for the server
type SecurityManager struct {
	blockedIPs     map[string]time.Time
	rateLimiters   map[string]*rate.Limiter
	securityEvents []SecurityEvent
	mutex          sync.RWMutex
	config         SecurityConfig
}

// SecurityConfig represents security configuration
type SecurityConfig struct {
	MaxFailedAttempts   int           `json:"max_failed_attempts"`
	BlockDuration       time.Duration `json:"block_duration"`
	RateLimitEnabled    bool          `json:"rate_limit_enabled"`
	RequestsPerMinute   int           `json:"requests_per_minute"`
	BurstLimit         int           `json:"burst_limit"`
	RequireFingerprint bool          `json:"require_fingerprint"`
	MaxMessageSize     int           `json:"max_message_size"`
	AllowedOrigins     []string      `json:"allowed_origins"`
}

// NewSecurityManager creates a new security manager
func NewSecurityManager(config SecurityConfig) *SecurityManager {
	return &SecurityManager{
		blockedIPs:     make(map[string]time.Time),
		rateLimiters:   make(map[string]*rate.Limiter),
		securityEvents: make([]SecurityEvent, 0),
		config:         config,
	}
}

// IsIPBlocked checks if an IP address is blocked
func (sm *SecurityManager) IsIPBlocked(ip string) bool {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	if blockTime, exists := sm.blockedIPs[ip]; exists {
		if time.Now().Before(blockTime.Add(sm.config.BlockDuration)) {
			return true
		}
		// Block expired, remove it
		delete(sm.blockedIPs, ip)
	}
	return false
}

// BlockIP blocks an IP address for a specified duration
func (sm *SecurityManager) BlockIP(ip string, reason string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	sm.blockedIPs[ip] = time.Now()

	// Log security event
	event := SecurityEvent{
		ID:          generateSecurityEventID(),
		Type:        "ip_blocked",
		Severity:    "warning",
		Timestamp:   time.Now(),
		IPAddress:   ip,
		Description: reason,
	}
	sm.logSecurityEvent(event)

	log.Printf("IP blocked: %s - %s", ip, reason)
}

// CheckRateLimit checks if a request should be rate limited
func (sm *SecurityManager) CheckRateLimit(ip string) bool {
	if !sm.config.RateLimitEnabled {
		return true
	}

	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	limiter, exists := sm.rateLimiters[ip]
	if !exists {
		limiter = rate.NewLimiter(
			rate.Every(time.Minute/time.Duration(sm.config.RequestsPerMinute)),
			sm.config.BurstLimit,
		)
		sm.rateLimiters[ip] = limiter
	}

	return limiter.Allow()
}

// ValidateFingerprint validates a client fingerprint
func (sm *SecurityManager) ValidateFingerprint(fingerprint string) error {
	if !sm.config.RequireFingerprint {
		return nil
	}

	if fingerprint == "" {
		return fmt.Errorf("fingerprint is required")
	}

	// Validate fingerprint format (should be hex string of appropriate length)
	if len(fingerprint) < 16 || len(fingerprint) > 64 {
		return fmt.Errorf("invalid fingerprint length")
	}

	if _, err := hex.DecodeString(fingerprint); err != nil {
		return fmt.Errorf("invalid fingerprint format")
	}

	return nil
}

// ValidateOrigin validates the request origin
func (sm *SecurityManager) ValidateOrigin(origin string) bool {
	if len(sm.config.AllowedOrigins) == 0 {
		return true // Allow all if not configured
	}

	for _, allowed := range sm.config.AllowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}

	return false
}

// SanitizeMessage sanitizes message content
func (sm *SecurityManager) SanitizeMessage(content string) (string, error) {
	// Check message size
	if len(content) > sm.config.MaxMessageSize {
		return "", fmt.Errorf("message too large: %d bytes (max: %d)",
			len(content), sm.config.MaxMessageSize)
	}

	// Remove null bytes and control characters
	cleaned := strings.Map(func(r rune) rune {
		if r == 0 || (r >= 1 && r <= 31 && r != 9 && r != 10 && r != 13) {
			return -1
		}
		return r
	}, content)

	return cleaned, nil
}

// LogSecurityEvent logs a security event
func (sm *SecurityManager) logSecurityEvent(event SecurityEvent) {
	sm.securityEvents = append(sm.securityEvents, event)

	// Keep only last 1000 events
	if len(sm.securityEvents) > 1000 {
		sm.securityEvents = sm.securityEvents[len(sm.securityEvents)-1000:]
	}
}

// GetSecurityEvents returns recent security events
func (sm *SecurityManager) GetSecurityEvents(limit int) []SecurityEvent {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	if limit <= 0 || limit > len(sm.securityEvents) {
		limit = len(sm.securityEvents)
	}

	events := make([]SecurityEvent, limit)
	copy(events, sm.securityEvents[len(sm.securityEvents)-limit:])
	return events
}

// Cleanup removes expired blocks and rate limiters
func (sm *SecurityManager) Cleanup() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	now := time.Now()

	// Clean up expired IP blocks
	for ip, blockTime := range sm.blockedIPs {
		if now.After(blockTime.Add(sm.config.BlockDuration)) {
			delete(sm.blockedIPs, ip)
		}
	}

	// Clean up old rate limiters (remove if not used for 1 hour)
	for ip, limiter := range sm.rateLimiters {
		// This is a simple cleanup - in production you'd track last access time
		_ = limiter
		if len(sm.rateLimiters) > 1000 { // Arbitrary limit
			delete(sm.rateLimiters, ip)
		}
	}
}

// SecurityMiddleware provides HTTP middleware for security checks
func (sm *SecurityManager) SecurityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get client IP
		ip := getClientIP(r)

		// Check if IP is blocked
		if sm.IsIPBlocked(ip) {
			sm.logSecurityEvent(SecurityEvent{
				ID:          generateSecurityEventID(),
				Type:        "blocked_access_attempt",
				Severity:    "info",
				Timestamp:   time.Now(),
				IPAddress:   ip,
				Description: "Access attempt from blocked IP",
			})
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		// Check rate limit
		if !sm.CheckRateLimit(ip) {
			sm.logSecurityEvent(SecurityEvent{
				ID:          generateSecurityEventID(),
				Type:        "rate_limit_exceeded",
				Severity:    "warning",
				Timestamp:   time.Now(),
				IPAddress:   ip,
				Description: "Rate limit exceeded",
			})
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// Validate origin for WebSocket upgrades
		if r.Header.Get("Upgrade") == "websocket" {
			origin := r.Header.Get("Origin")
			if !sm.ValidateOrigin(origin) {
				sm.logSecurityEvent(SecurityEvent{
					ID:          generateSecurityEventID(),
					Type:        "invalid_origin",
					Severity:    "warning",
					Timestamp:   time.Now(),
					IPAddress:   ip,
					Description: fmt.Sprintf("Invalid origin: %s", origin),
				})
				http.Error(w, "Invalid origin", http.StatusForbidden)
				return
			}
		}

		// Add security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		next.ServeHTTP(w, r)
	})
}

// Helper functions

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to remote address
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func generateSecurityEventID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// Password hashing utilities using Argon2
func HashPassword(password string) (string, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	// Encode salt and hash as hex and combine
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(hash), nil
}

func VerifyPassword(password, hashedPassword string) bool {
	parts := strings.Split(hashedPassword, ":")
	if len(parts) != 2 {
		return false
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return false
	}

	expectedHash, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}

	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	return subtle.ConstantTimeCompare(hash, expectedHash) == 1
}