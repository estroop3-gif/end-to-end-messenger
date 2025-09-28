package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// SecurityMiddleware handles advanced security protections
type SecurityMiddleware struct {
	auditLogger    *SecurityAuditLogger
	rateLimiters   map[string]*rate.Limiter
	rateMutex      sync.RWMutex
	blockedIPs     map[string]time.Time
	blockMutex     sync.RWMutex
	suspiciousIPs  map[string]int
	suspMutex      sync.RWMutex

	// Configuration
	maxRequestSize     int64
	maxHeaderSize      int64
	blockDuration      time.Duration
	suspiciousThreshold int
	strictMode         bool
}

// SecurityConfig holds security middleware configuration
type SecurityConfig struct {
	MaxRequestSize      int64         `json:"max_request_size"`
	MaxHeaderSize       int64         `json:"max_header_size"`
	BlockDuration       time.Duration `json:"block_duration"`
	SuspiciousThreshold int           `json:"suspicious_threshold"`
	StrictMode          bool          `json:"strict_mode"`
	RateLimit           struct {
		RequestsPerMinute int `json:"requests_per_minute"`
		BurstLimit       int `json:"burst_limit"`
	} `json:"rate_limit"`
}

// NewSecurityMiddleware creates a new security middleware
func NewSecurityMiddleware(auditLogger *SecurityAuditLogger, config SecurityConfig) *SecurityMiddleware {
	return &SecurityMiddleware{
		auditLogger:         auditLogger,
		rateLimiters:        make(map[string]*rate.Limiter),
		blockedIPs:          make(map[string]time.Time),
		suspiciousIPs:       make(map[string]int),
		maxRequestSize:      config.MaxRequestSize,
		maxHeaderSize:       config.MaxHeaderSize,
		blockDuration:       config.BlockDuration,
		suspiciousThreshold: config.SuspiciousThreshold,
		strictMode:          config.StrictMode,
	}
}

// SecurityHandler wraps HTTP handlers with security protections
func (sm *SecurityMiddleware) SecurityHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)

		// Check if IP is blocked
		if sm.isBlocked(clientIP) {
			sm.auditLogger.LogEvent("blocked_request", "info", "security_middleware",
				"Request from blocked IP", map[string]interface{}{
					"client_ip": clientIP,
					"url":       r.URL.String(),
				}, r)
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		// Rate limiting
		if !sm.checkRateLimit(clientIP, r) {
			sm.auditLogger.LogRateLimitHit(clientIP, r.URL.Path, r)
			sm.markSuspicious(clientIP, "rate_limit_exceeded")
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// Request validation
		if !sm.validateRequest(r) {
			sm.auditLogger.LogSuspiciousRequest("invalid_request", r)
			sm.markSuspicious(clientIP, "invalid_request")
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		// Security headers
		sm.setSecurityHeaders(w)

		// Content type validation for POST/PUT requests
		if r.Method == "POST" || r.Method == "PUT" {
			if !sm.validateContentType(r) {
				sm.auditLogger.LogSuspiciousRequest("invalid_content_type", r)
				sm.markSuspicious(clientIP, "invalid_content_type")
				http.Error(w, "Invalid content type", http.StatusBadRequest)
				return
			}
		}

		// Wrap response writer to capture response codes
		wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}

		// Call next handler
		next.ServeHTTP(wrapped, r)

		// Log successful requests
		sm.auditLogger.LogEvent("request_processed", "info", "security_middleware",
			"Request processed successfully", map[string]interface{}{
				"method":      r.Method,
				"url":         r.URL.String(),
				"status_code": wrapped.statusCode,
				"client_ip":   clientIP,
			}, r)
	})
}

// checkRateLimit implements advanced rate limiting
func (sm *SecurityMiddleware) checkRateLimit(clientIP string, r *http.Request) bool {
	sm.rateMutex.Lock()
	limiter, exists := sm.rateLimiters[clientIP]
	if !exists {
		// Different limits for different endpoints
		var limit rate.Limit
		var burst int

		switch {
		case strings.HasPrefix(r.URL.Path, "/ws"):
			limit = rate.Every(time.Minute / 10) // 10 connections per minute
			burst = 2
		case strings.HasPrefix(r.URL.Path, "/tor/"):
			limit = rate.Every(time.Minute / 30) // 30 requests per minute
			burst = 5
		default:
			limit = rate.Every(time.Minute / 60) // 60 requests per minute
			burst = 10
		}

		limiter = rate.NewLimiter(limit, burst)
		sm.rateLimiters[clientIP] = limiter
	}
	sm.rateMutex.Unlock()

	return limiter.Allow()
}

// validateRequest performs comprehensive request validation
func (sm *SecurityMiddleware) validateRequest(r *http.Request) bool {
	// Check request size
	if r.ContentLength > sm.maxRequestSize {
		return false
	}

	// Check header size
	headerSize := int64(0)
	for name, values := range r.Header {
		headerSize += int64(len(name))
		for _, value := range values {
			headerSize += int64(len(value))
		}
		if headerSize > sm.maxHeaderSize {
			return false
		}
	}

	// Check for suspicious patterns in URL
	if sm.hasSuspiciousURLPatterns(r.URL.String()) {
		return false
	}

	// Check for suspicious headers
	if sm.hasSuspiciousHeaders(r) {
		return false
	}

	// Check HTTP method
	allowedMethods := []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"}
	methodAllowed := false
	for _, method := range allowedMethods {
		if r.Method == method {
			methodAllowed = true
			break
		}
	}
	if !methodAllowed {
		return false
	}

	return true
}

// hasSuspiciousURLPatterns checks for suspicious URL patterns
func (sm *SecurityMiddleware) hasSuspiciousURLPatterns(url string) bool {
	suspiciousPatterns := []*regexp.Regexp{
		regexp.MustCompile(`\.\./`),                    // Directory traversal
		regexp.MustCompile(`[<>'"&]`),                  // XSS attempts
		regexp.MustCompile(`(union|select|insert|drop|delete|update)\s+`, regexp.IgnoreCase), // SQL injection
		regexp.MustCompile(`javascript:`),              // JavaScript injection
		regexp.MustCompile(`vbscript:`),               // VBScript injection
		regexp.MustCompile(`onload|onerror|onclick`),   // Event handlers
		regexp.MustCompile(`\x00`),                     // Null bytes
		regexp.MustCompile(`\.(php|asp|jsp|cgi)$`),     // Script files
	}

	for _, pattern := range suspiciousPatterns {
		if pattern.MatchString(url) {
			return true
		}
	}

	return false
}

// hasSuspiciousHeaders checks for suspicious HTTP headers
func (sm *SecurityMiddleware) hasSuspiciousHeaders(r *http.Request) bool {
	// Check User-Agent
	userAgent := r.Header.Get("User-Agent")
	if userAgent == "" && sm.strictMode {
		return true // Missing User-Agent in strict mode
	}

	// Check for automated tools
	suspiciousAgents := []string{
		"curl", "wget", "python-requests", "go-http-client",
		"scanner", "bot", "crawler", "nikto", "sqlmap",
	}

	userAgentLower := strings.ToLower(userAgent)
	for _, agent := range suspiciousAgents {
		if strings.Contains(userAgentLower, agent) && sm.strictMode {
			return true
		}
	}

	// Check for suspicious headers
	suspiciousHeaders := []string{
		"X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL",
		"X-Arbitrary-Header", "Proxy-Connection",
	}

	for _, header := range suspiciousHeaders {
		if r.Header.Get(header) != "" && sm.strictMode {
			return true
		}
	}

	return false
}

// validateContentType validates Content-Type header
func (sm *SecurityMiddleware) validateContentType(r *http.Request) bool {
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		return false
	}

	allowedTypes := []string{
		"application/json",
		"application/x-www-form-urlencoded",
		"multipart/form-data",
		"text/plain",
	}

	for _, allowedType := range allowedTypes {
		if strings.HasPrefix(contentType, allowedType) {
			return true
		}
	}

	return false
}

// setSecurityHeaders sets important security headers
func (sm *SecurityMiddleware) setSecurityHeaders(w http.ResponseWriter) {
	headers := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"X-XSS-Protection":          "1; mode=block",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Content-Security-Policy":   "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; media-src 'none'; child-src 'none';",
		"Permissions-Policy":        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), accelerometer=(), gyroscope=()",
		"Cache-Control":             "no-store, no-cache, must-revalidate, private",
		"Pragma":                    "no-cache",
		"Expires":                   "0",
	}

	for header, value := range headers {
		w.Header().Set(header, value)
	}
}

// markSuspicious marks an IP as suspicious
func (sm *SecurityMiddleware) markSuspicious(clientIP, reason string) {
	sm.suspMutex.Lock()
	defer sm.suspMutex.Unlock()

	count := sm.suspiciousIPs[clientIP] + 1
	sm.suspiciousIPs[clientIP] = count

	sm.auditLogger.LogEvent("suspicious_activity", "warning", "security_middleware",
		"IP marked as suspicious", map[string]interface{}{
			"client_ip": clientIP,
			"reason":    reason,
			"count":     count,
		}, nil)

	// Block IP if threshold exceeded
	if count >= sm.suspiciousThreshold {
		sm.blockIP(clientIP, reason)
	}
}

// blockIP blocks an IP address
func (sm *SecurityMiddleware) blockIP(clientIP, reason string) {
	sm.blockMutex.Lock()
	defer sm.blockMutex.Unlock()

	sm.blockedIPs[clientIP] = time.Now().Add(sm.blockDuration)

	sm.auditLogger.LogEvent("ip_blocked", "high", "security_middleware",
		"IP address blocked", map[string]interface{}{
			"client_ip":      clientIP,
			"reason":         reason,
			"block_duration": sm.blockDuration.String(),
		}, nil)
}

// isBlocked checks if an IP is currently blocked
func (sm *SecurityMiddleware) isBlocked(clientIP string) bool {
	sm.blockMutex.RLock()
	defer sm.blockMutex.RUnlock()

	blockUntil, exists := sm.blockedIPs[clientIP]
	if !exists {
		return false
	}

	if time.Now().After(blockUntil) {
		// Block expired, remove it
		delete(sm.blockedIPs, clientIP)
		return false
	}

	return true
}

// InputSanitizer provides input sanitization functions
type InputSanitizer struct{}

// SanitizeString removes potentially dangerous characters
func (is *InputSanitizer) SanitizeString(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")

	// Remove control characters except newline and tab
	var result strings.Builder
	for _, r := range input {
		if r >= 32 || r == '\n' || r == '\t' {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// SanitizeJSON validates and sanitizes JSON input
func (is *InputSanitizer) SanitizeJSON(input []byte, maxSize int) ([]byte, error) {
	if len(input) > maxSize {
		return nil, fmt.Errorf("JSON too large: %d bytes", len(input))
	}

	// Validate JSON structure
	var data interface{}
	if err := json.Unmarshal(input, &data); err != nil {
		return nil, fmt.Errorf("invalid JSON: %v", err)
	}

	// Re-marshal to ensure clean JSON
	clean, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to re-marshal JSON: %v", err)
	}

	return clean, nil
}

// ValidateFingerprint validates a client fingerprint
func (is *InputSanitizer) ValidateFingerprint(fingerprint string) bool {
	// Must be hex string of specific length
	if len(fingerprint) != 64 {
		return false
	}

	for _, r := range fingerprint {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}

	return true
}

// ValidateMessageID validates a message ID
func (is *InputSanitizer) ValidateMessageID(messageID string) bool {
	// UUID format validation
	uuidRegex := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	return uuidRegex.MatchString(messageID)
}

// XSSProtection provides XSS protection utilities
type XSSProtection struct{}

// SanitizeHTML removes potentially dangerous HTML
func (xss *XSSProtection) SanitizeHTML(input string) string {
	// Remove all HTML tags
	htmlRegex := regexp.MustCompile(`<[^>]*>`)
	cleaned := htmlRegex.ReplaceAllString(input, "")

	// Escape remaining dangerous characters
	cleaned = strings.ReplaceAll(cleaned, "<", "&lt;")
	cleaned = strings.ReplaceAll(cleaned, ">", "&gt;")
	cleaned = strings.ReplaceAll(cleaned, "\"", "&quot;")
	cleaned = strings.ReplaceAll(cleaned, "'", "&#x27;")
	cleaned = strings.ReplaceAll(cleaned, "&", "&amp;")

	return cleaned
}

// DetectXSSAttempt detects potential XSS attempts
func (xss *XSSProtection) DetectXSSAttempt(input string) bool {
	xssPatterns := []*regexp.Regexp{
		regexp.MustCompile(`<script[^>]*>.*?</script>`),
		regexp.MustCompile(`javascript:`),
		regexp.MustCompile(`vbscript:`),
		regexp.MustCompile(`onload\s*=`),
		regexp.MustCompile(`onerror\s*=`),
		regexp.MustCompile(`onclick\s*=`),
		regexp.MustCompile(`onmouseover\s*=`),
		regexp.MustCompile(`onfocus\s*=`),
		regexp.MustCompile(`<iframe[^>]*>`),
		regexp.MustCompile(`<object[^>]*>`),
		regexp.MustCompile(`<embed[^>]*>`),
	}

	inputLower := strings.ToLower(input)
	for _, pattern := range xssPatterns {
		if pattern.MatchString(inputLower) {
			return true
		}
	}

	return false
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Cleanup routines

// CleanupRoutine periodically cleans up old data
func (sm *SecurityMiddleware) CleanupRoutine() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		sm.cleanupExpiredBlocks()
		sm.cleanupOldRateLimiters()
		sm.cleanupSuspiciousIPs()
	}
}

func (sm *SecurityMiddleware) cleanupExpiredBlocks() {
	sm.blockMutex.Lock()
	defer sm.blockMutex.Unlock()

	now := time.Now()
	for ip, blockUntil := range sm.blockedIPs {
		if now.After(blockUntil) {
			delete(sm.blockedIPs, ip)
		}
	}
}

func (sm *SecurityMiddleware) cleanupOldRateLimiters() {
	sm.rateMutex.Lock()
	defer sm.rateMutex.Unlock()

	// Remove rate limiters that haven't been used recently
	// This is a simplified cleanup - in production, you'd track last access
	if len(sm.rateLimiters) > 1000 {
		// Keep only the most recent 500
		newLimiters := make(map[string]*rate.Limiter)
		count := 0
		for ip, limiter := range sm.rateLimiters {
			if count < 500 {
				newLimiters[ip] = limiter
				count++
			}
		}
		sm.rateLimiters = newLimiters
	}
}

func (sm *SecurityMiddleware) cleanupSuspiciousIPs() {
	sm.suspMutex.Lock()
	defer sm.suspMutex.Unlock()

	// Reset suspicious counts every hour
	sm.suspiciousIPs = make(map[string]int)
}