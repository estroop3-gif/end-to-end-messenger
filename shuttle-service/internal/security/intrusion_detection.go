package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// IntrusionDetectionSystem monitors and detects suspicious activities
type IntrusionDetectionSystem struct {
	config          IDSConfig
	logger          *zap.Logger
	patterns        map[string]*regexp.Regexp
	ipTracker       *IPTracker
	alertManager    *AlertManager
	ruleset         *Ruleset
	mu              sync.RWMutex
	enabled         bool
}

// IDSConfig contains configuration for the intrusion detection system
type IDSConfig struct {
	// Enabled controls whether IDS is active
	Enabled bool `json:"enabled"`

	// ScanningThreshold defines suspicious scanning behavior
	ScanningThreshold ScanningConfig `json:"scanning_threshold"`

	// BruteForceThreshold defines brute force attack detection
	BruteForceThreshold BruteForceConfig `json:"brute_force_threshold"`

	// RateLimitThreshold defines rate limiting violations
	RateLimitThreshold RateLimitConfig `json:"rate_limit_threshold"`

	// SQLInjectionPatterns contains SQL injection detection patterns
	SQLInjectionPatterns []string `json:"sql_injection_patterns"`

	// XSSPatterns contains cross-site scripting detection patterns
	XSSPatterns []string `json:"xss_patterns"`

	// PayloadAnomalyThreshold for detecting unusual payload sizes/patterns
	PayloadAnomalyThreshold PayloadConfig `json:"payload_anomaly_threshold"`

	// GeoLocationBlocking blocks requests from specific countries
	GeoLocationBlocking GeoBlockConfig `json:"geo_location_blocking"`

	// AlertWebhooks contains URLs to send alerts to
	AlertWebhooks []string `json:"alert_webhooks"`

	// LogLevel for IDS events
	LogLevel string `json:"log_level"`

	// RetentionPeriod for keeping tracking data
	RetentionPeriod time.Duration `json:"retention_period"`
}

type ScanningConfig struct {
	RequestsPerMinute   int           `json:"requests_per_minute"`
	UniquePathsPerHour  int           `json:"unique_paths_per_hour"`
	ErrorRateThreshold  float64       `json:"error_rate_threshold"`
	SuspiciousUserAgent []string      `json:"suspicious_user_agents"`
	WindowSize          time.Duration `json:"window_size"`
}

type BruteForceConfig struct {
	FailedAttemptsThreshold int           `json:"failed_attempts_threshold"`
	TimeWindow              time.Duration `json:"time_window"`
	LockoutDuration         time.Duration `json:"lockout_duration"`
	MonitoredEndpoints      []string      `json:"monitored_endpoints"`
}

type RateLimitConfig struct {
	ViolationsThreshold int           `json:"violations_threshold"`
	MonitoringWindow    time.Duration `json:"monitoring_window"`
	EscalationRatio     float64       `json:"escalation_ratio"`
}

type PayloadConfig struct {
	MaxSizeBytes      int64   `json:"max_size_bytes"`
	CompressionRatio  float64 `json:"compression_ratio"`
	EntropyThreshold  float64 `json:"entropy_threshold"`
	BinaryDataRatio   float64 `json:"binary_data_ratio"`
}

type GeoBlockConfig struct {
	Enabled         bool     `json:"enabled"`
	BlockedCountries []string `json:"blocked_countries"`
	AllowedCountries []string `json:"allowed_countries"`
	DatabasePath     string   `json:"database_path"`
}

// ThreatLevel represents the severity of a detected threat
type ThreatLevel int

const (
	ThreatLevelInfo ThreatLevel = iota
	ThreatLevelLow
	ThreatLevelMedium
	ThreatLevelHigh
	ThreatLevelCritical
)

func (t ThreatLevel) String() string {
	switch t {
	case ThreatLevelInfo:
		return "INFO"
	case ThreatLevelLow:
		return "LOW"
	case ThreatLevelMedium:
		return "MEDIUM"
	case ThreatLevelHigh:
		return "HIGH"
	case ThreatLevelCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// SecurityEvent represents a detected security event
type SecurityEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"`
	ThreatLevel ThreatLevel            `json:"threat_level"`
	SourceIP    string                 `json:"source_ip"`
	UserAgent   string                 `json:"user_agent"`
	RequestURI  string                 `json:"request_uri"`
	Method      string                 `json:"method"`
	Headers     map[string]string      `json:"headers"`
	Payload     string                 `json:"payload,omitempty"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
	Action      string                 `json:"action"` // "blocked", "monitored", "allowed"
}

// IPTracker tracks IP-based statistics and behaviors
type IPTracker struct {
	requests        map[string]*RequestStats
	lockouts        map[string]time.Time
	mu              sync.RWMutex
	cleanupInterval time.Duration
}

type RequestStats struct {
	TotalRequests    int64
	FailedRequests   int64
	UniqueEndpoints  map[string]bool
	LastSeen         time.Time
	FirstSeen        time.Time
	UserAgents       map[string]int
	ErrorCodes       map[int]int
	PayloadSizes     []int64
	GeoLocation      string
	RateLimitViolations int
}

// NewIntrusionDetectionSystem creates a new IDS instance
func NewIntrusionDetectionSystem(config IDSConfig, logger *zap.Logger) (*IntrusionDetectionSystem, error) {
	ids := &IntrusionDetectionSystem{
		config:       config,
		logger:       logger,
		patterns:     make(map[string]*regexp.Regexp),
		enabled:      config.Enabled,
		ipTracker:    NewIPTracker(config.RetentionPeriod),
		alertManager: NewAlertManager(config.AlertWebhooks, logger),
		ruleset:      NewRuleset(),
	}

	if !config.Enabled {
		logger.Info("Intrusion Detection System is disabled")
		return ids, nil
	}

	// Compile attack patterns
	if err := ids.compilePatterns(); err != nil {
		return nil, fmt.Errorf("failed to compile attack patterns: %w", err)
	}

	// Start background cleanup
	go ids.startCleanup()

	logger.Info("Intrusion Detection System initialized",
		zap.Bool("enabled", config.Enabled),
		zap.Int("sql_patterns", len(config.SQLInjectionPatterns)),
		zap.Int("xss_patterns", len(config.XSSPatterns)))

	return ids, nil
}

// AnalyzeRequest analyzes an HTTP request for security threats
func (ids *IntrusionDetectionSystem) AnalyzeRequest(r *http.Request, responseCode int, responseSize int64) []SecurityEvent {
	if !ids.enabled {
		return nil
	}

	var events []SecurityEvent
	clientIP := extractClientIP(r)

	// Update IP tracking statistics
	ids.ipTracker.UpdateStats(clientIP, r, responseCode, responseSize)

	// Check for various attack patterns
	events = append(events, ids.checkSQLInjection(r, clientIP)...)
	events = append(events, ids.checkXSS(r, clientIP)...)
	events = append(events, ids.checkScanning(r, clientIP)...)
	events = append(events, ids.checkBruteForce(r, clientIP, responseCode)...)
	events = append(events, ids.checkPayloadAnomalies(r, clientIP)...)
	events = append(events, ids.checkSuspiciousUserAgent(r, clientIP)...)
	events = append(events, ids.checkGeoLocation(r, clientIP)...)

	// Log and alert on events
	for _, event := range events {
		ids.handleSecurityEvent(event)
	}

	return events
}

// checkSQLInjection detects SQL injection attempts
func (ids *IntrusionDetectionSystem) checkSQLInjection(r *http.Request, clientIP string) []SecurityEvent {
	var events []SecurityEvent

	// Check query parameters
	for param, values := range r.URL.Query() {
		for _, value := range values {
			if ids.matchesPattern("sql_injection", value) {
				events = append(events, SecurityEvent{
					ID:          generateEventID(),
					Timestamp:   time.Now(),
					EventType:   "sql_injection_attempt",
					ThreatLevel: ThreatLevelHigh,
					SourceIP:    clientIP,
					UserAgent:   r.UserAgent(),
					RequestURI:  r.RequestURI,
					Method:      r.Method,
					Description: fmt.Sprintf("SQL injection pattern detected in parameter '%s'", param),
					Metadata: map[string]interface{}{
						"parameter": param,
						"value":     value,
					},
					Action: "blocked",
				})
			}
		}
	}

	// Check request body if present
	if r.Body != nil && r.ContentLength > 0 {
		// Note: In a real implementation, you'd need to carefully read and restore the body
		// This is a simplified example
		bodyStr := readRequestBody(r)
		if ids.matchesPattern("sql_injection", bodyStr) {
			events = append(events, SecurityEvent{
				ID:          generateEventID(),
				Timestamp:   time.Now(),
				EventType:   "sql_injection_attempt",
				ThreatLevel: ThreatLevelHigh,
				SourceIP:    clientIP,
				UserAgent:   r.UserAgent(),
				RequestURI:  r.RequestURI,
				Method:      r.Method,
				Description: "SQL injection pattern detected in request body",
				Payload:     truncateString(bodyStr, 500),
				Action:      "blocked",
			})
		}
	}

	return events
}

// checkXSS detects cross-site scripting attempts
func (ids *IntrusionDetectionSystem) checkXSS(r *http.Request, clientIP string) []SecurityEvent {
	var events []SecurityEvent

	// Check all parameters
	for param, values := range r.URL.Query() {
		for _, value := range values {
			if ids.matchesPattern("xss", value) {
				events = append(events, SecurityEvent{
					ID:          generateEventID(),
					Timestamp:   time.Now(),
					EventType:   "xss_attempt",
					ThreatLevel: ThreatLevelMedium,
					SourceIP:    clientIP,
					UserAgent:   r.UserAgent(),
					RequestURI:  r.RequestURI,
					Method:      r.Method,
					Description: fmt.Sprintf("XSS pattern detected in parameter '%s'", param),
					Metadata: map[string]interface{}{
						"parameter": param,
						"value":     value,
					},
					Action: "monitored",
				})
			}
		}
	}

	return events
}

// checkScanning detects scanning and reconnaissance behavior
func (ids *IntrusionDetectionSystem) checkScanning(r *http.Request, clientIP string) []SecurityEvent {
	var events []SecurityEvent

	stats := ids.ipTracker.GetStats(clientIP)
	if stats == nil {
		return events
	}

	config := ids.config.ScanningThreshold

	// Check request rate
	timeSinceFirst := time.Since(stats.FirstSeen)
	if timeSinceFirst > 0 {
		requestsPerMinute := float64(stats.TotalRequests) / timeSinceFirst.Minutes()
		if requestsPerMinute > float64(config.RequestsPerMinute) {
			events = append(events, SecurityEvent{
				ID:          generateEventID(),
				Timestamp:   time.Now(),
				EventType:   "high_request_rate",
				ThreatLevel: ThreatLevelMedium,
				SourceIP:    clientIP,
				UserAgent:   r.UserAgent(),
				RequestURI:  r.RequestURI,
				Method:      r.Method,
				Description: "Unusually high request rate detected",
				Metadata: map[string]interface{}{
					"requests_per_minute": requestsPerMinute,
					"threshold":           config.RequestsPerMinute,
					"total_requests":      stats.TotalRequests,
				},
				Action: "monitored",
			})
		}
	}

	// Check unique endpoints accessed
	if len(stats.UniqueEndpoints) > config.UniquePathsPerHour {
		events = append(events, SecurityEvent{
			ID:          generateEventID(),
			Timestamp:   time.Now(),
			EventType:   "endpoint_scanning",
			ThreatLevel: ThreatLevelMedium,
			SourceIP:    clientIP,
			UserAgent:   r.UserAgent(),
			RequestURI:  r.RequestURI,
			Method:      r.Method,
			Description: "Scanning behavior detected (many unique endpoints)",
			Metadata: map[string]interface{}{
				"unique_endpoints": len(stats.UniqueEndpoints),
				"threshold":        config.UniquePathsPerHour,
			},
			Action: "monitored",
		})
	}

	// Check error rate
	if stats.TotalRequests > 10 {
		errorRate := float64(stats.FailedRequests) / float64(stats.TotalRequests)
		if errorRate > config.ErrorRateThreshold {
			events = append(events, SecurityEvent{
				ID:          generateEventID(),
				Timestamp:   time.Now(),
				EventType:   "high_error_rate",
				ThreatLevel: ThreatLevelLow,
				SourceIP:    clientIP,
				UserAgent:   r.UserAgent(),
				RequestURI:  r.RequestURI,
				Method:      r.Method,
				Description: "High error rate indicates possible probing",
				Metadata: map[string]interface{}{
					"error_rate":      errorRate,
					"threshold":       config.ErrorRateThreshold,
					"failed_requests": stats.FailedRequests,
					"total_requests":  stats.TotalRequests,
				},
				Action: "monitored",
			})
		}
	}

	return events
}

// checkBruteForce detects brute force attacks
func (ids *IntrusionDetectionSystem) checkBruteForce(r *http.Request, clientIP string, responseCode int) []SecurityEvent {
	var events []SecurityEvent

	config := ids.config.BruteForceThreshold

	// Check if this endpoint is monitored for brute force
	monitored := false
	for _, endpoint := range config.MonitoredEndpoints {
		if strings.Contains(r.URL.Path, endpoint) {
			monitored = true
			break
		}
	}

	if !monitored {
		return events
	}

	// Check for authentication failures (401, 403)
	if responseCode == 401 || responseCode == 403 {
		stats := ids.ipTracker.GetStats(clientIP)
		if stats != nil && stats.FailedRequests >= int64(config.FailedAttemptsThreshold) {
			// Check if failures occurred within time window
			if time.Since(stats.FirstSeen) <= config.TimeWindow {
				events = append(events, SecurityEvent{
					ID:          generateEventID(),
					Timestamp:   time.Now(),
					EventType:   "brute_force_attack",
					ThreatLevel: ThreatLevelHigh,
					SourceIP:    clientIP,
					UserAgent:   r.UserAgent(),
					RequestURI:  r.RequestURI,
					Method:      r.Method,
					Description: "Brute force attack detected",
					Metadata: map[string]interface{}{
						"failed_attempts": stats.FailedRequests,
						"threshold":       config.FailedAttemptsThreshold,
						"time_window":     config.TimeWindow.String(),
					},
					Action: "blocked",
				})

				// Add to lockout list
				ids.ipTracker.AddLockout(clientIP, config.LockoutDuration)
			}
		}
	}

	return events
}

// IsBlocked checks if an IP is currently blocked
func (ids *IntrusionDetectionSystem) IsBlocked(clientIP string) bool {
	if !ids.enabled {
		return false
	}
	return ids.ipTracker.IsLockedOut(clientIP)
}

// GetBlockedIPs returns a list of currently blocked IPs
func (ids *IntrusionDetectionSystem) GetBlockedIPs() map[string]time.Time {
	return ids.ipTracker.GetLockouts()
}

// UnblockIP removes an IP from the blocked list
func (ids *IntrusionDetectionSystem) UnblockIP(clientIP string) {
	ids.ipTracker.RemoveLockout(clientIP)
	ids.logger.Info("IP manually unblocked", zap.String("ip", clientIP))
}

// GetStats returns IDS statistics
func (ids *IntrusionDetectionSystem) GetStats() map[string]interface{} {
	if !ids.enabled {
		return map[string]interface{}{"enabled": false}
	}

	return map[string]interface{}{
		"enabled":         true,
		"tracked_ips":     ids.ipTracker.GetTrackedIPCount(),
		"blocked_ips":     len(ids.ipTracker.GetLockouts()),
		"pattern_count":   len(ids.patterns),
		"retention_period": ids.config.RetentionPeriod.String(),
	}
}

// Private helper methods

func (ids *IntrusionDetectionSystem) compilePatterns() error {
	// Compile SQL injection patterns
	for i, pattern := range ids.config.SQLInjectionPatterns {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid SQL injection pattern %d: %w", i, err)
		}
		ids.patterns[fmt.Sprintf("sql_injection_%d", i)] = regex
	}

	// Compile XSS patterns
	for i, pattern := range ids.config.XSSPatterns {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid XSS pattern %d: %w", i, err)
		}
		ids.patterns[fmt.Sprintf("xss_%d", i)] = regex
	}

	return nil
}

func (ids *IntrusionDetectionSystem) matchesPattern(patternType, text string) bool {
	for name, pattern := range ids.patterns {
		if strings.HasPrefix(name, patternType) && pattern.MatchString(text) {
			return true
		}
	}
	return false
}

func (ids *IntrusionDetectionSystem) handleSecurityEvent(event SecurityEvent) {
	// Log the event
	switch event.ThreatLevel {
	case ThreatLevelCritical, ThreatLevelHigh:
		ids.logger.Error("Security threat detected",
			zap.String("event_id", event.ID),
			zap.String("type", event.EventType),
			zap.String("level", event.ThreatLevel.String()),
			zap.String("source_ip", event.SourceIP),
			zap.String("description", event.Description))
	case ThreatLevelMedium:
		ids.logger.Warn("Security event detected",
			zap.String("event_id", event.ID),
			zap.String("type", event.EventType),
			zap.String("level", event.ThreatLevel.String()),
			zap.String("source_ip", event.SourceIP))
	default:
		ids.logger.Info("Security event detected",
			zap.String("event_id", event.ID),
			zap.String("type", event.EventType),
			zap.String("source_ip", event.SourceIP))
	}

	// Send alerts for high-severity events
	if event.ThreatLevel >= ThreatLevelHigh {
		ids.alertManager.SendAlert(event)
	}
}

func (ids *IntrusionDetectionSystem) startCleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		ids.ipTracker.CleanupExpired()
	}
}

// Utility functions

func extractClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.Split(xff, ",")[0]
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func generateEventID() string {
	return fmt.Sprintf("evt_%d", time.Now().UnixNano())
}

func readRequestBody(r *http.Request) string {
	// Simplified body reading - in production, implement proper body preservation
	return ""
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// Default attack patterns
func DefaultSQLInjectionPatterns() []string {
	return []string{
		`(?i)(union\s+(all\s+)?select)`,
		`(?i)(select\s+\*\s+from)`,
		`(?i)(insert\s+into\s+\w+)`,
		`(?i)(delete\s+from\s+\w+)`,
		`(?i)(update\s+\w+\s+set)`,
		`(?i)(drop\s+(table|database)\s+\w+)`,
		`(?i)(\'\s*or\s*\'\s*=\s*\')`,
		`(?i)(\'\s*or\s*1\s*=\s*1)`,
		`(?i)(exec\s*\(\s*@)`,
		`(?i)(script\s*>)`,
	}
}

func DefaultXSSPatterns() []string {
	return []string{
		`(?i)(<script[^>]*>.*?</script>)`,
		`(?i)(javascript\s*:)`,
		`(?i)(on\w+\s*=)`,
		`(?i)(<iframe[^>]*>)`,
		`(?i)(<object[^>]*>)`,
		`(?i)(<embed[^>]*>)`,
		`(?i)(<link[^>]*>)`,
		`(?i)(document\.(cookie|domain|write))`,
		`(?i)(window\.(location|open))`,
		`(?i)(eval\s*\()`,
	}
}