package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SecurityEvent represents a security-related event
type SecurityEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Source      string                 `json:"source"`
	Message     string                 `json:"message"`
	Details     map[string]interface{} `json:"details"`
	ClientIP    string                 `json:"client_ip,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	Fingerprint string                 `json:"fingerprint,omitempty"`
}

// SecurityMetrics holds security-related metrics
type SecurityMetrics struct {
	TotalEvents        int64             `json:"total_events"`
	EventsByType       map[string]int64  `json:"events_by_type"`
	EventsBySeverity   map[string]int64  `json:"events_by_severity"`
	RateLimitHits      int64             `json:"rate_limit_hits"`
	AuthFailures       int64             `json:"auth_failures"`
	SuspiciousActivity int64             `json:"suspicious_activity"`
	LastUpdate         time.Time         `json:"last_update"`
}

// SecurityAuditLogger handles security event logging and monitoring
type SecurityAuditLogger struct {
	events         []SecurityEvent
	metrics        SecurityMetrics
	mutex          sync.RWMutex
	logFile        *os.File
	maxEvents      int
	retentionHours int
	alertThreshold map[string]int // Alert thresholds per event type
}

// NewSecurityAuditLogger creates a new security audit logger
func NewSecurityAuditLogger(logPath string, maxEvents int, retentionHours int) (*SecurityAuditLogger, error) {
	// Ensure log directory exists
	logDir := filepath.Dir(logPath)
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %v", err)
	}

	// Open log file
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %v", err)
	}

	logger := &SecurityAuditLogger{
		events:         make([]SecurityEvent, 0, maxEvents),
		metrics:        SecurityMetrics{
			EventsByType:     make(map[string]int64),
			EventsBySeverity: make(map[string]int64),
			LastUpdate:       time.Now(),
		},
		logFile:        logFile,
		maxEvents:      maxEvents,
		retentionHours: retentionHours,
		alertThreshold: map[string]int{
			"rate_limit_exceeded":   10,
			"auth_failure":          5,
			"suspicious_request":    3,
			"tor_circuit_failure":   5,
			"memory_leak_detected":  1,
			"crypto_failure":        1,
		},
	}

	// Start cleanup routine
	go logger.cleanupRoutine()

	return logger, nil
}

// LogEvent logs a security event
func (sal *SecurityAuditLogger) LogEvent(eventType, severity, source, message string, details map[string]interface{}, r *http.Request) {
	event := SecurityEvent{
		ID:        generateEventID(),
		Timestamp: time.Now(),
		Type:      eventType,
		Severity:  severity,
		Source:    source,
		Message:   message,
		Details:   details,
	}

	// Add request context if available
	if r != nil {
		event.ClientIP = getClientIP(r)
		event.UserAgent = r.UserAgent()
		event.Fingerprint = r.URL.Query().Get("fingerprint")
	}

	sal.addEvent(event)
	sal.writeToFile(event)
	sal.checkAlerts(event)
}

// addEvent adds an event to the in-memory store
func (sal *SecurityAuditLogger) addEvent(event SecurityEvent) {
	sal.mutex.Lock()
	defer sal.mutex.Unlock()

	// Add to events list
	sal.events = append(sal.events, event)

	// Trim if exceeding max events
	if len(sal.events) > sal.maxEvents {
		sal.events = sal.events[len(sal.events)-sal.maxEvents:]
	}

	// Update metrics
	sal.metrics.TotalEvents++
	sal.metrics.EventsByType[event.Type]++
	sal.metrics.EventsBySeverity[event.Severity]++
	sal.metrics.LastUpdate = time.Now()

	// Update specific metrics
	switch event.Type {
	case "rate_limit_exceeded":
		sal.metrics.RateLimitHits++
	case "auth_failure":
		sal.metrics.AuthFailures++
	case "suspicious_request", "malicious_content", "anomaly_detected":
		sal.metrics.SuspiciousActivity++
	}
}

// writeToFile writes the event to the log file
func (sal *SecurityAuditLogger) writeToFile(event SecurityEvent) {
	if sal.logFile == nil {
		return
	}

	jsonData, err := json.Marshal(event)
	if err != nil {
		log.Printf("Failed to marshal security event: %v", err)
		return
	}

	if _, err := sal.logFile.Write(append(jsonData, '\n')); err != nil {
		log.Printf("Failed to write security event to file: %v", err)
	}
}

// checkAlerts checks if event triggers any alerts
func (sal *SecurityAuditLogger) checkAlerts(event SecurityEvent) {
	threshold, exists := sal.alertThreshold[event.Type]
	if !exists {
		return
	}

	// Count recent events of this type (last hour)
	sal.mutex.RLock()
	recentCount := 0
	cutoff := time.Now().Add(-time.Hour)

	for i := len(sal.events) - 1; i >= 0; i-- {
		if sal.events[i].Timestamp.Before(cutoff) {
			break
		}
		if sal.events[i].Type == event.Type {
			recentCount++
		}
	}
	sal.mutex.RUnlock()

	if recentCount >= threshold {
		sal.triggerAlert(event.Type, recentCount, threshold)
	}
}

// triggerAlert handles security alerts
func (sal *SecurityAuditLogger) triggerAlert(eventType string, count, threshold int) {
	alertEvent := SecurityEvent{
		ID:        generateEventID(),
		Timestamp: time.Now(),
		Type:      "security_alert",
		Severity:  "critical",
		Source:    "audit_logger",
		Message:   fmt.Sprintf("Security alert: %s events exceeded threshold", eventType),
		Details: map[string]interface{}{
			"trigger_event": eventType,
			"count":         count,
			"threshold":     threshold,
			"timeframe":     "1 hour",
		},
	}

	sal.addEvent(alertEvent)
	sal.writeToFile(alertEvent)

	log.Printf("SECURITY ALERT: %s - %d events in last hour (threshold: %d)",
		eventType, count, threshold)
}

// cleanupRoutine periodically cleans up old events
func (sal *SecurityAuditLogger) cleanupRoutine() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		sal.cleanupOldEvents()
	}
}

// cleanupOldEvents removes events older than retention period
func (sal *SecurityAuditLogger) cleanupOldEvents() {
	sal.mutex.Lock()
	defer sal.mutex.Unlock()

	cutoff := time.Now().Add(-time.Duration(sal.retentionHours) * time.Hour)
	newEvents := make([]SecurityEvent, 0, len(sal.events))

	for _, event := range sal.events {
		if event.Timestamp.After(cutoff) {
			newEvents = append(newEvents, event)
		}
	}

	removed := len(sal.events) - len(newEvents)
	sal.events = newEvents

	if removed > 0 {
		log.Printf("Cleaned up %d old security events", removed)
	}
}

// GetEvents returns recent security events
func (sal *SecurityAuditLogger) GetEvents(limit int, eventType, severity string) []SecurityEvent {
	sal.mutex.RLock()
	defer sal.mutex.RUnlock()

	var filtered []SecurityEvent

	// Filter events
	for i := len(sal.events) - 1; i >= 0 && len(filtered) < limit; i-- {
		event := sal.events[i]

		// Apply filters
		if eventType != "" && event.Type != eventType {
			continue
		}
		if severity != "" && event.Severity != severity {
			continue
		}

		filtered = append(filtered, event)
	}

	return filtered
}

// GetMetrics returns current security metrics
func (sal *SecurityAuditLogger) GetMetrics() SecurityMetrics {
	sal.mutex.RLock()
	defer sal.mutex.RUnlock()

	// Create a copy of metrics
	metrics := sal.metrics
	metrics.EventsByType = make(map[string]int64)
	metrics.EventsBySeverity = make(map[string]int64)

	for k, v := range sal.metrics.EventsByType {
		metrics.EventsByType[k] = v
	}
	for k, v := range sal.metrics.EventsBySeverity {
		metrics.EventsBySeverity[k] = v
	}

	return metrics
}

// LogRateLimitHit logs a rate limit violation
func (sal *SecurityAuditLogger) LogRateLimitHit(clientIP, endpoint string, r *http.Request) {
	sal.LogEvent("rate_limit_exceeded", "warning", "rate_limiter",
		"Rate limit exceeded", map[string]interface{}{
			"endpoint":  endpoint,
			"client_ip": clientIP,
		}, r)
}

// LogAuthFailure logs an authentication failure
func (sal *SecurityAuditLogger) LogAuthFailure(reason, fingerprint string, r *http.Request) {
	sal.LogEvent("auth_failure", "warning", "auth",
		"Authentication failed", map[string]interface{}{
			"reason":      reason,
			"fingerprint": fingerprint,
		}, r)
}

// LogSuspiciousRequest logs a suspicious request
func (sal *SecurityAuditLogger) LogSuspiciousRequest(reason string, r *http.Request) {
	sal.LogEvent("suspicious_request", "high", "request_validator",
		"Suspicious request detected", map[string]interface{}{
			"reason":     reason,
			"method":     r.Method,
			"url":        r.URL.String(),
			"headers":    getRelevantHeaders(r),
		}, r)
}

// LogTorEvent logs Tor-related security events
func (sal *SecurityAuditLogger) LogTorEvent(eventType, message string, details map[string]interface{}) {
	severity := "info"
	if eventType == "circuit_failure" || eventType == "connection_failure" {
		severity = "warning"
	}

	sal.LogEvent("tor_"+eventType, severity, "tor_manager", message, details, nil)
}

// LogCryptoEvent logs cryptography-related events
func (sal *SecurityAuditLogger) LogCryptoEvent(eventType, message string, details map[string]interface{}) {
	severity := "high"
	if eventType == "key_generation" || eventType == "successful_encryption" {
		severity = "info"
	}

	sal.LogEvent("crypto_"+eventType, severity, "crypto", message, details, nil)
}

// LogMemoryEvent logs memory protection events
func (sal *SecurityAuditLogger) LogMemoryEvent(eventType, message string, details map[string]interface{}) {
	sal.LogEvent("memory_"+eventType, "info", "memory_protection", message, details, nil)
}

// Helper functions

func generateEventID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Nanosecond())
}

func getClientIP(r *http.Request) string {
	// Check for forwarded headers
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}

func getRelevantHeaders(r *http.Request) map[string]string {
	relevant := []string{
		"User-Agent",
		"Accept",
		"Accept-Language",
		"Accept-Encoding",
		"Content-Type",
		"Authorization",
		"X-Forwarded-For",
		"X-Real-IP",
	}

	headers := make(map[string]string)
	for _, header := range relevant {
		if value := r.Header.Get(header); value != "" {
			headers[header] = value
		}
	}
	return headers
}

// Close closes the audit logger
func (sal *SecurityAuditLogger) Close() error {
	if sal.logFile != nil {
		return sal.logFile.Close()
	}
	return nil
}