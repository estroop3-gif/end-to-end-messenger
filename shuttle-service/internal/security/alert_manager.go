package security

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// AlertManager handles security event alerting
type AlertManager struct {
	webhookURLs  []string
	logger       *zap.Logger
	client       *http.Client
	rateLimiter  map[string]time.Time
	mu           sync.RWMutex
}

// AlertPayload represents the payload sent to alert webhooks
type AlertPayload struct {
	Alert       SecurityEvent `json:"alert"`
	Timestamp   time.Time     `json:"timestamp"`
	Service     string        `json:"service"`
	Environment string        `json:"environment"`
	Severity    string        `json:"severity"`
	Summary     string        `json:"summary"`
}

// NewAlertManager creates a new alert manager
func NewAlertManager(webhookURLs []string, logger *zap.Logger) *AlertManager {
	return &AlertManager{
		webhookURLs: webhookURLs,
		logger:      logger,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		rateLimiter: make(map[string]time.Time),
	}
}

// SendAlert sends a security alert to configured webhooks
func (am *AlertManager) SendAlert(event SecurityEvent) {
	if len(am.webhookURLs) == 0 {
		return
	}

	// Rate limiting: don't send duplicate alerts too frequently
	alertKey := fmt.Sprintf("%s:%s", event.EventType, event.SourceIP)
	if am.isRateLimited(alertKey) {
		return
	}

	payload := AlertPayload{
		Alert:       event,
		Timestamp:   time.Now(),
		Service:     "shuttle-service",
		Environment: "production", // This could be configurable
		Severity:    event.ThreatLevel.String(),
		Summary:     fmt.Sprintf("%s from %s", event.EventType, event.SourceIP),
	}

	// Send to all configured webhooks
	for _, webhookURL := range am.webhookURLs {
		go am.sendWebhook(webhookURL, payload)
	}

	// Update rate limiter
	am.updateRateLimit(alertKey)
}

func (am *AlertManager) isRateLimited(alertKey string) bool {
	am.mu.RLock()
	defer am.mu.RUnlock()

	lastSent, exists := am.rateLimiter[alertKey]
	if !exists {
		return false
	}

	// Rate limit: same alert type + IP combination can only be sent once per 5 minutes
	return time.Since(lastSent) < 5*time.Minute
}

func (am *AlertManager) updateRateLimit(alertKey string) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.rateLimiter[alertKey] = time.Now()
}

func (am *AlertManager) sendWebhook(webhookURL string, payload AlertPayload) {
	data, err := json.Marshal(payload)
	if err != nil {
		am.logger.Error("Failed to marshal alert payload", zap.Error(err))
		return
	}

	resp, err := am.client.Post(webhookURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		am.logger.Error("Failed to send alert webhook",
			zap.String("url", webhookURL),
			zap.Error(err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		am.logger.Debug("Alert webhook sent successfully",
			zap.String("url", webhookURL),
			zap.String("event_type", payload.Alert.EventType))
	} else {
		am.logger.Warn("Alert webhook returned error status",
			zap.String("url", webhookURL),
			zap.Int("status", resp.StatusCode))
	}
}

// GetStats returns alert manager statistics
func (am *AlertManager) GetStats() map[string]interface{} {
	am.mu.RLock()
	defer am.mu.RUnlock()

	return map[string]interface{}{
		"webhook_count":        len(am.webhookURLs),
		"rate_limited_alerts":  len(am.rateLimiter),
	}
}