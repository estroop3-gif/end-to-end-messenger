package shuttle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"local-relay/internal/config"

	"go.uber.org/zap"
)

// Client represents a client for communicating with the shuttle service
type Client struct {
	config     config.ShuttleConfig
	httpClient *http.Client
	logger     *zap.Logger
	circuitBreaker *CircuitBreaker
	mu         sync.RWMutex
	healthy    bool
}

// OfferRequest represents a message offer to the shuttle
type OfferRequest struct {
	MessageID   string          `json:"message_id"`
	Recipient   string          `json:"recipient"`
	Payload     json.RawMessage `json:"payload"`
	TTL         int             `json:"ttl_seconds"`
	Priority    int             `json:"priority"`
	Metadata    OfferMetadata   `json:"metadata"`
}

// OfferMetadata contains additional information about the offer
type OfferMetadata struct {
	SenderHint    string `json:"sender_hint,omitempty"`
	ContentType   string `json:"content_type"`
	FrameSize     int    `json:"frame_size"`
	TimestampMs   int64  `json:"timestamp_ms"`
	RetryCount    int    `json:"retry_count"`
}

// OfferResponse represents the shuttle's response to an offer
type OfferResponse struct {
	MessageID    string `json:"message_id"`
	Accepted     bool   `json:"accepted"`
	QueuedUntil  int64  `json:"queued_until,omitempty"`
	ErrorCode    string `json:"error_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// ClaimRequest represents a request to claim messages
type ClaimRequest struct {
	ClientID       string   `json:"client_id"`
	MaxMessages    int      `json:"max_messages"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	MessageTypes   []string `json:"message_types,omitempty"`
}

// ClaimResponse represents the shuttle's response to a claim
type ClaimResponse struct {
	Messages  []ClaimedMessage `json:"messages"`
	More      bool            `json:"more"`
	NextToken string          `json:"next_token,omitempty"`
}

// ClaimedMessage represents a message claimed from the shuttle
type ClaimedMessage struct {
	MessageID   string          `json:"message_id"`
	Payload     json.RawMessage `json:"payload"`
	QueuedAt    int64          `json:"queued_at"`
	ClaimToken  string         `json:"claim_token"`
	TTL         int            `json:"ttl_remaining"`
	Metadata    OfferMetadata  `json:"metadata"`
}

// AckRequest represents an acknowledgment of message processing
type AckRequest struct {
	MessageID  string `json:"message_id"`
	ClaimToken string `json:"claim_token"`
	Success    bool   `json:"success"`
	ErrorCode  string `json:"error_code,omitempty"`
}

// HealthResponse represents the shuttle's health status
type HealthResponse struct {
	Status      string `json:"status"`
	Version     string `json:"version"`
	QueueLength int    `json:"queue_length"`
	Uptime      int64  `json:"uptime_seconds"`
}

// NewClient creates a new shuttle client
func NewClient(config config.ShuttleConfig, logger *zap.Logger) *Client {
	httpClient := &http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			MaxIdleConns:       10,
			IdleConnTimeout:    30 * time.Second,
			DisableCompression: false,
		},
	}

	client := &Client{
		config:     config,
		httpClient: httpClient,
		logger:     logger,
		healthy:    true,
	}

	// Initialize circuit breaker if enabled
	if config.Circuit.Enabled {
		client.circuitBreaker = NewCircuitBreaker(config.Circuit, logger)
	}

	// Start health check goroutine
	go client.healthCheckLoop()

	return client
}

// Offer sends a message offer to the shuttle service
func (c *Client) Offer(ctx context.Context, req *OfferRequest) (*OfferResponse, error) {
	if c.circuitBreaker != nil && c.circuitBreaker.IsOpen() {
		return nil, fmt.Errorf("circuit breaker is open")
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal offer request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/offer", c.config.URL)

	var resp *OfferResponse
	err = c.executeWithRetry(ctx, func() error {
		httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		c.setHeaders(httpReq)

		httpResp, err := c.httpClient.Do(httpReq)
		if err != nil {
			return fmt.Errorf("request failed: %w", err)
		}
		defer httpResp.Body.Close()

		if httpResp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(httpResp.Body)
			return fmt.Errorf("offer rejected: %d - %s", httpResp.StatusCode, string(bodyBytes))
		}

		resp = &OfferResponse{}
		if err := json.NewDecoder(httpResp.Body).Decode(resp); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}

		return nil
	})

	if err != nil {
		c.recordFailure()
		return nil, err
	}

	c.recordSuccess()
	return resp, nil
}

// Claim requests messages from the shuttle service
func (c *Client) Claim(ctx context.Context, req *ClaimRequest) (*ClaimResponse, error) {
	if c.circuitBreaker != nil && c.circuitBreaker.IsOpen() {
		return nil, fmt.Errorf("circuit breaker is open")
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claim request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/claim", c.config.URL)

	var resp *ClaimResponse
	err = c.executeWithRetry(ctx, func() error {
		httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		c.setHeaders(httpReq)

		httpResp, err := c.httpClient.Do(httpReq)
		if err != nil {
			return fmt.Errorf("request failed: %w", err)
		}
		defer httpResp.Body.Close()

		if httpResp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(httpResp.Body)
			return fmt.Errorf("claim failed: %d - %s", httpResp.StatusCode, string(bodyBytes))
		}

		resp = &ClaimResponse{}
		if err := json.NewDecoder(httpResp.Body).Decode(resp); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}

		return nil
	})

	if err != nil {
		c.recordFailure()
		return nil, err
	}

	c.recordSuccess()
	return resp, nil
}

// Ack acknowledges message processing
func (c *Client) Ack(ctx context.Context, req *AckRequest) error {
	if c.circuitBreaker != nil && c.circuitBreaker.IsOpen() {
		return fmt.Errorf("circuit breaker is open")
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal ack request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/ack", c.config.URL)

	err = c.executeWithRetry(ctx, func() error {
		httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		c.setHeaders(httpReq)

		httpResp, err := c.httpClient.Do(httpReq)
		if err != nil {
			return fmt.Errorf("request failed: %w", err)
		}
		defer httpResp.Body.Close()

		if httpResp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(httpResp.Body)
			return fmt.Errorf("ack failed: %d - %s", httpResp.StatusCode, string(bodyBytes))
		}

		return nil
	})

	if err != nil {
		c.recordFailure()
		return err
	}

	c.recordSuccess()
	return nil
}

// Health checks the shuttle service health
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	url := fmt.Sprintf("%s/api/v1/health", c.config.URL)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(httpReq)

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("health check failed: %d", httpResp.StatusCode)
	}

	var resp HealthResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &resp, nil
}

// IsHealthy returns the current health status
func (c *Client) IsHealthy() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.healthy
}

// Close closes the client and stops background processes
func (c *Client) Close() error {
	c.httpClient.CloseIdleConnections()
	return nil
}

// setHeaders sets common HTTP headers
func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "local-relay/1.0.0")

	if c.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.APIKey)
	}
}

// executeWithRetry executes a function with retry logic
func (c *Client) executeWithRetry(ctx context.Context, fn func() error) error {
	var lastErr error

	for attempt := 0; attempt <= c.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			delay := time.Duration(attempt) * c.config.RetryDelay
			if delay > c.config.MaxRetryDelay {
				delay = c.config.MaxRetryDelay
			}

			c.logger.Debug("Retrying shuttle request",
				zap.Int("attempt", attempt),
				zap.Duration("delay", delay))

			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		if err := fn(); err != nil {
			lastErr = err
			c.logger.Warn("Shuttle request failed",
				zap.Int("attempt", attempt),
				zap.Error(err))
			continue
		}

		return nil
	}

	return fmt.Errorf("all retry attempts failed: %w", lastErr)
}

// recordSuccess records a successful operation
func (c *Client) recordSuccess() {
	if c.circuitBreaker != nil {
		c.circuitBreaker.RecordSuccess()
	}
}

// recordFailure records a failed operation
func (c *Client) recordFailure() {
	if c.circuitBreaker != nil {
		c.circuitBreaker.RecordFailure()
	}
}

// healthCheckLoop performs periodic health checks
func (c *Client) healthCheckLoop() {
	ticker := time.NewTicker(c.config.HealthCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

		_, err := c.Health(ctx)

		c.mu.Lock()
		c.healthy = (err == nil)
		c.mu.Unlock()

		if err != nil {
			c.logger.Warn("Shuttle health check failed", zap.Error(err))
		} else {
			c.logger.Debug("Shuttle health check passed")
		}

		cancel()
	}
}