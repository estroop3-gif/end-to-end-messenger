package queue

import (
	"context"
	"fmt"
	"time"

	"shuttle-service/internal/config"
	"shuttle-service/internal/storage"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// MessageQueue manages the message queuing system
type MessageQueue struct {
	storage       *storage.RedisStorage
	config        config.QueueConfig
	logger        *zap.Logger
	cleanupStop   chan struct{}
	cleanupDone   chan struct{}
}

// OfferRequest represents a message offer request
type OfferRequest struct {
	MessageID   string          `json:"message_id"`
	Recipient   string          `json:"recipient"`
	Payload     []byte          `json:"payload"`
	TTL         int             `json:"ttl_seconds"`
	Priority    int             `json:"priority"`
	Metadata    OfferMetadata   `json:"metadata"`
}

// OfferMetadata contains additional message metadata
type OfferMetadata struct {
	SenderHint    string `json:"sender_hint,omitempty"`
	ContentType   string `json:"content_type"`
	FrameSize     int    `json:"frame_size"`
	TimestampMs   int64  `json:"timestamp_ms"`
	RetryCount    int    `json:"retry_count"`
}

// OfferResponse represents the response to an offer request
type OfferResponse struct {
	MessageID    string `json:"message_id"`
	Accepted     bool   `json:"accepted"`
	QueuedUntil  int64  `json:"queued_until,omitempty"`
	ErrorCode    string `json:"error_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// ClaimRequest represents a message claim request
type ClaimRequest struct {
	ClientID       string   `json:"client_id"`
	MaxMessages    int      `json:"max_messages"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	MessageTypes   []string `json:"message_types,omitempty"`
}

// ClaimResponse represents the response to a claim request
type ClaimResponse struct {
	Messages  []ClaimedMessage `json:"messages"`
	More      bool            `json:"more"`
	NextToken string          `json:"next_token,omitempty"`
}

// ClaimedMessage represents a claimed message
type ClaimedMessage struct {
	MessageID   string                     `json:"message_id"`
	Payload     []byte                     `json:"payload"`
	QueuedAt    int64                      `json:"queued_at"`
	ClaimToken  string                     `json:"claim_token"`
	TTL         int                        `json:"ttl_remaining"`
	Metadata    storage.MessageMetadata    `json:"metadata"`
}

// AckRequest represents a message acknowledgment
type AckRequest struct {
	MessageID  string `json:"message_id"`
	ClaimToken string `json:"claim_token"`
	Success    bool   `json:"success"`
	ErrorCode  string `json:"error_code,omitempty"`
}

// NewMessageQueue creates a new message queue
func NewMessageQueue(storage *storage.RedisStorage, config config.QueueConfig, logger *zap.Logger) *MessageQueue {
	return &MessageQueue{
		storage:     storage,
		config:      config,
		logger:      logger,
		cleanupStop: make(chan struct{}),
		cleanupDone: make(chan struct{}),
	}
}

// Offer processes a message offer request
func (mq *MessageQueue) Offer(ctx context.Context, req *OfferRequest) (*OfferResponse, error) {
	// Validate request
	if err := mq.validateOfferRequest(req); err != nil {
		return &OfferResponse{
			MessageID:    req.MessageID,
			Accepted:     false,
			ErrorCode:    "INVALID_REQUEST",
			ErrorMessage: err.Error(),
		}, nil
	}

	// Check queue capacity
	queueInfo, err := mq.storage.GetQueueInfo(ctx, req.Recipient)
	if err != nil {
		mq.logger.Error("Failed to get queue info", zap.Error(err))
		return &OfferResponse{
			MessageID:    req.MessageID,
			Accepted:     false,
			ErrorCode:    "INTERNAL_ERROR",
			ErrorMessage: "Failed to check queue capacity",
		}, nil
	}

	if length, ok := queueInfo["length"].(int64); ok && length >= int64(mq.config.MaxQueueSize) {
		return &OfferResponse{
			MessageID:    req.MessageID,
			Accepted:     false,
			ErrorCode:    "QUEUE_FULL",
			ErrorMessage: fmt.Sprintf("Queue for recipient %s is full", req.Recipient),
		}, nil
	}

	// Create message
	now := time.Now()
	ttl := req.TTL
	if ttl <= 0 {
		ttl = int(mq.config.DefaultTTL.Seconds())
	}
	if ttl > int(mq.config.MaxTTL.Seconds()) {
		ttl = int(mq.config.MaxTTL.Seconds())
	}

	message := &storage.Message{
		ID:        req.MessageID,
		Recipient: req.Recipient,
		Payload:   req.Payload,
		QueuedAt:  now.Unix(),
		TTL:       ttl,
		Priority:  req.Priority,
		Metadata: storage.MessageMetadata{
			SenderHint:  req.Metadata.SenderHint,
			ContentType: req.Metadata.ContentType,
			FrameSize:   req.Metadata.FrameSize,
			TimestampMs: req.Metadata.TimestampMs,
			RetryCount:  req.Metadata.RetryCount,
		},
		RetryCount: 0,
		DeadLetter: false,
	}

	// Store message
	if err := mq.storage.StoreMessage(ctx, message); err != nil {
		mq.logger.Error("Failed to store message",
			zap.String("message_id", req.MessageID),
			zap.Error(err))
		return &OfferResponse{
			MessageID:    req.MessageID,
			Accepted:     false,
			ErrorCode:    "STORAGE_ERROR",
			ErrorMessage: "Failed to store message",
		}, nil
	}

	queuedUntil := now.Add(time.Duration(ttl) * time.Second).Unix()

	mq.logger.Info("Message offered and accepted",
		zap.String("message_id", req.MessageID),
		zap.String("recipient", req.Recipient),
		zap.Int("ttl", ttl),
		zap.Int("priority", req.Priority))

	return &OfferResponse{
		MessageID:   req.MessageID,
		Accepted:    true,
		QueuedUntil: queuedUntil,
	}, nil
}

// Claim processes a message claim request
func (mq *MessageQueue) Claim(ctx context.Context, req *ClaimRequest) (*ClaimResponse, error) {
	// Validate request
	if err := mq.validateClaimRequest(req); err != nil {
		return nil, fmt.Errorf("invalid claim request: %w", err)
	}

	// Generate claim token
	claimToken := uuid.New().String()

	// Claim messages
	messages, err := mq.storage.ClaimMessages(ctx, req.ClientID, req.MaxMessages, claimToken)
	if err != nil {
		return nil, fmt.Errorf("failed to claim messages: %w", err)
	}

	// Convert to response format
	claimedMessages := make([]ClaimedMessage, len(messages))
	for i, msg := range messages {
		// Calculate remaining TTL
		remainingTTL := int(time.Unix(msg.QueuedAt, 0).Add(time.Duration(msg.TTL)*time.Second).Sub(time.Now()).Seconds())
		if remainingTTL < 0 {
			remainingTTL = 0
		}

		claimedMessages[i] = ClaimedMessage{
			MessageID:  msg.ID,
			Payload:    msg.Payload,
			QueuedAt:   msg.QueuedAt,
			ClaimToken: claimToken,
			TTL:        remainingTTL,
			Metadata:   msg.Metadata,
		}
	}

	// Check if there are more messages
	queueInfo, _ := mq.storage.GetQueueInfo(ctx, req.ClientID)
	more := false
	if length, ok := queueInfo["length"].(int64); ok && length > 0 {
		more = true
	}

	mq.logger.Info("Messages claimed",
		zap.String("client_id", req.ClientID),
		zap.Int("count", len(claimedMessages)),
		zap.String("claim_token", claimToken),
		zap.Bool("more", more))

	return &ClaimResponse{
		Messages:  claimedMessages,
		More:      more,
		NextToken: "", // Could implement pagination token here
	}, nil
}

// Ack processes a message acknowledgment
func (mq *MessageQueue) Ack(ctx context.Context, req *AckRequest) error {
	// Validate request
	if req.MessageID == "" {
		return fmt.Errorf("message ID is required")
	}
	if req.ClaimToken == "" {
		return fmt.Errorf("claim token is required")
	}

	// Process acknowledgment
	if err := mq.storage.AckMessage(ctx, req.MessageID, req.ClaimToken, req.Success); err != nil {
		return fmt.Errorf("failed to ack message: %w", err)
	}

	mq.logger.Debug("Message acknowledged",
		zap.String("message_id", req.MessageID),
		zap.String("claim_token", req.ClaimToken),
		zap.Bool("success", req.Success),
		zap.String("error_code", req.ErrorCode))

	return nil
}

// GetStats returns queue statistics
func (mq *MessageQueue) GetStats(ctx context.Context) (map[string]interface{}, error) {
	stats, err := mq.storage.GetStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}

	// Add queue-specific stats
	stats["config"] = map[string]interface{}{
		"default_ttl":      mq.config.DefaultTTL.String(),
		"max_ttl":          mq.config.MaxTTL.String(),
		"max_message_size": mq.config.MaxMessageSize,
		"max_queue_size":   mq.config.MaxQueueSize,
		"max_retries":      mq.config.MaxRetries,
	}

	return stats, nil
}

// GetQueueInfo returns information about a specific queue
func (mq *MessageQueue) GetQueueInfo(ctx context.Context, recipient string) (map[string]interface{}, error) {
	return mq.storage.GetQueueInfo(ctx, recipient)
}

// StartCleanup starts the background cleanup process
func (mq *MessageQueue) StartCleanup() {
	go mq.cleanupLoop()
}

// StopCleanup stops the background cleanup process
func (mq *MessageQueue) StopCleanup() {
	close(mq.cleanupStop)
	<-mq.cleanupDone
}

// cleanupLoop runs the periodic cleanup process
func (mq *MessageQueue) cleanupLoop() {
	defer close(mq.cleanupDone)

	ticker := time.NewTicker(mq.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := mq.storage.CleanupExpired(ctx); err != nil {
				mq.logger.Error("Cleanup failed", zap.Error(err))
			} else {
				mq.logger.Debug("Cleanup completed")
			}
			cancel()

		case <-mq.cleanupStop:
			mq.logger.Info("Cleanup loop stopped")
			return
		}
	}
}

// validateOfferRequest validates an offer request
func (mq *MessageQueue) validateOfferRequest(req *OfferRequest) error {
	if req.MessageID == "" {
		return fmt.Errorf("message ID is required")
	}

	if req.Recipient == "" {
		return fmt.Errorf("recipient is required")
	}

	if len(req.Payload) == 0 {
		return fmt.Errorf("payload is required")
	}

	if len(req.Payload) > mq.config.MaxMessageSize {
		return fmt.Errorf("payload too large: %d bytes (max: %d)", len(req.Payload), mq.config.MaxMessageSize)
	}

	if req.TTL > int(mq.config.MaxTTL.Seconds()) {
		return fmt.Errorf("TTL too large: %d seconds (max: %d)", req.TTL, int(mq.config.MaxTTL.Seconds()))
	}

	if req.Priority < 0 || req.Priority > 10 {
		return fmt.Errorf("priority must be between 0 and 10")
	}

	return nil
}

// validateClaimRequest validates a claim request
func (mq *MessageQueue) validateClaimRequest(req *ClaimRequest) error {
	if req.ClientID == "" {
		return fmt.Errorf("client ID is required")
	}

	if req.MaxMessages <= 0 {
		req.MaxMessages = 10 // Default
	}

	if req.MaxMessages > 100 {
		return fmt.Errorf("max messages too large: %d (max: 100)", req.MaxMessages)
	}

	if req.TimeoutSeconds < 0 {
		req.TimeoutSeconds = 30 // Default
	}

	if req.TimeoutSeconds > 300 {
		return fmt.Errorf("timeout too large: %d seconds (max: 300)", req.TimeoutSeconds)
	}

	return nil
}