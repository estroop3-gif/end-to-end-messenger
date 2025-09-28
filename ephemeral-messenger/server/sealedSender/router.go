// Sealed Sender Routing for Ephemeral Messenger
//
// Implements sealed-sender routing to hide recipient identity from the relay.
// Uses opaque routing tokens while placing real recipient info inside AEAD payload.
//
// SECURITY: Server never learns recipient identity, only opaque routing tokens.
package sealedSender

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// RoutingToken represents an opaque token that maps to a real recipient
type RoutingToken struct {
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
}

// SealedMessage represents a message with hidden recipient
type SealedMessage struct {
	RoutingToken  string            `json:"routing_token"`
	EncryptedData []byte            `json:"encrypted_data"`
	Metadata      map[string]string `json:"metadata"`
	Timestamp     time.Time         `json:"timestamp"`
	TTL           time.Duration     `json:"ttl"`
}

// RouteMapping internal mapping between tokens and recipients
type RouteMapping struct {
	RecipientID  string    `json:"recipient_id"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	MessageCount int       `json:"message_count"`
	MaxMessages  int       `json:"max_messages"`
}

// SealedSenderRouter manages routing tokens and message delivery
type SealedSenderRouter struct {
	// Token mappings (never exposed to logs)
	tokenMappings map[string]*RouteMapping

	// Message queues per token
	messageQueues map[string][]*SealedMessage

	// Configuration
	defaultTTL        time.Duration
	maxTokenLifetime  time.Duration
	maxMessagesPerToken int
	cleanupInterval   time.Duration

	// Synchronization
	mutex sync.RWMutex

	// Metrics (safe to log)
	totalTokensCreated   int64
	totalMessagesRouted  int64
	activeTokenCount     int64
	expiredTokenCount    int64
}

// NewSealedSenderRouter creates a new sealed sender router
func NewSealedSenderRouter() *SealedSenderRouter {
	router := &SealedSenderRouter{
		tokenMappings:       make(map[string]*RouteMapping),
		messageQueues:       make(map[string][]*SealedMessage),
		defaultTTL:          24 * time.Hour,
		maxTokenLifetime:    7 * 24 * time.Hour, // 7 days max
		maxMessagesPerToken: 1000,
		cleanupInterval:     1 * time.Hour,
	}

	// Start background cleanup
	go router.cleanupExpiredTokens()

	return router
}

// CreateRoutingToken creates a new opaque routing token for a recipient
func (ssr *SealedSenderRouter) CreateRoutingToken(recipientID string, createdBy string, ttl time.Duration) (*RoutingToken, error) {
	ssr.mutex.Lock()
	defer ssr.mutex.Unlock()

	// Generate cryptographically secure token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate routing token: %v", err)
	}

	// Create token string (base64url for URL safety)
	tokenString := base64.RawURLEncoding.EncodeToString(tokenBytes)

	// Validate TTL
	if ttl <= 0 {
		ttl = ssr.defaultTTL
	}
	if ttl > ssr.maxTokenLifetime {
		ttl = ssr.maxTokenLifetime
	}

	now := time.Now()
	expiresAt := now.Add(ttl)

	// Create mapping
	mapping := &RouteMapping{
		RecipientID:  recipientID,
		CreatedBy:    createdBy,
		CreatedAt:    now,
		ExpiresAt:    expiresAt,
		MessageCount: 0,
		MaxMessages:  ssr.maxMessagesPerToken,
	}

	// Store mapping
	ssr.tokenMappings[tokenString] = mapping
	ssr.messageQueues[tokenString] = make([]*SealedMessage, 0)

	// Update metrics
	ssr.totalTokensCreated++
	ssr.activeTokenCount++

	return &RoutingToken{
		Token:     tokenString,
		CreatedAt: now,
		ExpiresAt: expiresAt,
		Used:      false,
	}, nil
}

// RouteMessage routes a message using the opaque token
func (ssr *SealedSenderRouter) RouteMessage(message *SealedMessage) error {
	ssr.mutex.Lock()
	defer ssr.mutex.Unlock()

	// Validate token exists and is active
	mapping, exists := ssr.tokenMappings[message.RoutingToken]
	if !exists {
		return fmt.Errorf("invalid routing token")
	}

	// Check if token has expired
	if time.Now().After(mapping.ExpiresAt) {
		return fmt.Errorf("routing token has expired")
	}

	// Check message limit
	if mapping.MessageCount >= mapping.MaxMessages {
		return fmt.Errorf("message limit exceeded for routing token")
	}

	// Set message timestamp if not provided
	if message.Timestamp.IsZero() {
		message.Timestamp = time.Now()
	}

	// Set default TTL if not provided
	if message.TTL <= 0 {
		message.TTL = ssr.defaultTTL
	}

	// Add to queue
	ssr.messageQueues[message.RoutingToken] = append(
		ssr.messageQueues[message.RoutingToken],
		message,
	)

	// Update counters
	mapping.MessageCount++
	ssr.totalMessagesRouted++

	return nil
}

// GetMessagesForToken retrieves messages for a routing token (recipient polls)
func (ssr *SealedSenderRouter) GetMessagesForToken(token string) ([]*SealedMessage, error) {
	ssr.mutex.Lock()
	defer ssr.mutex.Unlock()

	// Validate token
	mapping, exists := ssr.tokenMappings[token]
	if !exists {
		return nil, fmt.Errorf("invalid routing token")
	}

	// Check if token has expired
	if time.Now().After(mapping.ExpiresAt) {
		return nil, fmt.Errorf("routing token has expired")
	}

	// Get messages
	messages := ssr.messageQueues[token]
	if messages == nil {
		return []*SealedMessage{}, nil
	}

	// Filter out expired messages
	now := time.Now()
	validMessages := make([]*SealedMessage, 0)

	for _, msg := range messages {
		if now.Before(msg.Timestamp.Add(msg.TTL)) {
			validMessages = append(validMessages, msg)
		}
	}

	// Update queue with valid messages only
	ssr.messageQueues[token] = validMessages

	return validMessages, nil
}

// DeleteMessage removes a message after successful delivery
func (ssr *SealedSenderRouter) DeleteMessage(token string, messageIndex int) error {
	ssr.mutex.Lock()
	defer ssr.mutex.Unlock()

	messages, exists := ssr.messageQueues[token]
	if !exists {
		return fmt.Errorf("invalid routing token")
	}

	if messageIndex < 0 || messageIndex >= len(messages) {
		return fmt.Errorf("invalid message index")
	}

	// Remove message from queue
	ssr.messageQueues[token] = append(
		messages[:messageIndex],
		messages[messageIndex+1:]...,
	)

	return nil
}

// RevokeToken invalidates a routing token
func (ssr *SealedSenderRouter) RevokeToken(token string, revokedBy string) error {
	ssr.mutex.Lock()
	defer ssr.mutex.Unlock()

	mapping, exists := ssr.tokenMappings[token]
	if !exists {
		return fmt.Errorf("invalid routing token")
	}

	// Check authorization (only creator can revoke)
	if mapping.CreatedBy != revokedBy {
		return fmt.Errorf("not authorized to revoke token")
	}

	// Remove mapping and messages
	delete(ssr.tokenMappings, token)
	delete(ssr.messageQueues, token)

	ssr.activeTokenCount--

	return nil
}

// GetRoutingStats returns safe routing statistics (no recipient info)
func (ssr *SealedSenderRouter) GetRoutingStats() map[string]interface{} {
	ssr.mutex.RLock()
	defer ssr.mutex.RUnlock()

	return map[string]interface{}{
		"total_tokens_created":   ssr.totalTokensCreated,
		"total_messages_routed":  ssr.totalMessagesRouted,
		"active_token_count":     ssr.activeTokenCount,
		"expired_token_count":    ssr.expiredTokenCount,
		"queue_sizes": func() map[string]int {
			sizes := make(map[string]int)
			for token, queue := range ssr.messageQueues {
				// Hash the token for safe logging
				hasher := sha256.New()
				hasher.Write([]byte(token))
				hashedToken := fmt.Sprintf("%x", hasher.Sum(nil))[:8]
				sizes[hashedToken] = len(queue)
			}
			return sizes
		}(),
	}
}

// Background cleanup of expired tokens and messages
func (ssr *SealedSenderRouter) cleanupExpiredTokens() {
	ticker := time.NewTicker(ssr.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		ssr.performCleanup()
	}
}

func (ssr *SealedSenderRouter) performCleanup() {
	ssr.mutex.Lock()
	defer ssr.mutex.Unlock()

	now := time.Now()
	tokensToDelete := make([]string, 0)

	// Find expired tokens
	for token, mapping := range ssr.tokenMappings {
		if now.After(mapping.ExpiresAt) {
			tokensToDelete = append(tokensToDelete, token)
		}
	}

	// Remove expired tokens
	for _, token := range tokensToDelete {
		delete(ssr.tokenMappings, token)
		delete(ssr.messageQueues, token)
		ssr.activeTokenCount--
		ssr.expiredTokenCount++
	}

	// Clean up expired messages in remaining queues
	for token, messages := range ssr.messageQueues {
		validMessages := make([]*SealedMessage, 0)
		for _, msg := range messages {
			if now.Before(msg.Timestamp.Add(msg.TTL)) {
				validMessages = append(validMessages, msg)
			}
		}
		ssr.messageQueues[token] = validMessages
	}
}

// ValidateToken checks if a token is valid without revealing recipient info
func (ssr *SealedSenderRouter) ValidateToken(token string) bool {
	ssr.mutex.RLock()
	defer ssr.mutex.RUnlock()

	mapping, exists := ssr.tokenMappings[token]
	if !exists {
		return false
	}

	return time.Now().Before(mapping.ExpiresAt)
}

// SealedEnvelope represents the complete sealed message structure
type SealedEnvelope struct {
	// Routing layer (visible to server)
	RoutingToken string            `json:"routing_token"`
	Metadata     map[string]string `json:"metadata"`

	// Encrypted payload (opaque to server)
	EncryptedPayload []byte `json:"encrypted_payload"`

	// The encrypted payload contains:
	// {
	//   "recipient_id": "actual_recipient",
	//   "sender_id": "actual_sender",
	//   "message_type": "text|file|etc",
	//   "inner_encrypted_data": "double_ratchet_encrypted_content"
	// }
}

// CreateSealedEnvelope creates a properly structured sealed envelope
func CreateSealedEnvelope(routingToken string, innerPayload []byte, metadata map[string]string) *SealedEnvelope {
	return &SealedEnvelope{
		RoutingToken:     routingToken,
		Metadata:         metadata,
		EncryptedPayload: innerPayload,
	}
}

// Helper function to generate secure routing tokens
func GenerateSecureToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// TokenGenerator creates tokens with different security levels
type TokenGenerator struct {
	entropy int // bits of entropy
}

func NewTokenGenerator(entropyBits int) *TokenGenerator {
	if entropyBits < 128 {
		entropyBits = 256 // Default to 256 bits
	}
	return &TokenGenerator{entropy: entropyBits}
}

func (tg *TokenGenerator) GenerateToken() (string, error) {
	bytes := make([]byte, tg.entropy/8)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// Rate limiting for token creation
type TokenRateLimiter struct {
	requests map[string][]time.Time
	limit    int
	window   time.Duration
	mutex    sync.RWMutex
}

func NewTokenRateLimiter(requestsPerWindow int, window time.Duration) *TokenRateLimiter {
	return &TokenRateLimiter{
		requests: make(map[string][]time.Time),
		limit:    requestsPerWindow,
		window:   window,
	}
}

func (trl *TokenRateLimiter) AllowRequest(clientID string) bool {
	trl.mutex.Lock()
	defer trl.mutex.Unlock()

	now := time.Now()
	windowStart := now.Add(-trl.window)

	// Get existing requests for this client
	requests := trl.requests[clientID]

	// Filter out old requests
	validRequests := make([]time.Time, 0)
	for _, req := range requests {
		if req.After(windowStart) {
			validRequests = append(validRequests, req)
		}
	}

	// Check if limit exceeded
	if len(validRequests) >= trl.limit {
		return false
	}

	// Add current request
	validRequests = append(validRequests, now)
	trl.requests[clientID] = validRequests

	return true
}