package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"shuttle-service/internal/config"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// RedisStorage implements storage using Redis
type RedisStorage struct {
	client *redis.Client
	logger *zap.Logger
}

// Message represents a stored message
type Message struct {
	ID          string          `json:"id"`
	Recipient   string          `json:"recipient"`
	Payload     json.RawMessage `json:"payload"`
	QueuedAt    int64           `json:"queued_at"`
	TTL         int             `json:"ttl"`
	Priority    int             `json:"priority"`
	Metadata    MessageMetadata `json:"metadata"`
	ClaimToken  string          `json:"claim_token,omitempty"`
	ClaimedAt   int64           `json:"claimed_at,omitempty"`
	RetryCount  int             `json:"retry_count"`
	DeadLetter  bool            `json:"dead_letter"`
}

// MessageMetadata contains additional message information
type MessageMetadata struct {
	SenderHint    string `json:"sender_hint,omitempty"`
	ContentType   string `json:"content_type"`
	FrameSize     int    `json:"frame_size"`
	TimestampMs   int64  `json:"timestamp_ms"`
	RetryCount    int    `json:"retry_count"`
	OriginalID    string `json:"original_id,omitempty"`
}

// NewRedisStorage creates a new Redis storage instance
func NewRedisStorage(config config.RedisConfig, logger *zap.Logger) (*RedisStorage, error) {
	opts := &redis.Options{
		Addr:         config.Addr,
		Password:     config.Password,
		DB:           config.DB,
		PoolSize:     config.PoolSize,
		MinIdleConns: config.MinIdleConns,
		MaxRetries:   config.MaxRetries,
		DialTimeout:  config.DialTimeout,
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
		IdleTimeout:  config.IdleTimeout,
	}

	client := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	logger.Info("Connected to Redis", zap.String("addr", config.Addr))

	return &RedisStorage{
		client: client,
		logger: logger,
	}, nil
}

// StoreMessage stores a message in the queue
func (r *RedisStorage) StoreMessage(ctx context.Context, msg *Message) error {
	// Serialize message
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Store in Redis with TTL
	ttl := time.Duration(msg.TTL) * time.Second
	if ttl <= 0 {
		ttl = 24 * time.Hour // Default TTL
	}

	// Use Redis transaction for atomicity
	pipe := r.client.TxPipeline()

	// Store message data
	messageKey := fmt.Sprintf("msg:%s", msg.ID)
	pipe.Set(ctx, messageKey, data, ttl)

	// Add to recipient queue (sorted set by priority and timestamp)
	queueKey := fmt.Sprintf("queue:%s", msg.Recipient)
	score := float64(msg.Priority)*1000000 + float64(msg.QueuedAt) // Priority first, then timestamp
	pipe.ZAdd(ctx, queueKey, redis.Z{Score: score, Member: msg.ID})
	pipe.Expire(ctx, queueKey, ttl+time.Hour) // Queue expires 1 hour after messages

	// Add to global message index for cleanup
	pipe.ZAdd(ctx, "messages:by_expiry", redis.Z{
		Score:  float64(time.Now().Add(ttl).Unix()),
		Member: msg.ID,
	})

	// Update statistics
	pipe.Incr(ctx, "stats:total_messages")
	pipe.Incr(ctx, fmt.Sprintf("stats:recipient:%s", msg.Recipient))

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to store message: %w", err)
	}

	r.logger.Debug("Message stored",
		zap.String("id", msg.ID),
		zap.String("recipient", msg.Recipient),
		zap.Duration("ttl", ttl))

	return nil
}

// ClaimMessages claims messages for a recipient
func (r *RedisStorage) ClaimMessages(ctx context.Context, recipient string, maxMessages int, claimToken string) ([]*Message, error) {
	queueKey := fmt.Sprintf("queue:%s", recipient)

	// Get message IDs from queue (highest priority/oldest first)
	messageIDs, err := r.client.ZRevRange(ctx, queueKey, 0, int64(maxMessages-1)).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get message IDs: %w", err)
	}

	if len(messageIDs) == 0 {
		return []*Message{}, nil
	}

	// Start transaction
	pipe := r.client.TxPipeline()

	// Remove claimed messages from queue
	for _, id := range messageIDs {
		pipe.ZRem(ctx, queueKey, id)
	}

	// Get message data
	messageKeys := make([]string, len(messageIDs))
	for i, id := range messageIDs {
		messageKeys[i] = fmt.Sprintf("msg:%s", id)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		return nil, fmt.Errorf("failed to remove messages from queue: %w", err)
	}

	// Get message data
	messageData, err := r.client.MGet(ctx, messageKeys...).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get message data: %w", err)
	}

	messages := make([]*Message, 0, len(messageData))
	claimedKey := fmt.Sprintf("claimed:%s", claimToken)

	pipe = r.client.TxPipeline()

	for i, data := range messageData {
		if data == nil {
			continue // Message expired or deleted
		}

		var msg Message
		if err := json.Unmarshal([]byte(data.(string)), &msg); err != nil {
			r.logger.Error("Failed to unmarshal message", zap.Error(err))
			continue
		}

		// Update claim information
		msg.ClaimToken = claimToken
		msg.ClaimedAt = time.Now().Unix()

		// Store claimed message (with shorter TTL)
		claimTTL := 10 * time.Minute
		updatedData, _ := json.Marshal(&msg)
		pipe.Set(ctx, fmt.Sprintf("msg:%s", msg.ID), updatedData, claimTTL)

		// Add to claimed messages index
		pipe.ZAdd(ctx, claimedKey, redis.Z{
			Score:  float64(msg.ClaimedAt),
			Member: msg.ID,
		})
		pipe.Expire(ctx, claimedKey, claimTTL)

		messages = append(messages, &msg)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		r.logger.Error("Failed to update claimed messages", zap.Error(err))
	}

	r.logger.Debug("Messages claimed",
		zap.String("recipient", recipient),
		zap.Int("count", len(messages)),
		zap.String("claim_token", claimToken))

	return messages, nil
}

// AckMessage acknowledges successful processing of a message
func (r *RedisStorage) AckMessage(ctx context.Context, messageID, claimToken string, success bool) error {
	messageKey := fmt.Sprintf("msg:%s", messageID)
	claimedKey := fmt.Sprintf("claimed:%s", claimToken)

	pipe := r.client.TxPipeline()

	if success {
		// Delete message on successful processing
		pipe.Del(ctx, messageKey)
		pipe.ZRem(ctx, "messages:by_expiry", messageID)
		pipe.Incr(ctx, "stats:acked_messages")
	} else {
		// Handle failed processing
		msgData, err := r.client.Get(ctx, messageKey).Result()
		if err != nil {
			return fmt.Errorf("failed to get message for retry: %w", err)
		}

		var msg Message
		if err := json.Unmarshal([]byte(msgData), &msg); err != nil {
			return fmt.Errorf("failed to unmarshal message: %w", err)
		}

		msg.RetryCount++
		if msg.RetryCount >= 3 { // Max retries
			// Move to dead letter queue
			msg.DeadLetter = true
			deadLetterKey := fmt.Sprintf("dead_letter:%s", msg.Recipient)

			updatedData, _ := json.Marshal(&msg)
			pipe.Set(ctx, messageKey, updatedData, 24*time.Hour) // Dead letter TTL
			pipe.ZAdd(ctx, deadLetterKey, redis.Z{
				Score:  float64(time.Now().Unix()),
				Member: messageID,
			})
			pipe.Incr(ctx, "stats:dead_letters")
		} else {
			// Retry: put back in queue with delay
			queueKey := fmt.Sprintf("queue:%s", msg.Recipient)
			retryTime := time.Now().Add(time.Duration(msg.RetryCount) * time.Minute)
			score := float64(msg.Priority)*1000000 + float64(retryTime.Unix())

			updatedData, _ := json.Marshal(&msg)
			pipe.Set(ctx, messageKey, updatedData, time.Duration(msg.TTL)*time.Second)
			pipe.ZAdd(ctx, queueKey, redis.Z{Score: score, Member: messageID})
			pipe.Incr(ctx, "stats:retried_messages")
		}
	}

	// Remove from claimed set
	pipe.ZRem(ctx, claimedKey, messageID)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to ack message: %w", err)
	}

	r.logger.Debug("Message acknowledged",
		zap.String("id", messageID),
		zap.Bool("success", success))

	return nil
}

// GetStats returns storage statistics
func (r *RedisStorage) GetStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Get basic stats
	pipe := r.client.Pipeline()
	totalMessages := pipe.Get(ctx, "stats:total_messages")
	ackedMessages := pipe.Get(ctx, "stats:acked_messages")
	retriedMessages := pipe.Get(ctx, "stats:retried_messages")
	deadLetters := pipe.Get(ctx, "stats:dead_letters")

	results, err := pipe.Exec(ctx)
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}

	// Parse results (default to 0 if key doesn't exist)
	getIntValue := func(cmd *redis.StringCmd) int64 {
		val, err := cmd.Int64()
		if err != nil {
			return 0
		}
		return val
	}

	stats["total_messages"] = getIntValue(totalMessages)
	stats["acked_messages"] = getIntValue(ackedMessages)
	stats["retried_messages"] = getIntValue(retriedMessages)
	stats["dead_letters"] = getIntValue(deadLetters)

	// Get queue lengths
	queues, err := r.client.Keys(ctx, "queue:*").Result()
	if err == nil {
		queueStats := make(map[string]int64)
		for _, queue := range queues {
			length, err := r.client.ZCard(ctx, queue).Result()
			if err == nil {
				recipient := queue[6:] // Remove "queue:" prefix
				queueStats[recipient] = length
			}
		}
		stats["queue_lengths"] = queueStats
	}

	// Get memory usage
	memInfo, err := r.client.Info(ctx, "memory").Result()
	if err == nil {
		stats["redis_memory_info"] = memInfo
	}

	return stats, nil
}

// CleanupExpired removes expired messages and empty queues
func (r *RedisStorage) CleanupExpired(ctx context.Context) error {
	now := float64(time.Now().Unix())

	// Get expired message IDs
	expiredIDs, err := r.client.ZRangeByScore(ctx, "messages:by_expiry", &redis.ZRangeBy{
		Min: "-inf",
		Max: fmt.Sprintf("%f", now),
	}).Result()
	if err != nil {
		return fmt.Errorf("failed to get expired messages: %w", err)
	}

	if len(expiredIDs) == 0 {
		return nil
	}

	r.logger.Debug("Cleaning up expired messages", zap.Int("count", len(expiredIDs)))

	// Remove expired messages
	pipe := r.client.TxPipeline()
	for _, id := range expiredIDs {
		pipe.Del(ctx, fmt.Sprintf("msg:%s", id))
		pipe.ZRem(ctx, "messages:by_expiry", id)
	}

	// Clean up empty queues
	queues, err := r.client.Keys(ctx, "queue:*").Result()
	if err == nil {
		for _, queue := range queues {
			pipe.ZRemRangeByScore(ctx, queue, "-inf", fmt.Sprintf("%f", now-86400)) // Remove old entries
		}
	}

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to cleanup expired messages: %w", err)
	}

	return nil
}

// GetQueueInfo returns information about a recipient's queue
func (r *RedisStorage) GetQueueInfo(ctx context.Context, recipient string) (map[string]interface{}, error) {
	queueKey := fmt.Sprintf("queue:%s", recipient)

	info := make(map[string]interface{})

	// Get queue length
	length, err := r.client.ZCard(ctx, queueKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get queue length: %w", err)
	}
	info["length"] = length

	if length > 0 {
		// Get oldest and newest message timestamps
		oldest, err := r.client.ZRange(ctx, queueKey, 0, 0, &redis.ZRangeArgs{ByScore: true}).Result()
		if err == nil && len(oldest) > 0 {
			info["oldest_score"] = oldest[0]
		}

		newest, err := r.client.ZRange(ctx, queueKey, -1, -1, &redis.ZRangeArgs{ByScore: true}).Result()
		if err == nil && len(newest) > 0 {
			info["newest_score"] = newest[0]
		}

		// Get queue size estimate
		totalSize := int64(0)
		messageIDs, err := r.client.ZRange(ctx, queueKey, 0, 100).Result() // Sample first 100
		if err == nil {
			for _, id := range messageIDs {
				size, err := r.client.StrLen(ctx, fmt.Sprintf("msg:%s", id)).Result()
				if err == nil {
					totalSize += size
				}
			}
		}
		info["estimated_size_bytes"] = totalSize
	}

	return info, nil
}

// Close closes the Redis connection
func (r *RedisStorage) Close() error {
	return r.client.Close()
}