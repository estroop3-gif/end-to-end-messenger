package queue

import (
	"context"
	"testing"
	"time"

	"shuttle-service/internal/config"
	"shuttle-service/internal/storage"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

// MockStorage implements storage interface for testing
type MockStorage struct {
	mock.Mock
}

func (m *MockStorage) StoreMessage(ctx context.Context, msg *storage.Message) error {
	args := m.Called(ctx, msg)
	return args.Error(0)
}

func (m *MockStorage) ClaimMessages(ctx context.Context, recipient string, maxMessages int, claimToken string) ([]*storage.Message, error) {
	args := m.Called(ctx, recipient, maxMessages, claimToken)
	return args.Get(0).([]*storage.Message), args.Error(1)
}

func (m *MockStorage) AckMessage(ctx context.Context, messageID, claimToken string, success bool) error {
	args := m.Called(ctx, messageID, claimToken, success)
	return args.Error(0)
}

func (m *MockStorage) GetStats(ctx context.Context) (map[string]interface{}, error) {
	args := m.Called(ctx)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockStorage) GetQueueInfo(ctx context.Context, recipient string) (map[string]interface{}, error) {
	args := m.Called(ctx, recipient)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockStorage) CleanupExpired(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockStorage) Close() error {
	args := m.Called()
	return args.Error(0)
}

func createTestQueue() (*MessageQueue, *MockStorage) {
	mockStorage := &MockStorage{}

	cfg := config.QueueConfig{
		DefaultTTL:      24 * time.Hour,
		MaxTTL:          7 * 24 * time.Hour,
		MaxMessageSize:  2 * 1024 * 1024,
		MaxQueueSize:    10000,
		CleanupInterval: 5 * time.Minute,
		MaxRetries:      3,
		RetryDelay:      1 * time.Minute,
		DeadLetterTTL:   24 * time.Hour,
	}

	logger := zap.NewNop()

	mq := &MessageQueue{
		storage:     mockStorage,
		config:      cfg,
		logger:      logger,
		cleanupStop: make(chan struct{}),
		cleanupDone: make(chan struct{}),
	}

	return mq, mockStorage
}

func TestOfferValidMessage(t *testing.T) {
	mq, mockStorage := createTestQueue()
	ctx := context.Background()

	// Mock queue info to show queue is not full
	mockStorage.On("GetQueueInfo", ctx, "test-recipient").Return(
		map[string]interface{}{"length": int64(0)}, nil)

	// Mock successful message storage
	mockStorage.On("StoreMessage", ctx, mock.AnythingOfType("*storage.Message")).Return(nil)

	req := &OfferRequest{
		MessageID: uuid.New().String(),
		Recipient: "test-recipient",
		Payload:   []byte("test message"),
		TTL:       3600,
		Priority:  5,
		Metadata: OfferMetadata{
			ContentType: "application/octet-stream",
			FrameSize:   12,
			TimestampMs: time.Now().UnixMilli(),
		},
	}

	resp, err := mq.Offer(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Accepted)
	assert.Equal(t, req.MessageID, resp.MessageID)
	assert.Greater(t, resp.QueuedUntil, time.Now().Unix())

	mockStorage.AssertExpectations(t)
}

func TestOfferInvalidMessage(t *testing.T) {
	mq, _ := createTestQueue()
	ctx := context.Background()

	// Test missing message ID
	req := &OfferRequest{
		MessageID: "",
		Recipient: "test-recipient",
		Payload:   []byte("test message"),
	}

	resp, err := mq.Offer(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.False(t, resp.Accepted)
	assert.Equal(t, "INVALID_REQUEST", resp.ErrorCode)
}

func TestOfferQueueFull(t *testing.T) {
	mq, mockStorage := createTestQueue()
	ctx := context.Background()

	// Mock queue info to show queue is full
	mockStorage.On("GetQueueInfo", ctx, "test-recipient").Return(
		map[string]interface{}{"length": int64(10000)}, nil)

	req := &OfferRequest{
		MessageID: uuid.New().String(),
		Recipient: "test-recipient",
		Payload:   []byte("test message"),
		TTL:       3600,
		Priority:  5,
	}

	resp, err := mq.Offer(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.False(t, resp.Accepted)
	assert.Equal(t, "QUEUE_FULL", resp.ErrorCode)

	mockStorage.AssertExpectations(t)
}

func TestClaimMessages(t *testing.T) {
	mq, mockStorage := createTestQueue()
	ctx := context.Background()

	// Create test messages
	testMessages := []*storage.Message{
		{
			ID:        uuid.New().String(),
			Recipient: "test-recipient",
			Payload:   []byte("message 1"),
			QueuedAt:  time.Now().Unix(),
			TTL:       3600,
			Priority:  5,
			Metadata: storage.MessageMetadata{
				ContentType: "application/octet-stream",
				FrameSize:   9,
				TimestampMs: time.Now().UnixMilli(),
			},
		},
		{
			ID:        uuid.New().String(),
			Recipient: "test-recipient",
			Payload:   []byte("message 2"),
			QueuedAt:  time.Now().Unix(),
			TTL:       3600,
			Priority:  3,
			Metadata: storage.MessageMetadata{
				ContentType: "application/octet-stream",
				FrameSize:   9,
				TimestampMs: time.Now().UnixMilli(),
			},
		},
	}

	// Mock claim operation
	mockStorage.On("ClaimMessages", ctx, "test-recipient", 10, mock.AnythingOfType("string")).Return(testMessages, nil)

	// Mock queue info for "more" flag
	mockStorage.On("GetQueueInfo", ctx, "test-recipient").Return(
		map[string]interface{}{"length": int64(0)}, nil)

	req := &ClaimRequest{
		ClientID:       "test-recipient",
		MaxMessages:    10,
		TimeoutSeconds: 30,
	}

	resp, err := mq.Claim(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Len(t, resp.Messages, 2)
	assert.False(t, resp.More)

	// Verify message details
	for i, msg := range resp.Messages {
		assert.Equal(t, testMessages[i].ID, msg.MessageID)
		assert.Equal(t, testMessages[i].Payload, msg.Payload)
		assert.NotEmpty(t, msg.ClaimToken)
		assert.GreaterOrEqual(t, msg.TTL, 0)
	}

	mockStorage.AssertExpectations(t)
}

func TestClaimNoMessages(t *testing.T) {
	mq, mockStorage := createTestQueue()
	ctx := context.Background()

	// Mock empty claim operation
	mockStorage.On("ClaimMessages", ctx, "test-recipient", 10, mock.AnythingOfType("string")).Return([]*storage.Message{}, nil)

	// Mock queue info
	mockStorage.On("GetQueueInfo", ctx, "test-recipient").Return(
		map[string]interface{}{"length": int64(0)}, nil)

	req := &ClaimRequest{
		ClientID:       "test-recipient",
		MaxMessages:    10,
		TimeoutSeconds: 30,
	}

	resp, err := mq.Claim(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Empty(t, resp.Messages)
	assert.False(t, resp.More)

	mockStorage.AssertExpectations(t)
}

func TestAckSuccess(t *testing.T) {
	mq, mockStorage := createTestQueue()
	ctx := context.Background()

	// Mock successful ack
	mockStorage.On("AckMessage", ctx, "test-message-id", "test-claim-token", true).Return(nil)

	req := &AckRequest{
		MessageID:  "test-message-id",
		ClaimToken: "test-claim-token",
		Success:    true,
	}

	err := mq.Ack(ctx, req)

	assert.NoError(t, err)
	mockStorage.AssertExpectations(t)
}

func TestAckValidation(t *testing.T) {
	mq, _ := createTestQueue()
	ctx := context.Background()

	// Test missing message ID
	req := &AckRequest{
		MessageID:  "",
		ClaimToken: "test-claim-token",
		Success:    true,
	}

	err := mq.Ack(ctx, req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "message ID is required")

	// Test missing claim token
	req = &AckRequest{
		MessageID:  "test-message-id",
		ClaimToken: "",
		Success:    true,
	}

	err = mq.Ack(ctx, req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "claim token is required")
}

func TestValidateOfferRequest(t *testing.T) {
	mq, _ := createTestQueue()

	// Valid request
	req := &OfferRequest{
		MessageID: "test-id",
		Recipient: "test-recipient",
		Payload:   []byte("test message"),
		TTL:       3600,
		Priority:  5,
	}
	assert.NoError(t, mq.validateOfferRequest(req))

	// Missing message ID
	req.MessageID = ""
	assert.Error(t, mq.validateOfferRequest(req))

	// Missing recipient
	req.MessageID = "test-id"
	req.Recipient = ""
	assert.Error(t, mq.validateOfferRequest(req))

	// Empty payload
	req.Recipient = "test-recipient"
	req.Payload = []byte{}
	assert.Error(t, mq.validateOfferRequest(req))

	// Payload too large
	req.Payload = make([]byte, 3*1024*1024) // 3MB > 2MB limit
	assert.Error(t, mq.validateOfferRequest(req))

	// Invalid priority
	req.Payload = []byte("test message")
	req.Priority = 15 // > 10
	assert.Error(t, mq.validateOfferRequest(req))
}

func TestValidateClaimRequest(t *testing.T) {
	mq, _ := createTestQueue()

	// Valid request
	req := &ClaimRequest{
		ClientID:       "test-client",
		MaxMessages:    10,
		TimeoutSeconds: 30,
	}
	assert.NoError(t, mq.validateClaimRequest(req))

	// Missing client ID
	req.ClientID = ""
	assert.Error(t, mq.validateClaimRequest(req))

	// Too many messages
	req.ClientID = "test-client"
	req.MaxMessages = 200 // > 100 limit
	assert.Error(t, mq.validateClaimRequest(req))

	// Invalid timeout
	req.MaxMessages = 10
	req.TimeoutSeconds = 500 // > 300 limit
	assert.Error(t, mq.validateClaimRequest(req))
}