package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"shuttle-service/internal/config"
	"shuttle-service/internal/queue"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

// MockMessageQueue implements queue interface for testing
type MockMessageQueue struct {
	mock.Mock
}

func (m *MockMessageQueue) Offer(ctx context.Context, req *queue.OfferRequest) (*queue.OfferResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*queue.OfferResponse), args.Error(1)
}

func (m *MockMessageQueue) Claim(ctx context.Context, req *queue.ClaimRequest) (*queue.ClaimResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*queue.ClaimResponse), args.Error(1)
}

func (m *MockMessageQueue) Ack(ctx context.Context, req *queue.AckRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockMessageQueue) GetStats(ctx context.Context) (map[string]interface{}, error) {
	args := m.Called(ctx)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockMessageQueue) GetQueueInfo(ctx context.Context, recipient string) (map[string]interface{}, error) {
	args := m.Called(ctx, recipient)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockMessageQueue) StartCleanup() {
	m.Called()
}

func (m *MockMessageQueue) StopCleanup() {
	m.Called()
}

func createTestServer() (*Server, *MockMessageQueue) {
	mockQueue := &MockMessageQueue{}

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:         8081,
			Host:         "0.0.0.0",
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
			CORSOrigins:  []string{"*"},
		},
		Auth: config.AuthConfig{
			Enabled: false,
		},
		Limits: config.LimitsConfig{
			RateLimit: config.RateLimitConfig{
				Enabled: false,
			},
		},
	}

	logger := zap.NewNop()

	server := &Server{
		config:       cfg,
		queue:        mockQueue,
		logger:       logger,
		rateLimiters: make(map[string]*rate.Limiter),
		startTime:    time.Now(),
	}

	return server, mockQueue
}

func TestHandleOffer(t *testing.T) {
	server, mockQueue := createTestServer()

	// Mock successful offer
	expectedResp := &queue.OfferResponse{
		MessageID:   "test-message-id",
		Accepted:    true,
		QueuedUntil: time.Now().Add(time.Hour).Unix(),
	}

	mockQueue.On("Offer", mock.Anything, mock.AnythingOfType("*queue.OfferRequest")).Return(expectedResp, nil)

	// Create test request
	offerReq := queue.OfferRequest{
		MessageID: "test-message-id",
		Recipient: "test-recipient",
		Payload:   []byte("test message"),
		TTL:       3600,
		Priority:  5,
		Metadata: queue.OfferMetadata{
			ContentType: "application/octet-stream",
			FrameSize:   12,
			TimestampMs: time.Now().UnixMilli(),
		},
	}

	reqBody, _ := json.Marshal(offerReq)
	req := httptest.NewRequest("POST", "/api/v1/offer", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	server.handleOffer(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp queue.OfferResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, expectedResp.MessageID, resp.MessageID)
	assert.Equal(t, expectedResp.Accepted, resp.Accepted)

	mockQueue.AssertExpectations(t)
}

func TestHandleOfferInvalidJSON(t *testing.T) {
	server, _ := createTestServer()

	req := httptest.NewRequest("POST", "/api/v1/offer", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	server.handleOffer(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Contains(t, resp, "error")
}

func TestHandleClaim(t *testing.T) {
	server, mockQueue := createTestServer()

	// Mock successful claim
	expectedResp := &queue.ClaimResponse{
		Messages: []queue.ClaimedMessage{
			{
				MessageID:   "msg-1",
				Payload:     []byte("message 1"),
				QueuedAt:    time.Now().Unix(),
				ClaimToken:  uuid.New().String(),
				TTL:         3600,
				Metadata:    storage.MessageMetadata{},
			},
		},
		More:      false,
		NextToken: "",
	}

	mockQueue.On("Claim", mock.Anything, mock.AnythingOfType("*queue.ClaimRequest")).Return(expectedResp, nil)

	// Create test request
	claimReq := queue.ClaimRequest{
		ClientID:       "test-client",
		MaxMessages:    10,
		TimeoutSeconds: 30,
	}

	reqBody, _ := json.Marshal(claimReq)
	req := httptest.NewRequest("POST", "/api/v1/claim", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	server.handleClaim(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp queue.ClaimResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Len(t, resp.Messages, 1)
	assert.Equal(t, expectedResp.Messages[0].MessageID, resp.Messages[0].MessageID)

	mockQueue.AssertExpectations(t)
}

func TestHandleAck(t *testing.T) {
	server, mockQueue := createTestServer()

	// Mock successful ack
	mockQueue.On("Ack", mock.Anything, mock.AnythingOfType("*queue.AckRequest")).Return(nil)

	// Create test request
	ackReq := queue.AckRequest{
		MessageID:  "test-message-id",
		ClaimToken: "test-claim-token",
		Success:    true,
	}

	reqBody, _ := json.Marshal(ackReq)
	req := httptest.NewRequest("POST", "/api/v1/ack", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	server.handleAck(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp map[string]string
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "ok", resp["status"])

	mockQueue.AssertExpectations(t)
}

func TestHandleHealth(t *testing.T) {
	server, mockQueue := createTestServer()

	// Mock queue stats
	mockQueue.On("GetStats", mock.Anything).Return(map[string]interface{}{
		"total_messages": int64(100),
	}, nil)

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	rr := httptest.NewRecorder()

	server.handleHealth(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.NoError(t, err)

	assert.Equal(t, "healthy", resp["status"])
	assert.Equal(t, "1.0.0", resp["version"])
	assert.Contains(t, resp, "uptime")
	assert.Contains(t, resp, "memory_mb")
	assert.Contains(t, resp, "goroutines")
	assert.Equal(t, "healthy", resp["queue_status"])

	mockQueue.AssertExpectations(t)
}

func TestHandleHealthQueueError(t *testing.T) {
	server, mockQueue := createTestServer()

	// Mock queue stats error
	mockQueue.On("GetStats", mock.Anything).Return(map[string]interface{}{}, assert.AnError)

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	rr := httptest.NewRecorder()

	server.handleHealth(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.NoError(t, err)

	assert.Equal(t, "healthy", resp["status"])
	assert.Equal(t, "error", resp["queue_status"])

	mockQueue.AssertExpectations(t)
}

func TestHandleStats(t *testing.T) {
	server, mockQueue := createTestServer()

	// Mock queue stats
	expectedStats := map[string]interface{}{
		"total_messages": int64(100),
		"acked_messages": int64(90),
	}

	mockQueue.On("GetStats", mock.Anything).Return(expectedStats, nil)

	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	rr := httptest.NewRecorder()

	server.handleStats(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.NoError(t, err)

	assert.Contains(t, resp, "server")
	assert.Contains(t, resp, "system")
	assert.Contains(t, resp, "queue")

	// Check server stats
	serverStats := resp["server"].(map[string]interface{})
	assert.Contains(t, serverStats, "uptime_seconds")

	// Check system stats
	systemStats := resp["system"].(map[string]interface{})
	assert.Contains(t, systemStats, "memory_alloc_mb")
	assert.Contains(t, systemStats, "goroutines")

	mockQueue.AssertExpectations(t)
}

func TestHandleQueueInfo(t *testing.T) {
	server, mockQueue := createTestServer()

	// Mock queue info
	expectedInfo := map[string]interface{}{
		"length":               int64(5),
		"estimated_size_bytes": int64(1024),
	}

	mockQueue.On("GetQueueInfo", mock.Anything, "test-recipient").Return(expectedInfo, nil)

	req := httptest.NewRequest("GET", "/api/v1/queue/test-recipient", nil)
	req = mux.SetURLVars(req, map[string]string{"recipient": "test-recipient"})

	rr := httptest.NewRecorder()
	server.handleQueueInfo(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, expectedInfo, resp)

	mockQueue.AssertExpectations(t)
}

func TestHandleQueueInfoMissingRecipient(t *testing.T) {
	server, _ := createTestServer()

	req := httptest.NewRequest("GET", "/api/v1/queue/", nil)
	req = mux.SetURLVars(req, map[string]string{"recipient": ""})

	rr := httptest.NewRecorder()
	server.handleQueueInfo(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Contains(t, resp, "error")
}

func TestCORSMiddleware(t *testing.T) {
	server, _ := createTestServer()

	// Test preflight request
	req := httptest.NewRequest("OPTIONS", "/api/v1/health", nil)
	req.Header.Set("Origin", "https://example.com")

	rr := httptest.NewRecorder()
	handler := server.corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "*", rr.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, rr.Header().Get("Access-Control-Allow-Methods"), "POST")
	assert.Contains(t, rr.Header().Get("Access-Control-Allow-Headers"), "Content-Type")
}

func TestUpdateStats(t *testing.T) {
	server, _ := createTestServer()

	initialTotal := server.stats.RequestsTotal

	server.updateStats(func(stats *ServerStats) {
		stats.RequestsTotal++
	})

	assert.Equal(t, initialTotal+1, server.stats.RequestsTotal)
}

func TestGetClientIP(t *testing.T) {
	server, _ := createTestServer()

	// Test X-Forwarded-For header
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	ip := server.getClientIP(req)
	assert.Equal(t, "192.168.1.100", ip)

	// Test X-Real-IP header
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Real-IP", "10.0.0.1")
	ip = server.getClientIP(req)
	assert.Equal(t, "10.0.0.1", ip)

	// Test RemoteAddr fallback
	req = httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	ip = server.getClientIP(req)
	assert.Equal(t, "127.0.0.1:12345", ip)
}