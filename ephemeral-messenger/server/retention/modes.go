// Retention Modes for Ephemeral Messenger
//
// Implements flexible data retention policies:
// - memory_only: Data exists only in memory, lost on restart
// - session_only: Data cleared when client disconnects
// - bounded: Data expires after time limit (configurable)
// - explicit_keep: Data persists until manually deleted
//
// PRIVACY: Default for burner accounts is memory_only

package retention

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// RetentionMode defines how long data should be kept
type RetentionMode string

const (
	// Data exists only in memory, never written to disk
	ModeMemoryOnly RetentionMode = "memory_only"

	// Data cleared when client session ends
	ModeSessionOnly RetentionMode = "session_only"

	// Data expires after configured time limit
	ModeBounded RetentionMode = "bounded"

	// Data persists until manually deleted
	ModeExplicitKeep RetentionMode = "explicit_keep"
)

// RetentionPolicy defines retention behavior for an account or conversation
type RetentionPolicy struct {
	Mode      RetentionMode `json:"mode"`
	TTL       time.Duration `json:"ttl,omitempty"`        // For bounded mode
	MaxSize   int64         `json:"max_size,omitempty"`   // Max data size in bytes
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
}

// ConversationData represents data that can be subject to retention
type ConversationData struct {
	ID           string                 `json:"id"`
	Participants []string               `json:"participants"`
	Messages     []Message              `json:"messages"`
	Metadata     map[string]interface{} `json:"metadata"`
	CreatedAt    time.Time              `json:"created_at"`
	LastActivity time.Time              `json:"last_activity"`
	DataSize     int64                  `json:"data_size"`
}

// Message represents a single message in a conversation
type Message struct {
	ID        string                 `json:"id"`
	From      string                 `json:"from"`
	To        []string               `json:"to"`
	Content   []byte                 `json:"content"`   // Encrypted content
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata"`
	Size      int64                  `json:"size"`
}

// SessionContext tracks client session information
type SessionContext struct {
	SessionID   string    `json:"session_id"`
	UserID      string    `json:"user_id"`
	ConnectedAt time.Time `json:"connected_at"`
	LastSeen    time.Time `json:"last_seen"`
	Active      bool      `json:"active"`
}

// RetentionManager manages data retention across the system
type RetentionManager struct {
	// Memory-only data (never persisted)
	memoryData map[string]*ConversationData

	// Session-based data (cleared on disconnect)
	sessionData map[string]map[string]*ConversationData // sessionID -> conversations

	// Bounded data with TTL
	boundedData map[string]*ConversationData

	// Persistent data
	persistentData map[string]*ConversationData

	// Active sessions
	sessions map[string]*SessionContext

	// Retention policies per user/conversation
	policies map[string]*RetentionPolicy

	// Configuration
	defaultPolicy   *RetentionPolicy
	cleanupInterval time.Duration

	// Synchronization
	mutex sync.RWMutex

	// Metrics
	totalDataSize   int64
	expiredMessages int64
	activeSessions  int64
}

// NewRetentionManager creates a new retention manager
func NewRetentionManager() *RetentionManager {
	defaultPolicy := &RetentionPolicy{
		Mode:      ModeBounded,
		TTL:       24 * time.Hour, // Default 24 hour retention
		MaxSize:   100 * 1024 * 1024, // 100MB default limit
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	rm := &RetentionManager{
		memoryData:      make(map[string]*ConversationData),
		sessionData:     make(map[string]map[string]*ConversationData),
		boundedData:     make(map[string]*ConversationData),
		persistentData:  make(map[string]*ConversationData),
		sessions:        make(map[string]*SessionContext),
		policies:        make(map[string]*RetentionPolicy),
		defaultPolicy:   defaultPolicy,
		cleanupInterval: 5 * time.Minute,
	}

	// Start background cleanup
	go rm.cleanupExpiredData()

	return rm
}

// SetRetentionPolicy sets retention policy for a user or conversation
func (rm *RetentionManager) SetRetentionPolicy(entityID string, policy *RetentionPolicy) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	// Validate policy
	if err := rm.validatePolicy(policy); err != nil {
		return fmt.Errorf("invalid retention policy: %v", err)
	}

	policy.UpdatedAt = time.Now()
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = time.Now()
	}

	rm.policies[entityID] = policy
	return nil
}

// GetRetentionPolicy returns retention policy for entity (user/conversation)
func (rm *RetentionManager) GetRetentionPolicy(entityID string) *RetentionPolicy {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	if policy, exists := rm.policies[entityID]; exists {
		return policy
	}
	return rm.defaultPolicy
}

// StoreConversationData stores conversation data according to retention policy
func (rm *RetentionManager) StoreConversationData(sessionID string, data *ConversationData) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	// Get retention policy for this conversation
	policy := rm.getEffectivePolicy(data)

	// Update data size
	rm.totalDataSize += data.DataSize

	// Check size limits
	if policy.MaxSize > 0 && data.DataSize > policy.MaxSize {
		return fmt.Errorf("conversation data exceeds size limit: %d > %d", data.DataSize, policy.MaxSize)
	}

	switch policy.Mode {
	case ModeMemoryOnly:
		rm.memoryData[data.ID] = data

	case ModeSessionOnly:
		if rm.sessionData[sessionID] == nil {
			rm.sessionData[sessionID] = make(map[string]*ConversationData)
		}
		rm.sessionData[sessionID][data.ID] = data

	case ModeBounded:
		rm.boundedData[data.ID] = data

	case ModeExplicitKeep:
		rm.persistentData[data.ID] = data

	default:
		return fmt.Errorf("unknown retention mode: %s", policy.Mode)
	}

	return nil
}

// GetConversationData retrieves conversation data if available and not expired
func (rm *RetentionManager) GetConversationData(sessionID, conversationID string) (*ConversationData, error) {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	// Check memory-only data
	if data, exists := rm.memoryData[conversationID]; exists {
		return data, nil
	}

	// Check session data
	if sessionConvs, exists := rm.sessionData[sessionID]; exists {
		if data, exists := sessionConvs[conversationID]; exists {
			return data, nil
		}
	}

	// Check bounded data (verify not expired)
	if data, exists := rm.boundedData[conversationID]; exists {
		policy := rm.getEffectivePolicy(data)
		if rm.isExpired(data, policy) {
			// Remove expired data
			delete(rm.boundedData, conversationID)
			rm.totalDataSize -= data.DataSize
			rm.expiredMessages++
			return nil, fmt.Errorf("conversation data expired")
		}
		return data, nil
	}

	// Check persistent data
	if data, exists := rm.persistentData[conversationID]; exists {
		return data, nil
	}

	return nil, fmt.Errorf("conversation not found")
}

// StartSession creates a new session context
func (rm *RetentionManager) StartSession(sessionID, userID string) *SessionContext {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	session := &SessionContext{
		SessionID:   sessionID,
		UserID:      userID,
		ConnectedAt: time.Now(),
		LastSeen:    time.Now(),
		Active:      true,
	}

	rm.sessions[sessionID] = session
	rm.activeSessions++

	return session
}

// EndSession terminates a session and cleans up session-only data
func (rm *RetentionManager) EndSession(sessionID string) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	session, exists := rm.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// Mark session as inactive
	session.Active = false

	// Clean up session-only data
	if sessionConvs, exists := rm.sessionData[sessionID]; exists {
		for _, data := range sessionConvs {
			rm.totalDataSize -= data.DataSize
		}
		delete(rm.sessionData, sessionID)
	}

	// Remove session
	delete(rm.sessions, sessionID)
	rm.activeSessions--

	return nil
}

// AddMessage adds a message to a conversation
func (rm *RetentionManager) AddMessage(sessionID, conversationID string, message *Message) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	// Find the conversation in appropriate storage
	var data *ConversationData
	var found bool

	// Check all storage types
	if d, exists := rm.memoryData[conversationID]; exists {
		data = d
		found = true
	} else if sessionConvs, exists := rm.sessionData[sessionID]; exists {
		if d, exists := sessionConvs[conversationID]; exists {
			data = d
			found = true
		}
	} else if d, exists := rm.boundedData[conversationID]; exists {
		data = d
		found = true
	} else if d, exists := rm.persistentData[conversationID]; exists {
		data = d
		found = true
	}

	if !found {
		return fmt.Errorf("conversation not found: %s", conversationID)
	}

	// Add message
	data.Messages = append(data.Messages, *message)
	data.LastActivity = time.Now()
	data.DataSize += message.Size
	rm.totalDataSize += message.Size

	return nil
}

// GetRetentionStats returns retention statistics
func (rm *RetentionManager) GetRetentionStats() map[string]interface{} {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	return map[string]interface{}{
		"total_conversations": len(rm.memoryData) + len(rm.boundedData) + len(rm.persistentData) + rm.countSessionConversations(),
		"memory_only_count":   len(rm.memoryData),
		"bounded_count":       len(rm.boundedData),
		"persistent_count":    len(rm.persistentData),
		"session_count":       rm.countSessionConversations(),
		"active_sessions":     rm.activeSessions,
		"total_data_size":     rm.totalDataSize,
		"expired_messages":    rm.expiredMessages,
		"cleanup_interval":    rm.cleanupInterval.String(),
	}
}

// DeleteConversation explicitly deletes a conversation
func (rm *RetentionManager) DeleteConversation(conversationID string) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	var deleted bool
	var dataSize int64

	// Remove from all storages
	if data, exists := rm.memoryData[conversationID]; exists {
		dataSize = data.DataSize
		delete(rm.memoryData, conversationID)
		deleted = true
	}

	if data, exists := rm.boundedData[conversationID]; exists {
		dataSize = data.DataSize
		delete(rm.boundedData, conversationID)
		deleted = true
	}

	if data, exists := rm.persistentData[conversationID]; exists {
		dataSize = data.DataSize
		delete(rm.persistentData, conversationID)
		deleted = true
	}

	// Remove from session data
	for sessionID, sessionConvs := range rm.sessionData {
		if data, exists := sessionConvs[conversationID]; exists {
			dataSize = data.DataSize
			delete(rm.sessionData[sessionID], conversationID)
			deleted = true

			// Clean up empty session containers
			if len(rm.sessionData[sessionID]) == 0 {
				delete(rm.sessionData, sessionID)
			}
		}
	}

	if deleted {
		rm.totalDataSize -= dataSize
		return nil
	}

	return fmt.Errorf("conversation not found: %s", conversationID)
}

// Helper methods

func (rm *RetentionManager) validatePolicy(policy *RetentionPolicy) error {
	switch policy.Mode {
	case ModeMemoryOnly, ModeSessionOnly, ModeExplicitKeep:
		// These modes don't require TTL

	case ModeBounded:
		if policy.TTL <= 0 {
			return fmt.Errorf("bounded mode requires positive TTL")
		}

	default:
		return fmt.Errorf("unknown retention mode: %s", policy.Mode)
	}

	if policy.MaxSize < 0 {
		return fmt.Errorf("negative max size not allowed")
	}

	return nil
}

func (rm *RetentionManager) getEffectivePolicy(data *ConversationData) *RetentionPolicy {
	// Check for conversation-specific policy
	if policy, exists := rm.policies[data.ID]; exists {
		return policy
	}

	// Check for user-specific policies
	for _, participant := range data.Participants {
		if policy, exists := rm.policies[participant]; exists {
			return policy
		}
	}

	// Return default policy
	return rm.defaultPolicy
}

func (rm *RetentionManager) isExpired(data *ConversationData, policy *RetentionPolicy) bool {
	if policy.Mode != ModeBounded {
		return false
	}

	expiryTime := data.LastActivity.Add(policy.TTL)
	return time.Now().After(expiryTime)
}

func (rm *RetentionManager) countSessionConversations() int {
	count := 0
	for _, sessionConvs := range rm.sessionData {
		count += len(sessionConvs)
	}
	return count
}

// Background cleanup of expired data
func (rm *RetentionManager) cleanupExpiredData() {
	ticker := time.NewTicker(rm.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		rm.performCleanup()
	}
}

func (rm *RetentionManager) performCleanup() {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	now := time.Now()
	conversationsToDelete := make([]string, 0)

	// Clean up bounded data
	for id, data := range rm.boundedData {
		policy := rm.getEffectivePolicy(data)
		if rm.isExpired(data, policy) {
			conversationsToDelete = append(conversationsToDelete, id)
		}
	}

	// Remove expired conversations
	for _, id := range conversationsToDelete {
		if data, exists := rm.boundedData[id]; exists {
			rm.totalDataSize -= data.DataSize
			rm.expiredMessages += int64(len(data.Messages))
			delete(rm.boundedData, id)
		}
	}

	// Clean up inactive sessions (older than 1 hour)
	sessionsToDelete := make([]string, 0)
	for sessionID, session := range rm.sessions {
		if !session.Active && now.Sub(session.LastSeen) > time.Hour {
			sessionsToDelete = append(sessionsToDelete, sessionID)
		}
	}

	for _, sessionID := range sessionsToDelete {
		// Clean up session data
		if sessionConvs, exists := rm.sessionData[sessionID]; exists {
			for _, data := range sessionConvs {
				rm.totalDataSize -= data.DataSize
			}
			delete(rm.sessionData, sessionID)
		}
		delete(rm.sessions, sessionID)
	}
}

// CreateBurnerPolicy creates a secure policy for burner accounts
func CreateBurnerPolicy() *RetentionPolicy {
	return &RetentionPolicy{
		Mode:      ModeMemoryOnly,  // Never persist to disk
		TTL:       0,               // No TTL needed for memory-only
		MaxSize:   10 * 1024 * 1024, // 10MB limit for burner accounts
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// Export data for backup/migration (respects retention policies)
func (rm *RetentionManager) ExportConversations(sessionID string, includeMemoryOnly bool) ([]byte, error) {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	exportData := make(map[string]*ConversationData)

	// Export persistent data
	for id, data := range rm.persistentData {
		exportData[id] = data
	}

	// Export bounded data (not expired)
	for id, data := range rm.boundedData {
		policy := rm.getEffectivePolicy(data)
		if !rm.isExpired(data, policy) {
			exportData[id] = data
		}
	}

	// Optionally include memory-only data
	if includeMemoryOnly {
		for id, data := range rm.memoryData {
			exportData[id] = data
		}
	}

	return json.Marshal(exportData)
}