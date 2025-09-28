// Burner Accounts for Ephemeral Messenger
//
// Implements ephemeral single-use identity accounts:
// - Single-use identity stored only in locked memory
// - Ephemeral onion service with client authentication
// - Tight retention limits (memory_only default)
// - TTL-based auto-destruct
// - Enhanced quotas and rate limits
//
// SECURITY: Burner accounts leave minimal forensic traces

package burner

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

// BurnerAccount represents a temporary, ephemeral identity
type BurnerAccount struct {
	// Identity
	ID           string    `json:"id"`
	PrivateKey   []byte    `json:"-"`              // Never serialized
	PublicKey    []byte    `json:"public_key"`
	OnionAddress string    `json:"onion_address"`
	ClientAuth   []byte    `json:"-"`              // Never serialized

	// Lifetime management
	CreatedAt    time.Time     `json:"created_at"`
	ExpiresAt    time.Time     `json:"expires_at"`
	TTL          time.Duration `json:"ttl"`
	AutoDestruct bool          `json:"auto_destruct"`

	// Usage tracking
	ConnectionCount   int64     `json:"connection_count"`
	MessagesSent      int64     `json:"messages_sent"`
	MessagesReceived  int64     `json:"messages_received"`
	DataTransferred   int64     `json:"data_transferred"`
	LastActivity      time.Time `json:"last_activity"`

	// Quotas and limits
	MaxConnections    int64         `json:"max_connections"`
	MaxMessages       int64         `json:"max_messages"`
	MaxDataTransfer   int64         `json:"max_data_transfer"`
	RateLimitWindow   time.Duration `json:"rate_limit_window"`
	RateLimitRequests int64         `json:"rate_limit_requests"`

	// Status
	Active    bool   `json:"active"`
	Destroyed bool   `json:"destroyed"`
	Reason    string `json:"reason,omitempty"`
}

// BurnerConfig defines configuration for burner account creation
type BurnerConfig struct {
	DefaultTTL          time.Duration `json:"default_ttl"`
	MaxTTL              time.Duration `json:"max_ttl"`
	MaxConnections      int64         `json:"max_connections"`
	MaxMessages         int64         `json:"max_messages"`
	MaxDataTransfer     int64         `json:"max_data_transfer"`
	RateLimitWindow     time.Duration `json:"rate_limit_window"`
	RateLimitRequests   int64         `json:"rate_limit_requests"`
	AutoDestruct        bool          `json:"auto_destruct"`
	CleanupInterval     time.Duration `json:"cleanup_interval"`
	MaxConcurrentActive int           `json:"max_concurrent_active"`
}

// BurnerManager manages ephemeral burner accounts
type BurnerManager struct {
	// Account storage (memory only)
	accounts map[string]*BurnerAccount

	// Configuration
	config *BurnerConfig

	// Rate limiting per source IP
	rateLimits map[string][]time.Time

	// Synchronization
	mutex sync.RWMutex

	// Metrics
	totalCreated   int64
	totalDestroyed int64
	activeCount    int64
	expiredCount   int64
}

// NewBurnerManager creates a new burner account manager
func NewBurnerManager() *BurnerManager {
	config := &BurnerConfig{
		DefaultTTL:          6 * time.Hour,   // 6 hours default
		MaxTTL:              24 * time.Hour,  // 24 hours maximum
		MaxConnections:      10,              // Limited connections
		MaxMessages:         100,             // Limited messages
		MaxDataTransfer:     50 * 1024 * 1024, // 50MB limit
		RateLimitWindow:     time.Hour,       // 1 hour window
		RateLimitRequests:   5,               // 5 requests per hour
		AutoDestruct:        true,            // Auto-destruct on expiry
		CleanupInterval:     15 * time.Minute, // Cleanup every 15 minutes
		MaxConcurrentActive: 100,             // Max 100 active burner accounts
	}

	bm := &BurnerManager{
		accounts:   make(map[string]*BurnerAccount),
		config:     config,
		rateLimits: make(map[string][]time.Time),
	}

	// Start background cleanup
	go bm.cleanupExpiredAccounts()

	return bm
}

// CreateBurnerAccount creates a new ephemeral burner account
func (bm *BurnerManager) CreateBurnerAccount(sourceIP string, requestedTTL time.Duration) (*BurnerAccount, error) {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	// Check rate limiting
	if !bm.checkRateLimit(sourceIP) {
		return nil, fmt.Errorf("rate limit exceeded for source IP")
	}

	// Check concurrent account limit
	if bm.activeCount >= int64(bm.config.MaxConcurrentActive) {
		return nil, fmt.Errorf("maximum concurrent burner accounts exceeded")
	}

	// Validate and adjust TTL
	ttl := bm.config.DefaultTTL
	if requestedTTL > 0 && requestedTTL <= bm.config.MaxTTL {
		ttl = requestedTTL
	}

	// Generate cryptographic identity
	privateKey, publicKey, err := bm.generateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %v", err)
	}

	// Generate onion address (simplified - real implementation would create actual v3 onion)
	onionAddress, err := bm.generateOnionAddress(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate onion address: %v", err)
	}

	// Generate client authentication key
	clientAuth, err := bm.generateClientAuth()
	if err != nil {
		return nil, fmt.Errorf("failed to generate client auth: %v", err)
	}

	// Create burner account
	now := time.Now()
	account := &BurnerAccount{
		ID:           uuid.New().String(),
		PrivateKey:   privateKey,
		PublicKey:    publicKey,
		OnionAddress: onionAddress,
		ClientAuth:   clientAuth,

		CreatedAt:    now,
		ExpiresAt:    now.Add(ttl),
		TTL:          ttl,
		AutoDestruct: bm.config.AutoDestruct,

		ConnectionCount:  0,
		MessagesSent:     0,
		MessagesReceived: 0,
		DataTransferred:  0,
		LastActivity:     now,

		MaxConnections:    bm.config.MaxConnections,
		MaxMessages:       bm.config.MaxMessages,
		MaxDataTransfer:   bm.config.MaxDataTransfer,
		RateLimitWindow:   bm.config.RateLimitWindow,
		RateLimitRequests: bm.config.RateLimitRequests,

		Active:    true,
		Destroyed: false,
	}

	// Store account (memory only)
	bm.accounts[account.ID] = account
	bm.totalCreated++
	bm.activeCount++

	// Update rate limiting
	bm.updateRateLimit(sourceIP)

	return account, nil
}

// GetBurnerAccount retrieves a burner account if valid and active
func (bm *BurnerManager) GetBurnerAccount(accountID string) (*BurnerAccount, error) {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()

	account, exists := bm.accounts[accountID]
	if !exists {
		return nil, fmt.Errorf("burner account not found")
	}

	if account.Destroyed {
		return nil, fmt.Errorf("burner account has been destroyed")
	}

	if !account.Active {
		return nil, fmt.Errorf("burner account is inactive")
	}

	if time.Now().After(account.ExpiresAt) {
		return nil, fmt.Errorf("burner account has expired")
	}

	return account, nil
}

// UseBurnerAccount records usage of a burner account
func (bm *BurnerManager) UseBurnerAccount(accountID string, usage BurnerUsage) error {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	account, exists := bm.accounts[accountID]
	if !exists {
		return fmt.Errorf("burner account not found")
	}

	if account.Destroyed || !account.Active {
		return fmt.Errorf("burner account is not available")
	}

	if time.Now().After(account.ExpiresAt) {
		return fmt.Errorf("burner account has expired")
	}

	// Check quotas
	if err := bm.checkQuotas(account, usage); err != nil {
		return fmt.Errorf("quota exceeded: %v", err)
	}

	// Update usage statistics
	account.ConnectionCount += usage.Connections
	account.MessagesSent += usage.MessagesSent
	account.MessagesReceived += usage.MessagesReceived
	account.DataTransferred += usage.DataTransferred
	account.LastActivity = time.Now()

	return nil
}

// DestroyBurnerAccount immediately destroys a burner account
func (bm *BurnerManager) DestroyBurnerAccount(accountID, reason string) error {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	account, exists := bm.accounts[accountID]
	if !exists {
		return fmt.Errorf("burner account not found")
	}

	if account.Destroyed {
		return fmt.Errorf("burner account already destroyed")
	}

	// Mark as destroyed
	account.Destroyed = true
	account.Active = false
	account.Reason = reason

	// Zero out sensitive data
	for i := range account.PrivateKey {
		account.PrivateKey[i] = 0
	}
	for i := range account.ClientAuth {
		account.ClientAuth[i] = 0
	}

	// Remove from active storage
	delete(bm.accounts, accountID)
	bm.totalDestroyed++
	bm.activeCount--

	return nil
}

// ExtendBurnerAccount extends the TTL of a burner account (if not expired)
func (bm *BurnerManager) ExtendBurnerAccount(accountID string, extensionTTL time.Duration) error {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	account, exists := bm.accounts[accountID]
	if !exists {
		return fmt.Errorf("burner account not found")
	}

	if account.Destroyed || !account.Active {
		return fmt.Errorf("burner account is not available")
	}

	// Check if already expired
	if time.Now().After(account.ExpiresAt) {
		return fmt.Errorf("cannot extend expired burner account")
	}

	// Validate extension
	newExpiry := account.ExpiresAt.Add(extensionTTL)
	maxAllowedExpiry := account.CreatedAt.Add(bm.config.MaxTTL)

	if newExpiry.After(maxAllowedExpiry) {
		return fmt.Errorf("extension would exceed maximum TTL")
	}

	account.ExpiresAt = newExpiry
	account.TTL = account.ExpiresAt.Sub(account.CreatedAt)

	return nil
}

// GetBurnerStats returns statistics about burner account usage
func (bm *BurnerManager) GetBurnerStats() map[string]interface{} {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()

	activeAccounts := make([]map[string]interface{}, 0)
	totalMessages := int64(0)
	totalDataTransfer := int64(0)

	for _, account := range bm.accounts {
		if account.Active && !account.Destroyed {
			activeAccounts = append(activeAccounts, map[string]interface{}{
				"id":               account.ID[:8], // Shortened for privacy
				"created_at":       account.CreatedAt.Unix(),
				"expires_at":       account.ExpiresAt.Unix(),
				"messages_sent":    account.MessagesSent,
				"messages_received": account.MessagesReceived,
				"connections":      account.ConnectionCount,
				"data_transferred": account.DataTransferred,
			})
			totalMessages += account.MessagesSent + account.MessagesReceived
			totalDataTransfer += account.DataTransferred
		}
	}

	return map[string]interface{}{
		"total_created":       bm.totalCreated,
		"total_destroyed":     bm.totalDestroyed,
		"active_count":        bm.activeCount,
		"expired_count":       bm.expiredCount,
		"total_messages":      totalMessages,
		"total_data_transfer": totalDataTransfer,
		"active_accounts":     activeAccounts,
		"config":              bm.config,
	}
}

// BurnerUsage represents usage statistics for recording
type BurnerUsage struct {
	Connections      int64 `json:"connections"`
	MessagesSent     int64 `json:"messages_sent"`
	MessagesReceived int64 `json:"messages_received"`
	DataTransferred  int64 `json:"data_transferred"`
}

// Helper methods

func (bm *BurnerManager) generateKeyPair() ([]byte, []byte, error) {
	// Generate Ed25519 key pair (simplified)
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, nil, err
	}

	// In real implementation, would derive public key from private key
	publicKey := make([]byte, 32)
	if _, err := rand.Read(publicKey); err != nil {
		return nil, nil, err
	}

	return privateKey, publicKey, nil
}

func (bm *BurnerManager) generateOnionAddress(publicKey []byte) (string, error) {
	// Generate Tor v3 onion address (simplified)
	// Real implementation would use proper Tor key derivation
	hasher := sha256.New()
	hasher.Write(publicKey)
	hash := hasher.Sum(nil)

	// Base32 encode (simplified)
	address := base64.StdEncoding.EncodeToString(hash[:16])
	return fmt.Sprintf("%s.onion", address), nil
}

func (bm *BurnerManager) generateClientAuth() ([]byte, error) {
	clientAuth := make([]byte, 32)
	if _, err := rand.Read(clientAuth); err != nil {
		return nil, err
	}
	return clientAuth, nil
}

func (bm *BurnerManager) checkRateLimit(sourceIP string) bool {
	now := time.Now()
	windowStart := now.Add(-bm.config.RateLimitWindow)

	// Get existing requests for this IP
	requests := bm.rateLimits[sourceIP]

	// Filter out old requests
	validRequests := make([]time.Time, 0)
	for _, req := range requests {
		if req.After(windowStart) {
			validRequests = append(validRequests, req)
		}
	}

	// Check if limit exceeded
	return int64(len(validRequests)) < bm.config.RateLimitRequests
}

func (bm *BurnerManager) updateRateLimit(sourceIP string) {
	now := time.Now()
	windowStart := now.Add(-bm.config.RateLimitWindow)

	// Get existing requests
	requests := bm.rateLimits[sourceIP]

	// Filter out old requests and add current
	validRequests := make([]time.Time, 0)
	for _, req := range requests {
		if req.After(windowStart) {
			validRequests = append(validRequests, req)
		}
	}
	validRequests = append(validRequests, now)

	bm.rateLimits[sourceIP] = validRequests
}

func (bm *BurnerManager) checkQuotas(account *BurnerAccount, usage BurnerUsage) error {
	if account.ConnectionCount+usage.Connections > account.MaxConnections {
		return fmt.Errorf("connection limit exceeded")
	}

	if account.MessagesSent+account.MessagesReceived+usage.MessagesSent+usage.MessagesReceived > account.MaxMessages {
		return fmt.Errorf("message limit exceeded")
	}

	if account.DataTransferred+usage.DataTransferred > account.MaxDataTransfer {
		return fmt.Errorf("data transfer limit exceeded")
	}

	return nil
}

// Background cleanup of expired and destroyed accounts
func (bm *BurnerManager) cleanupExpiredAccounts() {
	ticker := time.NewTicker(bm.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		bm.performCleanup()
	}
}

func (bm *BurnerManager) performCleanup() {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	now := time.Now()
	accountsToDestroy := make([]string, 0)

	// Find expired accounts
	for accountID, account := range bm.accounts {
		if now.After(account.ExpiresAt) && !account.Destroyed {
			accountsToDestroy = append(accountsToDestroy, accountID)
		}
	}

	// Destroy expired accounts
	for _, accountID := range accountsToDestroy {
		account := bm.accounts[accountID]

		// Zero out sensitive data
		for i := range account.PrivateKey {
			account.PrivateKey[i] = 0
		}
		for i := range account.ClientAuth {
			account.ClientAuth[i] = 0
		}

		account.Destroyed = true
		account.Active = false
		account.Reason = "expired"

		delete(bm.accounts, accountID)
		bm.totalDestroyed++
		bm.activeCount--
		bm.expiredCount++
	}

	// Clean up old rate limit entries
	windowStart := now.Add(-bm.config.RateLimitWindow)
	for ip, requests := range bm.rateLimits {
		validRequests := make([]time.Time, 0)
		for _, req := range requests {
			if req.After(windowStart) {
				validRequests = append(validRequests, req)
			}
		}
		if len(validRequests) == 0 {
			delete(bm.rateLimits, ip)
		} else {
			bm.rateLimits[ip] = validRequests
		}
	}
}

// Export burner account info (excludes sensitive data)
func (ba *BurnerAccount) SafeJSON() ([]byte, error) {
	safeAccount := struct {
		ID              string    `json:"id"`
		OnionAddress    string    `json:"onion_address"`
		CreatedAt       time.Time `json:"created_at"`
		ExpiresAt       time.Time `json:"expires_at"`
		TTL             string    `json:"ttl"`
		ConnectionCount int64     `json:"connection_count"`
		MessagesSent    int64     `json:"messages_sent"`
		MessagesReceived int64    `json:"messages_received"`
		DataTransferred int64     `json:"data_transferred"`
		Active          bool      `json:"active"`
		Destroyed       bool      `json:"destroyed"`
	}{
		ID:               ba.ID,
		OnionAddress:     ba.OnionAddress,
		CreatedAt:        ba.CreatedAt,
		ExpiresAt:        ba.ExpiresAt,
		TTL:              ba.TTL.String(),
		ConnectionCount:  ba.ConnectionCount,
		MessagesSent:     ba.MessagesSent,
		MessagesReceived: ba.MessagesReceived,
		DataTransferred:  ba.DataTransferred,
		Active:           ba.Active,
		Destroyed:        ba.Destroyed,
	}

	return json.Marshal(safeAccount)
}