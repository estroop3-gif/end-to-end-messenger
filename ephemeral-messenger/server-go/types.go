package main

import (
	"time"
)

// MessageType represents different types of messages
type MessageType string

const (
	MessageTypeText     MessageType = "text"
	MessageTypeFile     MessageType = "file"
	MessageTypeDocument MessageType = "document"
	MessageTypeStatus   MessageType = "status"
	MessageTypePresence MessageType = "presence"
)

// PresenceStatus represents client presence status
type PresenceStatus string

const (
	PresenceOnline    PresenceStatus = "online"
	PresenceOffline   PresenceStatus = "offline"
	PresenceAway      PresenceStatus = "away"
	PresenceInvisible PresenceStatus = "invisible"
)

// EnhancedMessage represents a full-featured ephemeral message
type EnhancedMessage struct {
	ID              string            `json:"id"`
	Type            MessageType       `json:"type"`
	From            string            `json:"from"`
	To              string            `json:"to"`
	Content         string            `json:"content"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	Timestamp       time.Time         `json:"timestamp"`
	ExpiresAt       time.Time         `json:"expires_at"`
	DeliveryType    string            `json:"delivery_type"`
	Priority        int               `json:"priority"`
	ReadReceipt     bool              `json:"read_receipt"`
	ForwardingCount int               `json:"forwarding_count"`
	MaxForwards     int               `json:"max_forwards"`
}

// ClientInfo represents extended client information
type ClientInfo struct {
	Fingerprint   string            `json:"fingerprint"`
	PublicKey     string            `json:"public_key,omitempty"`
	Presence      PresenceStatus    `json:"presence"`
	LastSeen      time.Time         `json:"last_seen"`
	Capabilities  []string          `json:"capabilities"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	ConnectionID  string            `json:"connection_id"`
	IPAddress     string            `json:"ip_address,omitempty"`
}

// DeliveryReceipt represents message delivery confirmation
type DeliveryReceipt struct {
	MessageID     string    `json:"message_id"`
	Status        string    `json:"status"` // "sent", "delivered", "read", "failed"
	Timestamp     time.Time `json:"timestamp"`
	RecipientID   string    `json:"recipient_id"`
	ErrorMessage  string    `json:"error_message,omitempty"`
}

// ServerStats represents server statistics
type ServerStats struct {
	Uptime          time.Duration `json:"uptime"`
	TotalClients    int           `json:"total_clients"`
	ActiveClients   int           `json:"active_clients"`
	PendingMessages int           `json:"pending_messages"`
	MessagesRouted  int64         `json:"messages_routed"`
	BytesTransferred int64        `json:"bytes_transferred"`
	ErrorCount      int64         `json:"error_count"`
	StartTime       time.Time     `json:"start_time"`
}

// SecurityEvent represents a security-related event
type SecurityEvent struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	Severity    string            `json:"severity"`
	Timestamp   time.Time         `json:"timestamp"`
	ClientID    string            `json:"client_id,omitempty"`
	IPAddress   string            `json:"ip_address"`
	Description string            `json:"description"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// RateLimitConfig represents rate limiting configuration
type RateLimitConfig struct {
	RequestsPerMinute int           `json:"requests_per_minute"`
	BurstLimit        int           `json:"burst_limit"`
	WindowSize        time.Duration `json:"window_size"`
	Enabled           bool          `json:"enabled"`
}

// ServerConfig represents server configuration
type ServerConfig struct {
	Port                string            `json:"port"`
	MaxMessageSize      int               `json:"max_message_size"`
	MessageTTL          time.Duration     `json:"message_ttl"`
	CleanupInterval     time.Duration     `json:"cleanup_interval"`
	MaxClientsPerIP     int               `json:"max_clients_per_ip"`
	RateLimit           RateLimitConfig   `json:"rate_limit"`
	TorEnabled          bool              `json:"tor_enabled"`
	TorHiddenServiceDir string            `json:"tor_hidden_service_dir"`
	LogLevel            string            `json:"log_level"`
	SecurityOptions     map[string]string `json:"security_options"`
}