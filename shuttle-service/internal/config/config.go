package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config represents the complete shuttle service configuration
type Config struct {
	Server ServerConfig `json:"server"`
	Redis  RedisConfig  `json:"redis"`
	Queue  QueueConfig  `json:"queue"`
	Auth   AuthConfig   `json:"auth"`
	Limits LimitsConfig `json:"limits"`
}

// ServerConfig contains HTTP server settings
type ServerConfig struct {
	Port         int           `json:"port"`
	Host         string        `json:"host"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
	IdleTimeout  time.Duration `json:"idle_timeout"`
	EnableTLS    bool          `json:"enable_tls"`
	TLSCert      string        `json:"tls_cert"`
	TLSKey       string        `json:"tls_key"`
	CORSOrigins  []string      `json:"cors_origins"`
}

// RedisConfig contains Redis connection settings
type RedisConfig struct {
	Addr        string        `json:"addr"`
	Password    string        `json:"password"`
	DB          int           `json:"db"`
	PoolSize    int           `json:"pool_size"`
	MinIdleConns int          `json:"min_idle_conns"`
	MaxRetries  int           `json:"max_retries"`
	DialTimeout time.Duration `json:"dial_timeout"`
	ReadTimeout time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
	IdleTimeout time.Duration `json:"idle_timeout"`
}

// QueueConfig contains message queue settings
type QueueConfig struct {
	DefaultTTL       time.Duration `json:"default_ttl"`
	MaxTTL           time.Duration `json:"max_ttl"`
	MaxMessageSize   int           `json:"max_message_size"`
	MaxQueueSize     int           `json:"max_queue_size"`
	CleanupInterval  time.Duration `json:"cleanup_interval"`
	MaxRetries       int           `json:"max_retries"`
	RetryDelay       time.Duration `json:"retry_delay"`
	DeadLetterTTL    time.Duration `json:"dead_letter_ttl"`
}

// AuthConfig contains authentication settings
type AuthConfig struct {
	Enabled       bool          `json:"enabled"`
	JWTSecret     string        `json:"jwt_secret"`
	TokenTTL      time.Duration `json:"token_ttl"`
	APIKeys       []APIKey      `json:"api_keys"`
	RequireHTTPS  bool          `json:"require_https"`
}

// APIKey represents an API key configuration
type APIKey struct {
	Name        string   `json:"name"`
	Key         string   `json:"key"`
	Permissions []string `json:"permissions"`
	RateLimit   int      `json:"rate_limit"`
}

// LimitsConfig contains rate limiting and quota settings
type LimitsConfig struct {
	RateLimit       RateLimitConfig `json:"rate_limit"`
	MaxConcurrent   int             `json:"max_concurrent"`
	MaxMemoryMB     int             `json:"max_memory_mb"`
	MaxConnections  int             `json:"max_connections"`
}

// RateLimitConfig contains rate limiting settings
type RateLimitConfig struct {
	Enabled         bool          `json:"enabled"`
	RequestsPerMin  int           `json:"requests_per_minute"`
	BurstSize       int           `json:"burst_size"`
	CleanupInterval time.Duration `json:"cleanup_interval"`
	ByIP            bool          `json:"by_ip"`
	ByAPIKey        bool          `json:"by_api_key"`
}

// Load reads and parses the configuration file
func Load(path string) (*Config, error) {
	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Create default config if it doesn't exist
		cfg := DefaultConfig()
		if err := Save(cfg, path); err != nil {
			return nil, fmt.Errorf("failed to create default config: %w", err)
		}
		return cfg, nil
	}

	// Read existing config
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// Save writes the configuration to a file
func Save(cfg *Config, path string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Port:         8081,
			Host:         "0.0.0.0",
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
			EnableTLS:    false,
			CORSOrigins:  []string{"*"},
		},
		Redis: RedisConfig{
			Addr:         "localhost:6379",
			Password:     "",
			DB:           0,
			PoolSize:     10,
			MinIdleConns: 2,
			MaxRetries:   3,
			DialTimeout:  5 * time.Second,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
			IdleTimeout:  5 * time.Minute,
		},
		Queue: QueueConfig{
			DefaultTTL:      24 * time.Hour,
			MaxTTL:          7 * 24 * time.Hour,
			MaxMessageSize:  2 * 1024 * 1024, // 2MB
			MaxQueueSize:    10000,
			CleanupInterval: 5 * time.Minute,
			MaxRetries:      3,
			RetryDelay:      1 * time.Minute,
			DeadLetterTTL:   24 * time.Hour,
		},
		Auth: AuthConfig{
			Enabled:      false,
			JWTSecret:    "", // Generated on first run if auth enabled
			TokenTTL:     24 * time.Hour,
			APIKeys:      []APIKey{},
			RequireHTTPS: true,
		},
		Limits: LimitsConfig{
			RateLimit: RateLimitConfig{
				Enabled:         true,
				RequestsPerMin:  100,
				BurstSize:       20,
				CleanupInterval: 5 * time.Minute,
				ByIP:            true,
				ByAPIKey:        true,
			},
			MaxConcurrent:  1000,
			MaxMemoryMB:    512,
			MaxConnections: 5000,
		},
	}
}

// Validate checks the configuration for errors
func (c *Config) Validate() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}

	if c.Server.ReadTimeout <= 0 {
		return fmt.Errorf("read timeout must be positive")
	}

	if c.Server.WriteTimeout <= 0 {
		return fmt.Errorf("write timeout must be positive")
	}

	if c.Redis.Addr == "" {
		return fmt.Errorf("redis address is required")
	}

	if c.Queue.DefaultTTL <= 0 {
		return fmt.Errorf("default TTL must be positive")
	}

	if c.Queue.MaxTTL <= 0 {
		return fmt.Errorf("max TTL must be positive")
	}

	if c.Queue.DefaultTTL > c.Queue.MaxTTL {
		return fmt.Errorf("default TTL cannot exceed max TTL")
	}

	if c.Queue.MaxMessageSize <= 0 {
		return fmt.Errorf("max message size must be positive")
	}

	if c.Queue.MaxQueueSize <= 0 {
		return fmt.Errorf("max queue size must be positive")
	}

	if c.Auth.Enabled && c.Auth.JWTSecret == "" {
		return fmt.Errorf("JWT secret is required when auth is enabled")
	}

	if c.Limits.MaxConcurrent <= 0 {
		return fmt.Errorf("max concurrent must be positive")
	}

	if c.Limits.MaxMemoryMB <= 0 {
		return fmt.Errorf("max memory must be positive")
	}

	return nil
}