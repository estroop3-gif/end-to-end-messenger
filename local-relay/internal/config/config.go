package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config represents the complete relay configuration
type Config struct {
	Server   ServerConfig   `json:"server"`
	Crypto   CryptoConfig   `json:"crypto"`
	Shuttle  ShuttleConfig  `json:"shuttle"`
	Security SecurityConfig `json:"security"`
	Logging  LoggingConfig  `json:"logging"`
}

// ServerConfig contains HTTP server settings
type ServerConfig struct {
	Port            int           `json:"port"`
	Host            string        `json:"host"`
	ReadTimeout     time.Duration `json:"read_timeout"`
	WriteTimeout    time.Duration `json:"write_timeout"`
	IdleTimeout     time.Duration `json:"idle_timeout"`
	MaxHeaderBytes  int           `json:"max_header_bytes"`
	EnableTLS       bool          `json:"enable_tls"`
	TLSCert         string        `json:"tls_cert"`
	TLSKey          string        `json:"tls_key"`
	CORSOrigins     []string      `json:"cors_origins"`
	MaxConnections  int           `json:"max_connections"`
}

// CryptoConfig contains cryptographic settings
type CryptoConfig struct {
	LayerCPrivateKey     string        `json:"layer_c_private_key_hex"`
	LayerCPublicKey      string        `json:"layer_c_public_key_hex"`
	KeyRotationInterval  time.Duration `json:"key_rotation_interval"`
	SessionTimeout       time.Duration `json:"session_timeout"`
	MaxSessions          int           `json:"max_sessions"`
	SecureRandomSource   string        `json:"secure_random_source"`
	ConstantTimeOps      bool          `json:"constant_time_ops"`
}

// ShuttleConfig contains shuttle service settings
type ShuttleConfig struct {
	URL                string        `json:"url"`
	APIKey             string        `json:"api_key"`
	Timeout            time.Duration `json:"timeout"`
	RetryAttempts      int           `json:"retry_attempts"`
	RetryDelay         time.Duration `json:"retry_delay"`
	MaxRetryDelay      time.Duration `json:"max_retry_delay"`
	HealthCheckInterval time.Duration `json:"health_check_interval"`
	Circuit            CircuitConfig `json:"circuit_breaker"`
}

// CircuitConfig contains circuit breaker settings
type CircuitConfig struct {
	Enabled           bool          `json:"enabled"`
	FailureThreshold  int           `json:"failure_threshold"`
	RecoveryTimeout   time.Duration `json:"recovery_timeout"`
	MaxConcurrency    int           `json:"max_concurrency"`
}

// SecurityConfig contains security-related settings
type SecurityConfig struct {
	RateLimiting        RateLimitConfig `json:"rate_limiting"`
	AllowedClients      []string        `json:"allowed_clients"`
	RequireClientCerts  bool            `json:"require_client_certs"`
	MaxFrameSize        int             `json:"max_frame_size"`
	MaxSessionAge       time.Duration   `json:"max_session_age"`
	EnableMetrics       bool            `json:"enable_metrics"`
	MetricsPath         string          `json:"metrics_path"`
}

// RateLimitConfig contains rate limiting settings
type RateLimitConfig struct {
	Enabled         bool          `json:"enabled"`
	RequestsPerMin  int           `json:"requests_per_minute"`
	BurstSize       int           `json:"burst_size"`
	CleanupInterval time.Duration `json:"cleanup_interval"`
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Level      string `json:"level"`
	Format     string `json:"format"`
	Output     string `json:"output"`
	MaxSize    int    `json:"max_size_mb"`
	MaxBackups int    `json:"max_backups"`
	MaxAge     int    `json:"max_age_days"`
	Compress   bool   `json:"compress"`
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
			Port:           8080,
			Host:           "localhost",
			ReadTimeout:    30 * time.Second,
			WriteTimeout:   30 * time.Second,
			IdleTimeout:    120 * time.Second,
			MaxHeaderBytes: 1024 * 1024, // 1MB
			EnableTLS:      false,
			CORSOrigins:    []string{"http://localhost:3000"},
			MaxConnections: 1000,
		},
		Crypto: CryptoConfig{
			LayerCPrivateKey:    "", // Generated on first run
			LayerCPublicKey:     "", // Generated on first run
			KeyRotationInterval: 30 * time.Minute,
			SessionTimeout:      24 * time.Hour,
			MaxSessions:         10000,
			SecureRandomSource:  "/dev/urandom",
			ConstantTimeOps:     true,
		},
		Shuttle: ShuttleConfig{
			URL:                 "https://shuttle.example.com",
			APIKey:              "", // Must be configured
			Timeout:             30 * time.Second,
			RetryAttempts:       3,
			RetryDelay:          1 * time.Second,
			MaxRetryDelay:       10 * time.Second,
			HealthCheckInterval: 30 * time.Second,
			Circuit: CircuitConfig{
				Enabled:          true,
				FailureThreshold: 5,
				RecoveryTimeout:  60 * time.Second,
				MaxConcurrency:   100,
			},
		},
		Security: SecurityConfig{
			RateLimiting: RateLimitConfig{
				Enabled:         true,
				RequestsPerMin:  60,
				BurstSize:       10,
				CleanupInterval: 5 * time.Minute,
			},
			AllowedClients:     []string{}, // Empty = allow all
			RequireClientCerts: false,
			MaxFrameSize:       2 * 1024 * 1024, // 2MB
			MaxSessionAge:      24 * time.Hour,
			EnableMetrics:      true,
			MetricsPath:        "/metrics",
		},
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "json",
			Output:     "stdout",
			MaxSize:    100, // MB
			MaxBackups: 3,
			MaxAge:     28, // days
			Compress:   true,
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

	if c.Crypto.KeyRotationInterval <= 0 {
		return fmt.Errorf("key rotation interval must be positive")
	}

	if c.Crypto.SessionTimeout <= 0 {
		return fmt.Errorf("session timeout must be positive")
	}

	if c.Crypto.MaxSessions <= 0 {
		return fmt.Errorf("max sessions must be positive")
	}

	if c.Shuttle.URL == "" {
		return fmt.Errorf("shuttle URL is required")
	}

	if c.Shuttle.Timeout <= 0 {
		return fmt.Errorf("shuttle timeout must be positive")
	}

	if c.Security.MaxFrameSize <= 0 {
		return fmt.Errorf("max frame size must be positive")
	}

	if c.Security.MaxFrameSize > 10*1024*1024 { // 10MB limit
		return fmt.Errorf("max frame size too large: %d", c.Security.MaxFrameSize)
	}

	return nil
}