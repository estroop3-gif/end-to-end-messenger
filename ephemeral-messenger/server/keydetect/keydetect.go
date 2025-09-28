// Package keydetect provides hardware key detection and validation for Ephemeral Messenger
//
// This module monitors removable devices for valid keyfiles and enforces hardware key
// requirements. It uses multiple detection methods for reliability and provides
// configurable grace periods for user convenience.
//
// SECURITY NOTE: This module is read-only and performs no destructive operations.
// It only detects and validates keyfiles - enforcement actions are handled separately.
package keydetect

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"../keyfile"
)

// KeyDetector monitors for hardware key presence and validates keyfiles
type KeyDetector struct {
	config          *Config
	currentKey      *ValidatedKey
	mu              sync.RWMutex
	watcher         *fsnotify.Watcher
	callbacks       []KeyEventCallback
	graceTimer      *time.Timer
	gracePeriodFunc func()
	ctx             context.Context
	cancel          context.CancelFunc
	isRunning       bool
}

// Config holds key detection configuration
type Config struct {
	// Paths to monitor for removable devices
	DevicePaths []string `json:"device_paths"`

	// Key directory name to look for on devices (e.g., "KEYSTORE")
	KeyDirName string `json:"key_dir_name"`

	// Keyfile name to validate (e.g., "secure_key.json")
	KeyFileName string `json:"key_file_name"`

	// Grace period when key is removed (seconds)
	GracePeriodSec int `json:"grace_period_sec"`

	// Polling interval as fallback (seconds)
	PollingIntervalSec int `json:"polling_interval_sec"`

	// Whether to use filesystem events (recommended)
	UseFilesystemEvents bool `json:"use_filesystem_events"`

	// Maximum concurrent device scans
	MaxConcurrentScans int `json:"max_concurrent_scans"`

	// Enable detailed logging
	VerboseLogging bool `json:"verbose_logging"`
}

// ValidatedKey represents a successfully validated hardware key
type ValidatedKey struct {
	// Device information
	DeviceUUID   string `json:"device_uuid"`
	DevicePath   string `json:"device_path"`
	KeyFilePath  string `json:"key_file_path"`

	// Keyfile content
	KeyFile *keyfile.ValidatedKeyFile `json:"keyfile"`

	// Detection metadata
	DetectedAt  time.Time `json:"detected_at"`
	LastSeen    time.Time `json:"last_seen"`
	AccessCount int       `json:"access_count"`
}

// KeyEventCallback is called when key status changes
type KeyEventCallback func(event KeyEvent)

// KeyEvent represents a key detection event
type KeyEvent struct {
	Type      KeyEventType  `json:"type"`
	Key       *ValidatedKey `json:"key,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
	Message   string        `json:"message"`
	Error     string        `json:"error,omitempty"`
}

// KeyEventType represents the type of key event
type KeyEventType string

const (
	KeyEventAttached       KeyEventType = "attached"
	KeyEventRemoved        KeyEventType = "removed"
	KeyEventInvalid        KeyEventType = "invalid"
	KeyEventExpired        KeyEventType = "expired"
	KeyEventGraceStarted   KeyEventType = "grace_started"
	KeyEventGraceTimeout   KeyEventType = "grace_timeout"
	KeyEventGraceCancelled KeyEventType = "grace_cancelled"
	KeyEventValidated      KeyEventType = "validated"
	KeyEventError          KeyEventType = "error"
)

// DefaultConfig returns a sensible default configuration
func DefaultConfig() *Config {
	return &Config{
		DevicePaths: []string{
			"/media",
			"/run/media",
			"/mnt",
			"/run/user/1000",         // User session mounts
			"/run/user/1001",         // Amnesia user in Tails
		},
		KeyDirName:             "KEYSTORE",
		KeyFileName:            "secure_key.json",
		GracePeriodSec:         300, // 5 minutes
		PollingIntervalSec:     10,  // 10 seconds
		UseFilesystemEvents:    true,
		MaxConcurrentScans:     3,
		VerboseLogging:         false,
	}
}

// NewKeyDetector creates a new key detector instance
func NewKeyDetector(config *Config) (*KeyDetector, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Validate configuration
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	var watcher *fsnotify.Watcher
	var err error

	if config.UseFilesystemEvents {
		watcher, err = fsnotify.NewWatcher()
		if err != nil {
			log.Printf("Warning: Failed to create filesystem watcher: %v", err)
			log.Printf("Falling back to polling-only mode")
			config.UseFilesystemEvents = false
		}
	}

	detector := &KeyDetector{
		config:    config,
		watcher:   watcher,
		callbacks: make([]KeyEventCallback, 0),
		ctx:       ctx,
		cancel:    cancel,
		isRunning: false,
	}

	// Add device paths to watcher if available
	if watcher != nil {
		for _, path := range config.DevicePaths {
			if _, err := os.Stat(path); err == nil {
				if err := watcher.Add(path); err != nil {
					log.Printf("Warning: Failed to watch path %s: %v", path, err)
				} else if config.VerboseLogging {
					log.Printf("Watching path: %s", path)
				}
			}
		}
	}

	return detector, nil
}

// Start begins key detection monitoring
func (kd *KeyDetector) Start() error {
	kd.mu.Lock()
	defer kd.mu.Unlock()

	if kd.isRunning {
		return fmt.Errorf("key detector is already running")
	}

	log.Println("Starting hardware key detection...")

	// Initial scan for existing keys
	if err := kd.performInitialScan(); err != nil {
		log.Printf("Warning: Initial key scan failed: %v", err)
	}

	// Start monitoring goroutines
	if kd.config.UseFilesystemEvents && kd.watcher != nil {
		go kd.monitorFilesystemEvents()
	}

	go kd.pollingLoop()

	kd.isRunning = true

	log.Printf("Key detection started (filesystem_events: %v, polling: %vs)",
		kd.config.UseFilesystemEvents, kd.config.PollingIntervalSec)

	return nil
}

// Stop stops key detection monitoring
func (kd *KeyDetector) Stop() error {
	kd.mu.Lock()
	defer kd.mu.Unlock()

	if !kd.isRunning {
		return nil
	}

	log.Println("Stopping hardware key detection...")

	// Cancel context to stop goroutines
	kd.cancel()

	// Close filesystem watcher
	if kd.watcher != nil {
		if err := kd.watcher.Close(); err != nil {
			log.Printf("Warning: Error closing filesystem watcher: %v", err)
		}
	}

	// Stop grace timer
	if kd.graceTimer != nil {
		kd.graceTimer.Stop()
		kd.graceTimer = nil
	}

	kd.isRunning = false

	log.Println("Key detection stopped")
	return nil
}

// GetCurrentKey returns the currently validated key, if any
func (kd *KeyDetector) GetCurrentKey() *ValidatedKey {
	kd.mu.RLock()
	defer kd.mu.RUnlock()
	return kd.currentKey
}

// IsKeyPresent returns true if a valid key is currently attached
func (kd *KeyDetector) IsKeyPresent() bool {
	return kd.GetCurrentKey() != nil
}

// AddCallback registers a callback for key events
func (kd *KeyDetector) AddCallback(callback KeyEventCallback) {
	kd.mu.Lock()
	defer kd.mu.Unlock()
	kd.callbacks = append(kd.callbacks, callback)
}

// SetGracePeriodCallback sets the function to call when grace period expires
func (kd *KeyDetector) SetGracePeriodCallback(callback func()) {
	kd.mu.Lock()
	defer kd.mu.Unlock()
	kd.gracePeriodFunc = callback
}

// RefreshDetection manually triggers a key detection scan
func (kd *KeyDetector) RefreshDetection() error {
	if !kd.isRunning {
		return fmt.Errorf("key detector is not running")
	}

	go func() {
		if err := kd.performScan(); err != nil {
			kd.emitEvent(KeyEvent{
				Type:      KeyEventError,
				Timestamp: time.Now(),
				Message:   "Manual refresh failed",
				Error:     err.Error(),
			})
		}
	}()

	return nil
}

// GetDetectionStats returns statistics about key detection
func (kd *KeyDetector) GetDetectionStats() map[string]interface{} {
	kd.mu.RLock()
	defer kd.mu.RUnlock()

	stats := map[string]interface{}{
		"is_running":            kd.isRunning,
		"current_key_present":   kd.currentKey != nil,
		"grace_timer_active":    kd.graceTimer != nil,
		"filesystem_events":     kd.config.UseFilesystemEvents,
		"polling_interval_sec":  kd.config.PollingIntervalSec,
		"grace_period_sec":      kd.config.GracePeriodSec,
		"watched_paths":         kd.config.DevicePaths,
	}

	if kd.currentKey != nil {
		stats["current_key"] = map[string]interface{}{
			"user_id":      kd.currentKey.KeyFile.UserID,
			"fingerprint":  kd.currentKey.KeyFile.Fingerprint,
			"detected_at":  kd.currentKey.DetectedAt,
			"last_seen":    kd.currentKey.LastSeen,
			"access_count": kd.currentKey.AccessCount,
			"expires_at":   kd.currentKey.KeyFile.ExpiresAt,
		}
	}

	return stats
}

// performInitialScan scans for keys on startup
func (kd *KeyDetector) performInitialScan() error {
	if kd.config.VerboseLogging {
		log.Println("Performing initial key scan...")
	}

	return kd.performScan()
}

// performScan scans all configured paths for valid keyfiles
func (kd *KeyDetector) performScan() error {
	for _, basePath := range kd.config.DevicePaths {
		if err := kd.scanPath(basePath); err != nil {
			if kd.config.VerboseLogging {
				log.Printf("Scan path %s failed: %v", basePath, err)
			}
			continue
		}

		// If we found a key, stop scanning
		kd.mu.RLock()
		hasKey := kd.currentKey != nil
		kd.mu.RUnlock()

		if hasKey {
			break
		}
	}

	return nil
}

// scanPath scans a specific path for keyfiles
func (kd *KeyDetector) scanPath(basePath string) error {
	if _, err := os.Stat(basePath); err != nil {
		return err // Path doesn't exist
	}

	return filepath.WalkDir(basePath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Continue on errors
		}

		// Look for key directory
		if d.IsDir() && d.Name() == kd.config.KeyDirName {
			keyFilePath := filepath.Join(path, kd.config.KeyFileName)

			if kd.config.VerboseLogging {
				log.Printf("Checking for keyfile: %s", keyFilePath)
			}

			if _, err := os.Stat(keyFilePath); err == nil {
				if validatedKey, err := kd.validateAndCreateKey(keyFilePath, path); err == nil {
					kd.setCurrentKey(validatedKey)
					return filepath.SkipAll // Found valid key, stop scanning
				} else {
					log.Printf("Invalid keyfile at %s: %v", keyFilePath, err)
					kd.emitEvent(KeyEvent{
						Type:      KeyEventInvalid,
						Timestamp: time.Now(),
						Message:   fmt.Sprintf("Invalid keyfile: %s", keyFilePath),
						Error:     err.Error(),
					})
				}
			}
		}

		return nil
	})
}

// validateAndCreateKey validates a keyfile and creates a ValidatedKey
func (kd *KeyDetector) validateAndCreateKey(keyFilePath, devicePath string) (*ValidatedKey, error) {
	// Read keyfile
	data, err := os.ReadFile(keyFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read keyfile: %w", err)
	}

	// Parse keyfile
	kf, err := keyfile.ParseKeyFile(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse keyfile: %w", err)
	}

	// Perform full validation
	validatedKF, err := kf.FullValidation()
	if err != nil {
		return nil, fmt.Errorf("keyfile validation failed: %w", err)
	}

	// Get device UUID (simplified for now)
	deviceUUID, err := kd.getDeviceUUID(devicePath)
	if err != nil {
		log.Printf("Warning: Could not determine device UUID for %s: %v", devicePath, err)
		deviceUUID = fmt.Sprintf("unknown-%d", time.Now().Unix())
	}

	// Create validated key
	validatedKey := &ValidatedKey{
		DeviceUUID:  deviceUUID,
		DevicePath:  devicePath,
		KeyFilePath: keyFilePath,
		KeyFile:     validatedKF,
		DetectedAt:  time.Now(),
		LastSeen:    time.Now(),
		AccessCount: 1,
	}

	if kd.config.VerboseLogging {
		log.Printf("Validated keyfile: %s", validatedKF.Summary())
	}

	return validatedKey, nil
}

// setCurrentKey sets the current validated key and triggers callbacks
func (kd *KeyDetector) setCurrentKey(key *ValidatedKey) {
	kd.mu.Lock()
	defer kd.mu.Unlock()

	// Cancel grace timer if key is attached
	if kd.graceTimer != nil {
		kd.graceTimer.Stop()
		kd.graceTimer = nil

		kd.emitEventUnlocked(KeyEvent{
			Type:      KeyEventGraceCancelled,
			Key:       key,
			Timestamp: time.Now(),
			Message:   "Grace period cancelled - key reattached",
		})
	}

	oldKey := kd.currentKey
	kd.currentKey = key

	// Emit appropriate event
	if oldKey == nil {
		kd.emitEventUnlocked(KeyEvent{
			Type:      KeyEventAttached,
			Key:       key,
			Timestamp: time.Now(),
			Message:   fmt.Sprintf("Hardware key attached: %s", key.KeyFile.UserID),
		})
		log.Printf("Hardware key attached: user %s (fingerprint: %s)",
			key.KeyFile.UserID, key.KeyFile.Fingerprint)
	} else {
		kd.emitEventUnlocked(KeyEvent{
			Type:      KeyEventValidated,
			Key:       key,
			Timestamp: time.Now(),
			Message:   fmt.Sprintf("Hardware key revalidated: %s", key.KeyFile.UserID),
		})
		log.Printf("Hardware key revalidated: user %s", key.KeyFile.UserID)
	}
}

// clearCurrentKey clears the current key and starts grace period
func (kd *KeyDetector) clearCurrentKey() {
	kd.mu.Lock()
	defer kd.mu.Unlock()

	if kd.currentKey == nil {
		return // No key to clear
	}

	oldKey := kd.currentKey
	kd.currentKey = nil

	// Start grace period timer
	if kd.graceTimer != nil {
		kd.graceTimer.Stop()
	}

	kd.graceTimer = time.AfterFunc(
		time.Duration(kd.config.GracePeriodSec)*time.Second,
		func() {
			kd.onGracePeriodExpired()
		},
	)

	// Emit events
	kd.emitEventUnlocked(KeyEvent{
		Type:      KeyEventRemoved,
		Key:       oldKey,
		Timestamp: time.Now(),
		Message:   fmt.Sprintf("Hardware key removed: %s", oldKey.KeyFile.UserID),
	})

	kd.emitEventUnlocked(KeyEvent{
		Type:      KeyEventGraceStarted,
		Key:       oldKey,
		Timestamp: time.Now(),
		Message:   fmt.Sprintf("Grace period started (%d seconds)", kd.config.GracePeriodSec),
	})

	log.Printf("Hardware key removed: user %s (grace period: %d seconds)",
		oldKey.KeyFile.UserID, kd.config.GracePeriodSec)
}

// onGracePeriodExpired is called when the grace period expires
func (kd *KeyDetector) onGracePeriodExpired() {
	kd.mu.Lock()
	gracePeriodFunc := kd.gracePeriodFunc
	kd.graceTimer = nil
	kd.mu.Unlock()

	// Emit timeout event
	kd.emitEvent(KeyEvent{
		Type:      KeyEventGraceTimeout,
		Timestamp: time.Now(),
		Message:   "Grace period expired - hardware key enforcement triggered",
	})

	// Call grace period function if set
	if gracePeriodFunc != nil {
		go gracePeriodFunc()
	}

	log.Println("Grace period expired - hardware key enforcement triggered")
}

// monitorFilesystemEvents monitors filesystem events for key changes
func (kd *KeyDetector) monitorFilesystemEvents() {
	for {
		select {
		case event, ok := <-kd.watcher.Events:
			if !ok {
				return
			}

			if kd.config.VerboseLogging {
				log.Printf("Filesystem event: %s %s", event.Op, event.Name)
			}

			// Handle filesystem events
			if event.Has(fsnotify.Create) || event.Has(fsnotify.Write) {
				// New device might be mounted or file written
				go func() {
					time.Sleep(1 * time.Second) // Brief delay for mount/write to complete
					kd.performScan()
				}()
			} else if event.Has(fsnotify.Remove) {
				// Device might be unmounted
				go func() {
					time.Sleep(1 * time.Second) // Brief delay
					kd.checkCurrentKeyStillValid()
				}()
			}

		case err, ok := <-kd.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Filesystem watcher error: %v", err)

		case <-kd.ctx.Done():
			return
		}
	}
}

// pollingLoop polls for key presence as a fallback mechanism
func (kd *KeyDetector) pollingLoop() {
	ticker := time.NewTicker(time.Duration(kd.config.PollingIntervalSec) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Check if current key is still present
			if err := kd.checkCurrentKeyStillValid(); err != nil {
				if kd.config.VerboseLogging {
					log.Printf("Current key validation failed: %v", err)
				}
			}

			// If no current key, scan for new ones
			kd.mu.RLock()
			hasKey := kd.currentKey != nil
			kd.mu.RUnlock()

			if !hasKey {
				if err := kd.performScan(); err != nil && kd.config.VerboseLogging {
					log.Printf("Polling scan failed: %v", err)
				}
			}

		case <-kd.ctx.Done():
			return
		}
	}
}

// checkCurrentKeyStillValid verifies the current key is still accessible
func (kd *KeyDetector) checkCurrentKeyStillValid() error {
	kd.mu.RLock()
	currentKey := kd.currentKey
	kd.mu.RUnlock()

	if currentKey == nil {
		return nil // No key to check
	}

	// Check if keyfile is still accessible
	if _, err := os.Stat(currentKey.KeyFilePath); err != nil {
		// Key file no longer accessible
		kd.clearCurrentKey()
		return fmt.Errorf("keyfile no longer accessible: %w", err)
	}

	// Update last seen time
	kd.mu.Lock()
	if kd.currentKey != nil {
		kd.currentKey.LastSeen = time.Now()
		kd.currentKey.AccessCount++
	}
	kd.mu.Unlock()

	return nil
}

// emitEvent sends an event to all registered callbacks (thread-safe)
func (kd *KeyDetector) emitEvent(event KeyEvent) {
	kd.mu.RLock()
	callbacks := make([]KeyEventCallback, len(kd.callbacks))
	copy(callbacks, kd.callbacks)
	kd.mu.RUnlock()

	for _, callback := range callbacks {
		go func(cb KeyEventCallback) {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Callback panic: %v", r)
				}
			}()
			cb(event)
		}(callback)
	}
}

// emitEventUnlocked sends an event to all callbacks (assumes lock held)
func (kd *KeyDetector) emitEventUnlocked(event KeyEvent) {
	callbacks := make([]KeyEventCallback, len(kd.callbacks))
	copy(callbacks, kd.callbacks)

	for _, callback := range callbacks {
		go func(cb KeyEventCallback) {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Callback panic: %v", r)
				}
			}()
			cb(event)
		}(callback)
	}
}

// getDeviceUUID attempts to determine the UUID of the device
func (kd *KeyDetector) getDeviceUUID(devicePath string) (string, error) {
	// This is a simplified implementation
	// In production, use proper device identification via lsblk, udev, etc.

	// Try to find the device in /dev/disk/by-uuid
	// This is a placeholder - implement proper device UUID detection
	return fmt.Sprintf("device-%d", time.Now().Unix()), nil
}

// validateConfig validates the detector configuration
func validateConfig(config *Config) error {
	if len(config.DevicePaths) == 0 {
		return fmt.Errorf("at least one device path must be specified")
	}

	if config.KeyDirName == "" {
		return fmt.Errorf("key directory name cannot be empty")
	}

	if config.KeyFileName == "" {
		return fmt.Errorf("key file name cannot be empty")
	}

	if config.GracePeriodSec < 0 {
		return fmt.Errorf("grace period cannot be negative")
	}

	if config.PollingIntervalSec < 1 {
		return fmt.Errorf("polling interval must be at least 1 second")
	}

	if config.MaxConcurrentScans < 1 {
		config.MaxConcurrentScans = 1
	}

	return nil
}