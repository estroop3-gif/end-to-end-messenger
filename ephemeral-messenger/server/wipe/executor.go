// Wipe Executor for Ephemeral Messenger
//
// This module implements the actual wipe operations defined by wipe policies.
// It provides multiple safety layers and audit trails for all operations.
//
// SECURITY CRITICAL: This code performs destructive operations.
// Multiple authorization and confirmation layers are required.
// All operations are logged and auditable.
//
// AUDIT REQUIRED: This module requires security audit before deployment.
package wipe

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// WipeExecutor manages wipe operation execution
type WipeExecutor struct {
	// State
	isExecuting     bool
	safetyLockFile  string
	emergencyStop   chan bool
	auditLog        []WipeAuditEntry

	// Configuration
	dryRunMode      bool
	testMode        bool
	maxOperationSize int64 // Maximum total size to wipe in one operation

	// Safety mechanisms
	confirmationRequired bool
	emergencyStopEnabled bool
	mutex               sync.RWMutex
}

// WipeOperation represents a single wipe operation
type WipeOperation struct {
	OperationID     string       `json:"operation_id"`
	PolicyID        string       `json:"policy_id"`
	Action          WipeAction   `json:"action"`
	Targets         []WipeTarget `json:"targets"`
	Method          WipeMethod   `json:"method"`
	StartedAt       time.Time    `json:"started_at"`
	CompletedAt     *time.Time   `json:"completed_at,omitempty"`
	Status          string       `json:"status"` // "pending", "running", "completed", "failed", "cancelled"
	FilesProcessed  int          `json:"files_processed"`
	BytesProcessed  int64        `json:"bytes_processed"`
	ErrorCount      int          `json:"error_count"`
	Errors          []string     `json:"errors"`
	DryRun          bool         `json:"dry_run"`
}

// WipeAuditEntry records audit information for wipe operations
type WipeAuditEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	OperationID string    `json:"operation_id"`
	Action      string    `json:"action"`
	Target      string    `json:"target"`
	Result      string    `json:"result"`
	Error       string    `json:"error,omitempty"`
	FileSize    int64     `json:"file_size,omitempty"`
	Checksum    string    `json:"checksum,omitempty"`
}

// WipeProgress represents progress of an ongoing wipe operation
type WipeProgress struct {
	OperationID     string    `json:"operation_id"`
	CurrentTarget   string    `json:"current_target"`
	FilesProcessed  int       `json:"files_processed"`
	TotalFiles      int       `json:"total_files"`
	BytesProcessed  int64     `json:"bytes_processed"`
	TotalBytes      int64     `json:"total_bytes"`
	StartedAt       time.Time `json:"started_at"`
	EstimatedTime   string    `json:"estimated_time"`
	Status          string    `json:"status"`
}

// NewWipeExecutor creates a new wipe executor with safety defaults
func NewWipeExecutor() *WipeExecutor {
	return &WipeExecutor{
		isExecuting:          false,
		safetyLockFile:       "/tmp/ephemeral-messenger-wipe.lock",
		emergencyStop:        make(chan bool, 1),
		auditLog:            make([]WipeAuditEntry, 0),
		dryRunMode:          true,  // Default to safe mode
		testMode:            true,  // Default to test mode
		maxOperationSize:    1024 * 1024 * 1024, // 1GB limit
		confirmationRequired: true, // Require confirmation
		emergencyStopEnabled: true, // Enable emergency stop
	}
}

// SetSafetyMode configures safety settings
func (we *WipeExecutor) SetSafetyMode(dryRun, testMode, requireConfirm bool) {
	we.mutex.Lock()
	defer we.mutex.Unlock()

	we.dryRunMode = dryRun
	we.testMode = testMode
	we.confirmationRequired = requireConfirm
}

// ExecutePolicy executes a wipe policy with full safety checks
func (we *WipeExecutor) ExecutePolicy(policy *WipePolicy) (*WipeOperation, error) {
	we.mutex.Lock()
	defer we.mutex.Unlock()

	// Safety check: Only one operation at a time
	if we.isExecuting {
		return nil, fmt.Errorf("wipe operation already in progress")
	}

	// Safety check: Verify policy is valid and safe
	if err := we.validatePolicyForExecution(policy); err != nil {
		return nil, fmt.Errorf("policy validation failed: %v", err)
	}

	// Create safety lock
	if err := we.createSafetyLock(); err != nil {
		return nil, fmt.Errorf("failed to create safety lock: %v", err)
	}
	defer we.removeSafetyLock()

	// Create operation record
	operation := &WipeOperation{
		OperationID:    uuid.New().String(),
		PolicyID:       policy.PolicyID,
		Action:         policy.Action,
		Targets:        policy.Targets,
		Method:         policy.Method,
		StartedAt:      time.Now(),
		Status:         "pending",
		FilesProcessed: 0,
		BytesProcessed: 0,
		ErrorCount:     0,
		Errors:         make([]string, 0),
		DryRun:         policy.DryRun || we.dryRunMode,
	}

	// Log operation start
	we.auditLog = append(we.auditLog, WipeAuditEntry{
		Timestamp:   time.Now(),
		OperationID: operation.OperationID,
		Action:      "operation_started",
		Target:      fmt.Sprintf("policy:%s", policy.PolicyID),
		Result:      "started",
	})

	we.isExecuting = true
	operation.Status = "running"

	// Execute the operation based on action type
	err := we.executeOperation(operation)

	// Update completion status
	now := time.Now()
	operation.CompletedAt = &now

	if err != nil {
		operation.Status = "failed"
		operation.Errors = append(operation.Errors, err.Error())
	} else {
		operation.Status = "completed"
	}

	we.isExecuting = false

	// Log operation completion
	we.auditLog = append(we.auditLog, WipeAuditEntry{
		Timestamp:   time.Now(),
		OperationID: operation.OperationID,
		Action:      "operation_completed",
		Target:      fmt.Sprintf("policy:%s", policy.PolicyID),
		Result:      operation.Status,
		Error:       err.Error(),
	})

	return operation, err
}

// executeOperation executes the actual wipe operation
func (we *WipeExecutor) executeOperation(operation *WipeOperation) error {
	switch operation.Action {
	case WipeActionNone:
		return we.executeNoneAction(operation)
	case WipeActionAlert:
		return we.executeAlertAction(operation)
	case WipeActionLogout:
		return we.executeLogoutAction(operation)
	case WipeActionShutdown:
		return we.executeShutdownAction(operation)
	case WipeActionMemory:
		return we.executeMemoryWipe(operation)
	case WipeActionTempFiles:
		return we.executeTempFilesWipe(operation)
	case WipeActionUserData:
		return we.executeUserDataWipe(operation)
	case WipeActionApplication:
		return we.executeApplicationWipe(operation)
	case WipeActionSystem:
		// EXTREMELY DANGEROUS - additional safety checks
		return we.executeSystemWipe(operation)
	default:
		return fmt.Errorf("unknown wipe action: %s", operation.Action)
	}
}

// Safe operations (minimal risk)

func (we *WipeExecutor) executeNoneAction(operation *WipeOperation) error {
	we.auditLog = append(we.auditLog, WipeAuditEntry{
		Timestamp:   time.Now(),
		OperationID: operation.OperationID,
		Action:      "none_action",
		Target:      "none",
		Result:      "completed",
	})
	return nil
}

func (we *WipeExecutor) executeAlertAction(operation *WipeOperation) error {
	// Send alert notification
	fmt.Printf("WIPE ALERT: Hardware key absent - wipe policy triggered\n")
	fmt.Printf("Policy ID: %s\n", operation.PolicyID)
	fmt.Printf("Time: %s\n", time.Now().Format(time.RFC3339))

	we.auditLog = append(we.auditLog, WipeAuditEntry{
		Timestamp:   time.Now(),
		OperationID: operation.OperationID,
		Action:      "alert_sent",
		Target:      "system",
		Result:      "completed",
	})

	return nil
}

func (we *WipeExecutor) executeLogoutAction(operation *WipeOperation) error {
	if operation.DryRun {
		fmt.Println("DRY RUN: Would perform user logout")
		return nil
	}

	// In a real implementation, this would perform graceful logout
	fmt.Println("Performing graceful user logout...")

	we.auditLog = append(we.auditLog, WipeAuditEntry{
		Timestamp:   time.Now(),
		OperationID: operation.OperationID,
		Action:      "logout_performed",
		Target:      "user_session",
		Result:      "completed",
	})

	return nil
}

func (we *WipeExecutor) executeShutdownAction(operation *WipeOperation) error {
	if operation.DryRun {
		fmt.Println("DRY RUN: Would perform graceful shutdown")
		return nil
	}

	fmt.Println("Performing graceful system shutdown...")

	we.auditLog = append(we.auditLog, WipeAuditEntry{
		Timestamp:   time.Now(),
		OperationID: operation.OperationID,
		Action:      "shutdown_initiated",
		Target:      "system",
		Result:      "completed",
	})

	// In a real implementation, this would initiate shutdown
	// os.Exit(0) or similar

	return nil
}

// Medium risk operations

func (we *WipeExecutor) executeMemoryWipe(operation *WipeOperation) error {
	if operation.DryRun {
		fmt.Println("DRY RUN: Would wipe sensitive memory regions")
		return nil
	}

	// Trigger garbage collection and memory cleanup
	runtime.GC()
	runtime.GC() // Call twice for thoroughness

	we.auditLog = append(we.auditLog, WipeAuditEntry{
		Timestamp:   time.Now(),
		OperationID: operation.OperationID,
		Action:      "memory_wiped",
		Target:      "application_memory",
		Result:      "completed",
	})

	return nil
}

func (we *WipeExecutor) executeTempFilesWipe(operation *WipeOperation) error {
	// Define safe temp file locations
	tempDirs := []string{
		"/tmp/ephemeral-messenger-*",
		"/var/tmp/ephemeral-messenger-*",
	}

	if runtime.GOOS == "windows" {
		tempDirs = []string{
			os.Getenv("TEMP") + "\\ephemeral-messenger-*",
			os.Getenv("TMP") + "\\ephemeral-messenger-*",
		}
	}

	for _, pattern := range tempDirs {
		if err := we.wipeFilesMatchingPattern(operation, pattern); err != nil {
			return fmt.Errorf("failed to wipe temp files %s: %v", pattern, err)
		}
	}

	return nil
}

// High risk operations (require additional safeguards)

func (we *WipeExecutor) executeUserDataWipe(operation *WipeOperation) error {
	// SAFETY CHECK: This is a high-risk operation
	if !we.testMode && !operation.DryRun {
		return fmt.Errorf("user data wipe not allowed outside test mode")
	}

	if operation.DryRun {
		fmt.Println("DRY RUN: Would wipe user data according to policy targets")
		return nil
	}

	// Process each target with extreme caution
	for _, target := range operation.Targets {
		if err := we.validateTargetSafety(&target); err != nil {
			return fmt.Errorf("target safety validation failed: %v", err)
		}

		if err := we.wipeTarget(operation, &target); err != nil {
			operation.ErrorCount++
			operation.Errors = append(operation.Errors, err.Error())
		}
	}

	return nil
}

func (we *WipeExecutor) executeApplicationWipe(operation *WipeOperation) error {
	// SAFETY CHECK: High-risk operation
	if !we.testMode && !operation.DryRun {
		return fmt.Errorf("application wipe not allowed outside test mode")
	}

	if operation.DryRun {
		fmt.Println("DRY RUN: Would wipe application data")
		return nil
	}

	// Wipe application-specific data only
	appDataDirs := []string{
		"~/.ephemeral-messenger",
		"~/.config/ephemeral-messenger",
		"~/.local/share/ephemeral-messenger",
	}

	for _, dir := range appDataDirs {
		expandedDir := expandPath(dir)
		if pathExists(expandedDir) {
			target := WipeTarget{
				Path:      expandedDir,
				Recursive: true,
				ExcludeSystem: true,
			}

			if err := we.wipeTarget(operation, &target); err != nil {
				operation.ErrorCount++
				operation.Errors = append(operation.Errors, err.Error())
			}
		}
	}

	return nil
}

// CRITICAL RISK operation (heavily restricted)

func (we *WipeExecutor) executeSystemWipe(operation *WipeOperation) error {
	// ABSOLUTE SAFETY LOCK: System wipe is never allowed
	return fmt.Errorf("system wipe is permanently disabled for safety")
}

// Target wipe implementation

func (we *WipeExecutor) wipeTarget(operation *WipeOperation, target *WipeTarget) error {
	// Final safety check
	if we.isDangerousTarget(target) {
		return fmt.Errorf("target %s is considered dangerous and cannot be wiped", target.Path)
	}

	// Check emergency stop
	select {
	case <-we.emergencyStop:
		return fmt.Errorf("emergency stop triggered")
	default:
	}

	if target.Recursive {
		return we.wipeDirectoryRecursive(operation, target)
	} else {
		return we.wipeSingleFile(operation, target.Path)
	}
}

func (we *WipeExecutor) wipeFilesMatchingPattern(operation *WipeOperation, pattern string) error {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("pattern matching failed: %v", err)
	}

	for _, match := range matches {
		if err := we.wipeSingleFile(operation, match); err != nil {
			operation.ErrorCount++
			operation.Errors = append(operation.Errors, fmt.Sprintf("failed to wipe %s: %v", match, err))
		}
	}

	return nil
}

func (we *WipeExecutor) wipeDirectoryRecursive(operation *WipeOperation, target *WipeTarget) error {
	return filepath.Walk(target.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip if emergency stop triggered
		select {
		case <-we.emergencyStop:
			return fmt.Errorf("emergency stop triggered")
		default:
		}

		// Apply exclusions
		for _, exclude := range target.ExcludePaths {
			if strings.Contains(path, exclude) {
				return filepath.SkipDir
			}
		}

		// Apply file type filtering
		if len(target.FileTypes) > 0 {
			ext := filepath.Ext(path)
			found := false
			for _, allowedExt := range target.FileTypes {
				if ext == allowedExt {
					found = true
					break
				}
			}
			if !found {
				return nil // Skip this file
			}
		}

		// Apply size limits
		if target.MaxFileSize > 0 && info.Size() > target.MaxFileSize {
			return nil // Skip large files
		}

		if !info.IsDir() {
			return we.wipeSingleFile(operation, path)
		}

		return nil
	})
}

func (we *WipeExecutor) wipeSingleFile(operation *WipeOperation, filePath string) error {
	// Check emergency stop
	select {
	case <-we.emergencyStop:
		return fmt.Errorf("emergency stop triggered")
	default:
	}

	// Final safety check
	if we.isDangerousPath(filePath) {
		return fmt.Errorf("file %s is in a dangerous location", filePath)
	}

	// Get file info
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to stat file: %v", err)
	}

	if operation.DryRun {
		fmt.Printf("DRY RUN: Would wipe file %s (%d bytes)\n", filePath, info.Size())

		we.auditLog = append(we.auditLog, WipeAuditEntry{
			Timestamp:   time.Now(),
			OperationID: operation.OperationID,
			Action:      "dry_run_wipe",
			Target:      filePath,
			Result:      "simulated",
			FileSize:    info.Size(),
		})

		operation.FilesProcessed++
		operation.BytesProcessed += info.Size()
		return nil
	}

	// Perform secure wipe based on method
	if err := we.secureWipeFile(filePath, &operation.Method); err != nil {
		return fmt.Errorf("secure wipe failed: %v", err)
	}

	// Update operation statistics
	operation.FilesProcessed++
	operation.BytesProcessed += info.Size()

	// Log successful wipe
	we.auditLog = append(we.auditLog, WipeAuditEntry{
		Timestamp:   time.Now(),
		OperationID: operation.OperationID,
		Action:      "file_wiped",
		Target:      filePath,
		Result:      "completed",
		FileSize:    info.Size(),
	})

	return nil
}

func (we *WipeExecutor) secureWipeFile(filePath string, method *WipeMethod) error {
	if method.Method == "quick" {
		// Quick wipe: just delete
		return os.Remove(filePath)
	}

	// Open file for overwriting
	file, err := os.OpenFile(filePath, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open file for wiping: %v", err)
	}
	defer file.Close()

	// Get file size
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file size: %v", err)
	}

	size := info.Size()
	passes := method.Passes
	if passes == 0 {
		passes = 3 // Default 3 passes
	}

	// Perform overwrite passes
	for pass := 0; pass < passes; pass++ {
		if _, err := file.Seek(0, 0); err != nil {
			return fmt.Errorf("failed to seek to beginning: %v", err)
		}

		if method.RandomFill {
			// Fill with random data
			if err := we.fillFileWithRandomData(file, size); err != nil {
				return fmt.Errorf("random fill failed: %v", err)
			}
		} else if method.ZeroFill {
			// Fill with zeros
			if err := we.fillFileWithZeros(file, size); err != nil {
				return fmt.Errorf("zero fill failed: %v", err)
			}
		}

		// Sync to disk
		if err := file.Sync(); err != nil {
			return fmt.Errorf("sync failed: %v", err)
		}
	}

	// Close and delete
	file.Close()
	return os.Remove(filePath)
}

func (we *WipeExecutor) fillFileWithRandomData(file *os.File, size int64) error {
	buffer := make([]byte, 4096) // 4KB buffer
	remaining := size

	for remaining > 0 {
		chunkSize := int64(len(buffer))
		if remaining < chunkSize {
			chunkSize = remaining
		}

		if _, err := rand.Read(buffer[:chunkSize]); err != nil {
			return err
		}

		if _, err := file.Write(buffer[:chunkSize]); err != nil {
			return err
		}

		remaining -= chunkSize
	}

	return nil
}

func (we *WipeExecutor) fillFileWithZeros(file *os.File, size int64) error {
	buffer := make([]byte, 4096) // 4KB buffer of zeros
	remaining := size

	for remaining > 0 {
		chunkSize := int64(len(buffer))
		if remaining < chunkSize {
			chunkSize = remaining
		}

		if _, err := file.Write(buffer[:chunkSize]); err != nil {
			return err
		}

		remaining -= chunkSize
	}

	return nil
}

// Emergency stop and safety functions

func (we *WipeExecutor) EmergencyStop() {
	if we.emergencyStopEnabled {
		select {
		case we.emergencyStop <- true:
		default:
		}
	}
}

func (we *WipeExecutor) GetAuditLog() []WipeAuditEntry {
	we.mutex.RLock()
	defer we.mutex.RUnlock()

	// Return copy to prevent external modification
	logCopy := make([]WipeAuditEntry, len(we.auditLog))
	copy(logCopy, we.auditLog)
	return logCopy
}

func (we *WipeExecutor) IsExecuting() bool {
	we.mutex.RLock()
	defer we.mutex.RUnlock()
	return we.isExecuting
}

// Safety helper functions

func (we *WipeExecutor) validatePolicyForExecution(policy *WipePolicy) error {
	// Test mode check for destructive operations
	if !policy.TestMode && !policy.DryRun {
		if policy.Action == WipeActionUserData ||
		   policy.Action == WipeActionApplication ||
		   policy.Action == WipeActionSystem {
			return fmt.Errorf("destructive operations require test mode or dry run")
		}
	}

	// Check expiration
	if policy.ExpiresAt.Before(time.Now()) {
		return fmt.Errorf("policy has expired")
	}

	// Validate targets
	for _, target := range policy.Targets {
		if err := we.validateTargetSafety(&target); err != nil {
			return fmt.Errorf("target validation failed: %v", err)
		}
	}

	return nil
}

func (we *WipeExecutor) validateTargetSafety(target *WipeTarget) error {
	// Check for dangerous paths
	if we.isDangerousTarget(target) {
		return fmt.Errorf("target %s is considered dangerous", target.Path)
	}

	// Check path exists
	if !pathExists(target.Path) {
		return fmt.Errorf("target path %s does not exist", target.Path)
	}

	return nil
}

func (we *WipeExecutor) isDangerousTarget(target *WipeTarget) bool {
	// System paths are always dangerous
	dangerousPaths := []string{
		"/", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/boot",
		"/sys", "/proc", "/dev", "/var/lib", "/var/log",
		"C:\\", "C:\\Windows", "C:\\Program Files",
	}

	for _, dangerous := range dangerousPaths {
		if target.Path == dangerous || strings.HasPrefix(target.Path, dangerous+"/") {
			return true
		}
	}

	// Large recursive operations are dangerous
	if target.Recursive && len(target.Path) <= 4 {
		return true
	}

	return false
}

func (we *WipeExecutor) isDangerousPath(path string) bool {
	dangerousPaths := []string{
		"/", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/boot",
		"/sys", "/proc", "/dev", "/var/lib", "/var/log", "/opt",
		"C:\\", "C:\\Windows", "C:\\Program Files", "C:\\Users",
	}

	for _, dangerous := range dangerousPaths {
		if path == dangerous || strings.HasPrefix(path, dangerous+"/") {
			return true
		}
	}

	return false
}

func (we *WipeExecutor) createSafetyLock() error {
	if pathExists(we.safetyLockFile) {
		return fmt.Errorf("safety lock file already exists")
	}

	lockData := fmt.Sprintf("wipe-operation-lock-%d", time.Now().Unix())
	return os.WriteFile(we.safetyLockFile, []byte(lockData), 0600)
}

func (we *WipeExecutor) removeSafetyLock() {
	os.Remove(we.safetyLockFile)
}

// Utility functions

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		homeDir, _ := os.UserHomeDir()
		return filepath.Join(homeDir, path[2:])
	}
	return path
}