// Wipe Monitor for Ephemeral Messenger
//
// This module monitors system conditions and triggers wipe policies
// when conditions are met. It provides the monitoring and triggering
// logic for the hardware key enforcement system.
//
// SECURITY CRITICAL: This code decides when to trigger destructive operations.
// All trigger conditions must be carefully validated to prevent false positives.
//
// AUDIT REQUIRED: This module requires security audit before deployment.
package wipe

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// WipeMonitor monitors system conditions and triggers wipe policies
type WipeMonitor struct {
	// Core components
	policyManager *WipePolicyManager
	executor      *WipeExecutor

	// State tracking
	isRunning        bool
	keyPresent       bool
	keyAbsentSince   *time.Time
	gracePeriodEnd   *time.Time
	failedAuthCount  int
	lastActivityTime time.Time

	// Configuration
	checkInterval      time.Duration
	gracePeriod        time.Duration
	maxFailedAuth      int
	activityTimeout    time.Duration

	// Safety mechanisms
	emergencyDisabled  bool
	testMode           bool
	requireConfirmation bool

	// Monitoring
	triggerHistory     []TriggerEvent
	monitoringStats    MonitoringStats
	alertCallbacks     []AlertCallback

	// Synchronization
	mutex              sync.RWMutex
	ctx                context.Context
	cancel             context.CancelFunc
}

// TriggerEvent records when and why a trigger occurred
type TriggerEvent struct {
	EventID         string          `json:"event_id"`
	Timestamp       time.Time       `json:"timestamp"`
	TriggerType     string          `json:"trigger_type"`
	PolicyID        string          `json:"policy_id"`
	Conditions      TriggerState    `json:"conditions"`
	Action          WipeAction      `json:"action"`
	Result          string          `json:"result"`
	Error           string          `json:"error,omitempty"`
	PreventedReason string          `json:"prevented_reason,omitempty"`
}

// TriggerState captures the state when a trigger occurs
type TriggerState struct {
	KeyPresent         bool      `json:"key_present"`
	KeyAbsentDuration  string    `json:"key_absent_duration"`
	GracePeriodActive  bool      `json:"grace_period_active"`
	GracePeriodExpired bool      `json:"grace_period_expired"`
	FailedAuthCount    int       `json:"failed_auth_count"`
	LastActivity       time.Time `json:"last_activity"`
	SystemLoad         float64   `json:"system_load"`
	NetworkConnected   bool      `json:"network_connected"`
	BatteryLevel       int       `json:"battery_level"`
}

// MonitoringStats tracks monitoring statistics
type MonitoringStats struct {
	StartedAt           time.Time `json:"started_at"`
	ChecksPerformed     int64     `json:"checks_performed"`
	TriggersEvaluated   int64     `json:"triggers_evaluated"`
	PoliciesTriggered   int64     `json:"policies_triggered"`
	OperationsExecuted  int64     `json:"operations_executed"`
	LastCheckTime       time.Time `json:"last_check_time"`
	AverageCheckTime    string    `json:"average_check_time"`
}

// AlertCallback is called when alerts are generated
type AlertCallback func(alertType string, message string, severity string)

// NewWipeMonitor creates a new wipe monitor
func NewWipeMonitor(policyManager *WipePolicyManager, executor *WipeExecutor) *WipeMonitor {
	ctx, cancel := context.WithCancel(context.Background())

	return &WipeMonitor{
		policyManager:       policyManager,
		executor:           executor,
		isRunning:          false,
		keyPresent:         true, // Assume key present initially
		gracePeriod:        5 * time.Minute, // Default 5 minute grace period
		checkInterval:      10 * time.Second, // Check every 10 seconds
		maxFailedAuth:      3,     // Max 3 failed authentications
		activityTimeout:    30 * time.Minute, // 30 minutes of inactivity
		emergencyDisabled:  false,
		testMode:           true,  // Default to test mode
		requireConfirmation: true, // Require confirmation
		triggerHistory:     make([]TriggerEvent, 0),
		alertCallbacks:     make([]AlertCallback, 0),
		ctx:               ctx,
		cancel:            cancel,
	}
}

// Start begins monitoring for wipe conditions
func (wm *WipeMonitor) Start() error {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	if wm.isRunning {
		return fmt.Errorf("wipe monitor is already running")
	}

	// Initialize monitoring stats
	wm.monitoringStats = MonitoringStats{
		StartedAt:     time.Now(),
		LastCheckTime: time.Now(),
	}

	wm.isRunning = true
	wm.lastActivityTime = time.Now()

	// Start monitoring goroutine
	go wm.monitoringLoop()

	wm.sendAlert("monitor_started", "Wipe monitoring started", "info")
	return nil
}

// Stop stops the wipe monitoring
func (wm *WipeMonitor) Stop() error {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	if !wm.isRunning {
		return fmt.Errorf("wipe monitor is not running")
	}

	wm.cancel()
	wm.isRunning = false

	wm.sendAlert("monitor_stopped", "Wipe monitoring stopped", "info")
	return nil
}

// UpdateKeyPresence updates the hardware key presence status
func (wm *WipeMonitor) UpdateKeyPresence(present bool) {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	previousState := wm.keyPresent
	wm.keyPresent = present

	now := time.Now()

	if !present && previousState {
		// Key just became absent
		wm.keyAbsentSince = &now
		wm.gracePeriodEnd = &[]time.Time{now.Add(wm.gracePeriod)}[0]

		wm.sendAlert("key_removed",
			fmt.Sprintf("Hardware key removed, grace period ends at %s",
				wm.gracePeriodEnd.Format(time.RFC3339)), "warning")
	} else if present && !previousState {
		// Key just became present
		wm.keyAbsentSince = nil
		wm.gracePeriodEnd = nil

		wm.sendAlert("key_inserted", "Hardware key inserted, grace period cancelled", "info")
	}
}

// RecordFailedAuthentication records a failed authentication attempt
func (wm *WipeMonitor) RecordFailedAuthentication() {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	wm.failedAuthCount++

	wm.sendAlert("auth_failed",
		fmt.Sprintf("Authentication failed (%d/%d)", wm.failedAuthCount, wm.maxFailedAuth),
		"warning")
}

// RecordActivity records user/system activity
func (wm *WipeMonitor) RecordActivity() {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	wm.lastActivityTime = time.Now()
}

// AddAlertCallback adds a callback for alert notifications
func (wm *WipeMonitor) AddAlertCallback(callback AlertCallback) {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	wm.alertCallbacks = append(wm.alertCallbacks, callback)
}

// SetConfiguration updates monitoring configuration
func (wm *WipeMonitor) SetConfiguration(
	checkInterval, gracePeriod, activityTimeout time.Duration,
	maxFailedAuth int,
	testMode, requireConfirmation bool) {

	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	wm.checkInterval = checkInterval
	wm.gracePeriod = gracePeriod
	wm.activityTimeout = activityTimeout
	wm.maxFailedAuth = maxFailedAuth
	wm.testMode = testMode
	wm.requireConfirmation = requireConfirmation
}

// EmergencyDisable disables all wipe operations (emergency stop)
func (wm *WipeMonitor) EmergencyDisable() {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	wm.emergencyDisabled = true
	wm.executor.EmergencyStop()

	wm.sendAlert("emergency_disabled", "Wipe operations emergency disabled", "critical")
}

// GetStatus returns current monitoring status
func (wm *WipeMonitor) GetStatus() (TriggerState, MonitoringStats) {
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()

	var keyAbsentDuration string
	if wm.keyAbsentSince != nil {
		keyAbsentDuration = time.Since(*wm.keyAbsentSince).String()
	}

	state := TriggerState{
		KeyPresent:         wm.keyPresent,
		KeyAbsentDuration:  keyAbsentDuration,
		GracePeriodActive:  wm.gracePeriodEnd != nil && time.Now().Before(*wm.gracePeriodEnd),
		GracePeriodExpired: wm.gracePeriodEnd != nil && time.Now().After(*wm.gracePeriodEnd),
		FailedAuthCount:    wm.failedAuthCount,
		LastActivity:       wm.lastActivityTime,
		NetworkConnected:   wm.checkNetworkConnectivity(),
		BatteryLevel:       wm.getBatteryLevel(),
	}

	return state, wm.monitoringStats
}

// GetTriggerHistory returns recent trigger events
func (wm *WipeMonitor) GetTriggerHistory() []TriggerEvent {
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()

	// Return copy to prevent external modification
	history := make([]TriggerEvent, len(wm.triggerHistory))
	copy(history, wm.triggerHistory)
	return history
}

// Main monitoring loop

func (wm *WipeMonitor) monitoringLoop() {
	ticker := time.NewTicker(wm.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-wm.ctx.Done():
			return
		case <-ticker.C:
			wm.performMonitoringCheck()
		}
	}
}

func (wm *WipeMonitor) performMonitoringCheck() {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	checkStartTime := time.Now()

	// Update stats
	wm.monitoringStats.ChecksPerformed++
	wm.monitoringStats.LastCheckTime = checkStartTime

	// Skip if emergency disabled
	if wm.emergencyDisabled {
		return
	}

	// Get current state
	currentState := wm.getCurrentState()

	// Evaluate all active policies
	activePolicies := wm.policyManager.GetActivePolicies()

	for _, policy := range activePolicies {
		wm.monitoringStats.TriggersEvaluated++

		if wm.shouldTriggerPolicy(&policy, &currentState) {
			wm.triggerPolicy(&policy, &currentState)
		}
	}

	// Calculate average check time
	checkDuration := time.Since(checkStartTime)
	// Update average (simplified calculation)
	wm.monitoringStats.AverageCheckTime = checkDuration.String()
}

func (wm *WipeMonitor) getCurrentState() TriggerState {
	var keyAbsentDuration string
	if wm.keyAbsentSince != nil {
		keyAbsentDuration = time.Since(*wm.keyAbsentSince).String()
	}

	return TriggerState{
		KeyPresent:         wm.keyPresent,
		KeyAbsentDuration:  keyAbsentDuration,
		GracePeriodActive:  wm.gracePeriodEnd != nil && time.Now().Before(*wm.gracePeriodEnd),
		GracePeriodExpired: wm.gracePeriodEnd != nil && time.Now().After(*wm.gracePeriodEnd),
		FailedAuthCount:    wm.failedAuthCount,
		LastActivity:       wm.lastActivityTime,
		NetworkConnected:   wm.checkNetworkConnectivity(),
		BatteryLevel:       wm.getBatteryLevel(),
	}
}

func (wm *WipeMonitor) shouldTriggerPolicy(policy *WipePolicy, state *TriggerState) bool {
	trigger := &policy.Trigger

	// Check key absent duration
	if trigger.KeyAbsentDuration > 0 {
		if state.KeyPresent {
			return false // Key is present
		}

		if wm.keyAbsentSince == nil {
			return false // No absent time recorded
		}

		if time.Since(*wm.keyAbsentSince) < trigger.KeyAbsentDuration {
			return false // Not absent long enough
		}
	}

	// Check grace period expiration
	if trigger.GracePeriodExpired {
		if !state.GracePeriodExpired {
			return false
		}
	}

	// Check failed authentication count
	if trigger.MultipleFailedAuth {
		if state.FailedAuthCount < wm.maxFailedAuth {
			return false
		}
	}

	// Check network loss requirement
	if trigger.RequireNetworkLoss {
		if state.NetworkConnected {
			return false
		}
	}

	// Check user logout requirement
	if trigger.RequireUserLoggedOut {
		// Check if user activity is recent
		if time.Since(state.LastActivity) < wm.activityTimeout {
			return false
		}
	}

	// Check minimum battery level
	if trigger.MinimumBatteryLevel > 0 {
		if state.BatteryLevel < trigger.MinimumBatteryLevel {
			return false // Battery too low for safe operation
		}
	}

	return true
}

func (wm *WipeMonitor) triggerPolicy(policy *WipePolicy, state *TriggerState) {
	eventID := uuid.New().String()

	// Create trigger event record
	event := TriggerEvent{
		EventID:     eventID,
		Timestamp:   time.Now(),
		TriggerType: "policy_triggered",
		PolicyID:    policy.PolicyID,
		Conditions:  *state,
		Action:      policy.Action,
		Result:      "pending",
	}

	// Safety checks before execution
	if wm.testMode || policy.TestMode {
		event.Result = "test_mode_blocked"
		event.PreventedReason = "test mode active, execution blocked for safety"
	} else if policy.DryRun {
		event.Result = "dry_run"
		event.PreventedReason = "dry run mode, simulation only"
	} else if wm.requireConfirmation && !wm.confirmExecution(policy) {
		event.Result = "confirmation_denied"
		event.PreventedReason = "user denied execution confirmation"
	} else {
		// Execute the policy
		wm.sendAlert("policy_triggered",
			fmt.Sprintf("Wipe policy %s triggered, executing %s", policy.Name, policy.Action),
			"critical")

		operation, err := wm.executor.ExecutePolicy(policy)
		if err != nil {
			event.Result = "execution_failed"
			event.Error = err.Error()

			wm.sendAlert("execution_failed",
				fmt.Sprintf("Policy execution failed: %v", err), "error")
		} else {
			event.Result = "executed"
			wm.monitoringStats.OperationsExecuted++

			wm.sendAlert("execution_completed",
				fmt.Sprintf("Policy %s executed successfully, operation ID: %s",
					policy.Name, operation.OperationID), "info")
		}
	}

	// Record the trigger event
	wm.triggerHistory = append(wm.triggerHistory, event)

	// Keep only last 100 events
	if len(wm.triggerHistory) > 100 {
		wm.triggerHistory = wm.triggerHistory[1:]
	}

	wm.monitoringStats.PoliciesTriggered++
}

func (wm *WipeMonitor) confirmExecution(policy *WipePolicy) bool {
	// In a real implementation, this would prompt for user confirmation
	// For safety, default to false (deny execution)

	wm.sendAlert("confirmation_required",
		fmt.Sprintf("Policy %s requires user confirmation before execution", policy.Name),
		"warning")

	// Simulate confirmation denial for safety
	return false
}

func (wm *WipeMonitor) sendAlert(alertType, message, severity string) {
	for _, callback := range wm.alertCallbacks {
		go callback(alertType, message, severity)
	}

	// Also log to console for debugging
	fmt.Printf("[WIPE-MONITOR] %s: %s (%s)\n", alertType, message, severity)
}

// System monitoring helper functions

func (wm *WipeMonitor) checkNetworkConnectivity() bool {
	// Simplified network check
	// In a real implementation, this would check actual network connectivity
	return true
}

func (wm *WipeMonitor) getBatteryLevel() int {
	// Simplified battery check
	// In a real implementation, this would check actual battery level
	return 100
}

// GetSystemHealth returns system health information relevant to wipe decisions
func (wm *WipeMonitor) GetSystemHealth() map[string]interface{} {
	return map[string]interface{}{
		"network_connected":    wm.checkNetworkConnectivity(),
		"battery_level":        wm.getBatteryLevel(),
		"disk_space_available": wm.checkDiskSpace(),
		"memory_available":     wm.checkMemoryUsage(),
		"system_load":          wm.getSystemLoad(),
		"uptime":              wm.getSystemUptime(),
	}
}

func (wm *WipeMonitor) checkDiskSpace() string {
	// Placeholder implementation
	return "sufficient"
}

func (wm *WipeMonitor) checkMemoryUsage() string {
	// Placeholder implementation
	return "normal"
}

func (wm *WipeMonitor) getSystemLoad() float64 {
	// Placeholder implementation
	return 0.5
}

func (wm *WipeMonitor) getSystemUptime() string {
	// Placeholder implementation
	return "12h34m"
}