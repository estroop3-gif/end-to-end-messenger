// Wipe Policy Engine for Ephemeral Messenger
//
// This module defines and validates wipe policies that control when and what
// data can be wiped when hardware keys are absent.
//
// SECURITY CRITICAL: This code controls destructive operations.
// All policies must be cryptographically signed and validated.
// Multiple authorization layers required for any destructive action.
//
// AUDIT REQUIRED: This module requires security audit before deployment.
package wipe

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// WipePolicyVersion defines the current wipe policy format version
const WipePolicyVersion = 1

// WipeAction defines what type of wipe operation to perform
type WipeAction string

const (
	WipeActionNone        WipeAction = "none"           // No action
	WipeActionAlert       WipeAction = "alert"          // Alert only
	WipeActionLogout      WipeAction = "logout"         // Safe logout
	WipeActionShutdown    WipeAction = "shutdown"       // Graceful shutdown
	WipeActionMemory      WipeAction = "memory"         // Wipe memory only
	WipeActionTempFiles   WipeAction = "temp_files"     // Wipe temporary files
	WipeActionUserData    WipeAction = "user_data"      // Wipe user data
	WipeActionApplication WipeAction = "application"    // Wipe application data
	WipeActionSystem      WipeAction = "system"         // System-level wipe (DANGEROUS)
)

// WipeTrigger defines when a wipe should be triggered
type WipeTrigger struct {
	// Trigger conditions
	KeyAbsentDuration    time.Duration `json:"key_absent_duration"`    // How long key must be absent
	GracePeriodExpired   bool          `json:"grace_period_expired"`   // Grace period has expired
	MultipleFailedAuth   bool          `json:"multiple_failed_auth"`   // Multiple auth failures
	SuspiciousActivity   bool          `json:"suspicious_activity"`    // Suspicious activity detected
	AdminTriggered       bool          `json:"admin_triggered"`        // Manually triggered by admin
	EmergencyShutdown    bool          `json:"emergency_shutdown"`     // Emergency shutdown signal

	// Additional conditions
	RequireNetworkLoss   bool          `json:"require_network_loss"`   // Only if network is lost
	RequireUserLoggedOut bool          `json:"require_user_logged_out"` // Only if user logged out
	MinimumBatteryLevel  int           `json:"minimum_battery_level"`  // Minimum battery % for wipe
}

// WipeTarget defines what data to wipe
type WipeTarget struct {
	// Scope definition
	Path           string   `json:"path"`             // File/directory path
	Pattern        string   `json:"pattern"`          // Glob pattern
	Recursive      bool     `json:"recursive"`        // Recursive deletion
	FileTypes      []string `json:"file_types"`       // Specific file extensions
	MaxFileSize    int64    `json:"max_file_size"`    // Maximum file size to wipe

	// Safety constraints
	RequireConfirm bool     `json:"require_confirm"`  // Require additional confirmation
	BackupFirst    bool     `json:"backup_first"`     // Create backup before wipe
	PreserveOnFail bool     `json:"preserve_on_fail"` // Preserve if wipe fails

	// Exclusions for safety
	ExcludePaths   []string `json:"exclude_paths"`    // Paths to never wipe
	ExcludeSystem  bool     `json:"exclude_system"`   // Never wipe system files
	ExcludeRunning bool     `json:"exclude_running"`  // Never wipe running processes
}

// WipeMethod defines how to perform the wipe
type WipeMethod struct {
	// Wipe technique
	Method         string `json:"method"`           // "secure", "standard", "quick"
	Passes         int    `json:"passes"`           // Number of overwrite passes
	VerifyWipe     bool   `json:"verify_wipe"`      // Verify wipe completion
	ZeroFill       bool   `json:"zero_fill"`        // Fill with zeros
	RandomFill     bool   `json:"random_fill"`      // Fill with random data

	// Logging and audit
	LogOperations  bool   `json:"log_operations"`   // Log all operations
	AuditTrail     bool   `json:"audit_trail"`      // Create audit trail
	NotifyAdmin    bool   `json:"notify_admin"`     // Notify administrators
}

// WipePolicy defines a complete wipe policy
type WipePolicy struct {
	// Metadata
	Version        int       `json:"version"`
	PolicyID       string    `json:"policy_id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	CreatedBy      string    `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`

	// Policy configuration
	Enabled        bool         `json:"enabled"`
	Priority       int          `json:"priority"`        // Higher priority = executed first
	Trigger        WipeTrigger  `json:"trigger"`
	Action         WipeAction   `json:"action"`
	Targets        []WipeTarget `json:"targets"`
	Method         WipeMethod   `json:"method"`

	// Safety mechanisms
	RequiredAuths  []string     `json:"required_auths"`  // Required authorization keys
	SafetyOverride string       `json:"safety_override"` // Emergency override key
	TestMode       bool         `json:"test_mode"`       // Test mode (no actual wipe)
	DryRun         bool         `json:"dry_run"`         // Dry run mode

	// Cryptographic signature
	Signature      string       `json:"signature"`       // Ed25519 signature
}

// PolicyValidationResult contains validation results
type PolicyValidationResult struct {
	Valid           bool     `json:"valid"`
	Errors          []string `json:"errors"`
	Warnings        []string `json:"warnings"`
	SecurityIssues  []string `json:"security_issues"`
	RiskLevel       string   `json:"risk_level"` // "low", "medium", "high", "critical"
}

// WipePolicyManager manages wipe policies
type WipePolicyManager struct {
	policies           []WipePolicy
	authorizedKeys     []ed25519.PublicKey
	emergencyOverride  ed25519.PublicKey
	safetyChecksEnabled bool
}

// NewWipePolicyManager creates a new policy manager
func NewWipePolicyManager() *WipePolicyManager {
	return &WipePolicyManager{
		policies:            make([]WipePolicy, 0),
		authorizedKeys:      make([]ed25519.PublicKey, 0),
		safetyChecksEnabled: true,
	}
}

// AddAuthorizedKey adds an authorized signing key
func (wpm *WipePolicyManager) AddAuthorizedKey(publicKey ed25519.PublicKey) {
	wpm.authorizedKeys = append(wpm.authorizedKeys, publicKey)
}

// SetEmergencyOverride sets the emergency override key
func (wpm *WipePolicyManager) SetEmergencyOverride(publicKey ed25519.PublicKey) {
	wpm.emergencyOverride = publicKey
}

// LoadPolicy loads and validates a wipe policy
func (wpm *WipePolicyManager) LoadPolicy(policyData []byte) error {
	var policy WipePolicy

	if err := json.Unmarshal(policyData, &policy); err != nil {
		return fmt.Errorf("failed to parse policy JSON: %v", err)
	}

	// Validate policy
	validation := wpm.ValidatePolicy(&policy)
	if !validation.Valid {
		return fmt.Errorf("policy validation failed: %v", validation.Errors)
	}

	// Critical policies require additional checks
	if validation.RiskLevel == "critical" || validation.RiskLevel == "high" {
		if !wpm.safetyChecksEnabled {
			return fmt.Errorf("safety checks disabled, cannot load %s risk policy", validation.RiskLevel)
		}

		// Require multiple authorizations for high-risk policies
		if len(policy.RequiredAuths) < 2 {
			return fmt.Errorf("high-risk policies require at least 2 authorization signatures")
		}
	}

	// Verify signature
	if err := wpm.VerifyPolicySignature(&policy); err != nil {
		return fmt.Errorf("policy signature verification failed: %v", err)
	}

	wpm.policies = append(wpm.policies, policy)
	return nil
}

// ValidatePolicy performs comprehensive policy validation
func (wpm *WipePolicyManager) ValidatePolicy(policy *WipePolicy) PolicyValidationResult {
	result := PolicyValidationResult{
		Valid:          true,
		Errors:         make([]string, 0),
		Warnings:       make([]string, 0),
		SecurityIssues: make([]string, 0),
		RiskLevel:      "low",
	}

	// Validate basic structure
	if policy.Version != WipePolicyVersion {
		result.Errors = append(result.Errors, fmt.Sprintf("unsupported policy version: %d", policy.Version))
		result.Valid = false
	}

	if policy.PolicyID == "" {
		result.Errors = append(result.Errors, "policy ID is required")
		result.Valid = false
	}

	if _, err := uuid.Parse(policy.PolicyID); err != nil {
		result.Errors = append(result.Errors, "policy ID must be a valid UUID")
		result.Valid = false
	}

	if policy.ExpiresAt.Before(time.Now()) {
		result.Errors = append(result.Errors, "policy has expired")
		result.Valid = false
	}

	// Validate action safety
	riskLevel := wpm.assessActionRisk(policy.Action)
	if riskLevel > result.RiskLevel {
		result.RiskLevel = riskLevel
	}

	// Validate targets for safety
	for _, target := range policy.Targets {
		targetRisk := wpm.assessTargetRisk(&target)
		if targetRisk == "critical" {
			result.SecurityIssues = append(result.SecurityIssues,
				fmt.Sprintf("target %s poses critical risk", target.Path))
			result.RiskLevel = "critical"
		}

		// Check for dangerous paths
		if wpm.isDangerousPath(target.Path) {
			result.SecurityIssues = append(result.SecurityIssues,
				fmt.Sprintf("target path %s is potentially dangerous", target.Path))
		}
	}

	// Validate authorization requirements
	if result.RiskLevel == "high" || result.RiskLevel == "critical" {
		if len(policy.RequiredAuths) == 0 {
			result.Errors = append(result.Errors, "high-risk policies require authorization signatures")
			result.Valid = false
		}
	}

	// Validate trigger conditions
	if policy.Trigger.KeyAbsentDuration > 24*time.Hour {
		result.Warnings = append(result.Warnings, "very long key absent duration may cause unintended wipes")
	}

	// Safety mechanism checks
	if !policy.TestMode && !policy.DryRun && result.RiskLevel == "critical" {
		result.SecurityIssues = append(result.SecurityIssues,
			"critical wipe policy without test mode is extremely dangerous")
	}

	return result
}

// VerifyPolicySignature verifies the cryptographic signature on a policy
func (wpm *WipePolicyManager) VerifyPolicySignature(policy *WipePolicy) error {
	if policy.Signature == "" {
		return fmt.Errorf("policy signature is missing")
	}

	// Decode signature
	signatureBytes, err := base64.StdEncoding.DecodeString(policy.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %v", err)
	}

	// Create signing data (excludes signature field)
	signingData, err := wpm.createPolicySigningData(policy)
	if err != nil {
		return fmt.Errorf("failed to create signing data: %v", err)
	}

	// Check against all authorized keys
	for _, pubKey := range wpm.authorizedKeys {
		if ed25519.Verify(pubKey, signingData, signatureBytes) {
			return nil // Valid signature found
		}
	}

	// Check emergency override key
	if wpm.emergencyOverride != nil {
		if ed25519.Verify(wpm.emergencyOverride, signingData, signatureBytes) {
			return nil // Emergency override valid
		}
	}

	return fmt.Errorf("signature verification failed - no valid signature found")
}

// SignPolicy signs a wipe policy with the given private key
func (wpm *WipePolicyManager) SignPolicy(policy *WipePolicy, privateKey ed25519.PrivateKey) error {
	// Create signing data
	signingData, err := wpm.createPolicySigningData(policy)
	if err != nil {
		return fmt.Errorf("failed to create signing data: %v", err)
	}

	// Sign the data
	signature := ed25519.Sign(privateKey, signingData)
	policy.Signature = base64.StdEncoding.EncodeToString(signature)

	return nil
}

// GetActivePolicies returns policies that should be evaluated
func (wpm *WipePolicyManager) GetActivePolicies() []WipePolicy {
	active := make([]WipePolicy, 0)

	now := time.Now()
	for _, policy := range wpm.policies {
		if policy.Enabled && policy.ExpiresAt.After(now) {
			active = append(active, policy)
		}
	}

	return active
}

// Helper functions

func (wpm *WipePolicyManager) assessActionRisk(action WipeAction) string {
	switch action {
	case WipeActionNone, WipeActionAlert:
		return "low"
	case WipeActionLogout, WipeActionShutdown:
		return "low"
	case WipeActionMemory, WipeActionTempFiles:
		return "medium"
	case WipeActionUserData, WipeActionApplication:
		return "high"
	case WipeActionSystem:
		return "critical"
	default:
		return "medium"
	}
}

func (wpm *WipePolicyManager) assessTargetRisk(target *WipeTarget) string {
	// System paths are always critical
	systemPaths := []string{"/", "/usr", "/bin", "/sbin", "/lib", "/etc", "/boot", "/sys", "/proc"}
	for _, sysPath := range systemPaths {
		if target.Path == sysPath || (target.Recursive && target.Path == sysPath) {
			return "critical"
		}
	}

	// Home directory recursive wipe is high risk
	if target.Recursive && (target.Path == "/home" || target.Path == "/Users") {
		return "high"
	}

	// Large scope wipes are high risk
	if target.Recursive && len(target.Path) <= 3 {
		return "high"
	}

	return "medium"
}

func (wpm *WipePolicyManager) isDangerousPath(path string) bool {
	dangerousPaths := []string{
		"/", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/boot",
		"/sys", "/proc", "/dev", "/var/lib", "/var/log", "/opt",
		"C:\\", "C:\\Windows", "C:\\Program Files", "C:\\Users",
	}

	for _, dangerous := range dangerousPaths {
		if path == dangerous {
			return true
		}
	}

	return false
}

func (wpm *WipePolicyManager) createPolicySigningData(policy *WipePolicy) ([]byte, error) {
	// Create signing structure (excludes signature field)
	signingStruct := struct {
		Version        int          `json:"version"`
		PolicyID       string       `json:"policy_id"`
		Name           string       `json:"name"`
		Description    string       `json:"description"`
		CreatedBy      string       `json:"created_by"`
		CreatedAt      time.Time    `json:"created_at"`
		ExpiresAt      time.Time    `json:"expires_at"`
		Enabled        bool         `json:"enabled"`
		Priority       int          `json:"priority"`
		Trigger        WipeTrigger  `json:"trigger"`
		Action         WipeAction   `json:"action"`
		Targets        []WipeTarget `json:"targets"`
		Method         WipeMethod   `json:"method"`
		RequiredAuths  []string     `json:"required_auths"`
		SafetyOverride string       `json:"safety_override"`
		TestMode       bool         `json:"test_mode"`
		DryRun         bool         `json:"dry_run"`
	}{
		Version:        policy.Version,
		PolicyID:       policy.PolicyID,
		Name:           policy.Name,
		Description:    policy.Description,
		CreatedBy:      policy.CreatedBy,
		CreatedAt:      policy.CreatedAt,
		ExpiresAt:      policy.ExpiresAt,
		Enabled:        policy.Enabled,
		Priority:       policy.Priority,
		Trigger:        policy.Trigger,
		Action:         policy.Action,
		Targets:        policy.Targets,
		Method:         policy.Method,
		RequiredAuths:  policy.RequiredAuths,
		SafetyOverride: policy.SafetyOverride,
		TestMode:       policy.TestMode,
		DryRun:         policy.DryRun,
	}

	return json.Marshal(signingStruct)
}

// CreateSamplePolicy creates a safe sample policy for demonstration
func CreateSamplePolicy() *WipePolicy {
	return &WipePolicy{
		Version:     WipePolicyVersion,
		PolicyID:    uuid.New().String(),
		Name:        "Sample Safe Policy",
		Description: "Example policy that only logs alerts",
		CreatedBy:   "ephemeral-messenger-system",
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(30 * 24 * time.Hour), // 30 days
		Enabled:     true,
		Priority:    1,
		Trigger: WipeTrigger{
			KeyAbsentDuration: 10 * time.Minute,
			GracePeriodExpired: true,
		},
		Action: WipeActionAlert, // Safe action
		Targets: []WipeTarget{}, // No targets
		Method: WipeMethod{
			LogOperations: true,
			AuditTrail:    true,
			NotifyAdmin:   true,
		},
		TestMode: true, // Safe test mode
		DryRun:   true, // Safe dry run
	}
}