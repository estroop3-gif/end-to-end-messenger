// Admin Authorization System for Ephemeral Messenger
//
// This module implements a multi-signature authorization system for
// high-risk operations including wipe policies and system configuration.
//
// SECURITY CRITICAL: This code controls access to destructive operations.
// All authorizations must be cryptographically verifiable and auditable.
//
// AUDIT REQUIRED: This module requires security audit before deployment.
package auth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// AdminAuthorizationLevel defines different authorization levels
type AdminAuthorizationLevel string

const (
	AuthLevelNone      AdminAuthorizationLevel = "none"      // No special authorization
	AuthLevelBasic     AdminAuthorizationLevel = "basic"     // Single admin signature
	AuthLevelElevated  AdminAuthorizationLevel = "elevated"  // Multiple admin signatures
	AuthLevelCritical  AdminAuthorizationLevel = "critical"  // Quorum + time delay
	AuthLevelEmergency AdminAuthorizationLevel = "emergency" // Emergency procedures
)

// OperationType defines the type of operation being authorized
type OperationType string

const (
	OpTypeWipePolicy     OperationType = "wipe_policy"
	OpTypeSystemConfig   OperationType = "system_config"
	OpTypeUserManagement OperationType = "user_management"
	OpTypeKeyManagement  OperationType = "key_management"
	OpTypeEmergencyStop  OperationType = "emergency_stop"
	OpTypeSystemWipe     OperationType = "system_wipe"
	OpTypeRecovery       OperationType = "recovery"
)

// AdminRole defines different administrative roles
type AdminRole string

const (
	RoleSystemAdmin    AdminRole = "system_admin"     // Full system access
	RoleSecurityAdmin  AdminRole = "security_admin"   // Security operations
	RoleOperationsAdmin AdminRole = "operations_admin" // Operations management
	RoleAuditAdmin     AdminRole = "audit_admin"      // Audit and monitoring
	RoleEmergencyAdmin AdminRole = "emergency_admin"  // Emergency procedures
)

// AdminIdentity represents an authorized administrator
type AdminIdentity struct {
	AdminID      string             `json:"admin_id"`
	Name         string             `json:"name"`
	Email        string             `json:"email"`
	Role         AdminRole          `json:"role"`
	PublicKey    ed25519.PublicKey  `json:"public_key"`
	CreatedAt    time.Time          `json:"created_at"`
	LastActive   time.Time          `json:"last_active"`
	Status       string             `json:"status"` // "active", "suspended", "revoked"
	Capabilities []string           `json:"capabilities"`
}

// AuthorizationRequest represents a request for administrative authorization
type AuthorizationRequest struct {
	RequestID       string                  `json:"request_id"`
	Operation       OperationType           `json:"operation"`
	RequiredLevel   AdminAuthorizationLevel `json:"required_level"`
	Description     string                  `json:"description"`
	RequestedBy     string                  `json:"requested_by"`
	RequestedAt     time.Time               `json:"requested_at"`
	ExpiresAt       time.Time               `json:"expires_at"`
	Payload         map[string]interface{}  `json:"payload"`
	RequiredRoles   []AdminRole             `json:"required_roles"`
	MinimumSigners  int                     `json:"minimum_signers"`
	TimeDelay       time.Duration           `json:"time_delay"`
	Status          string                  `json:"status"` // "pending", "approved", "denied", "expired"
	Signatures      []AdminSignature        `json:"signatures"`
	ApprovedAt      *time.Time              `json:"approved_at,omitempty"`
	DeniedAt        *time.Time              `json:"denied_at,omitempty"`
}

// AdminSignature represents a cryptographic signature from an administrator
type AdminSignature struct {
	SignerID    string    `json:"signer_id"`
	SignerRole  AdminRole `json:"signer_role"`
	SignedAt    time.Time `json:"signed_at"`
	Signature   string    `json:"signature"`   // Base64 encoded Ed25519 signature
	Decision    string    `json:"decision"`    // "approve" or "deny"
	Comments    string    `json:"comments"`    // Optional comments
	IPAddress   string    `json:"ip_address"`  // Audit trail
	UserAgent   string    `json:"user_agent"`  // Audit trail
}

// AuthorizationPolicy defines authorization requirements for operations
type AuthorizationPolicy struct {
	PolicyID        string                  `json:"policy_id"`
	Operation       OperationType           `json:"operation"`
	RequiredLevel   AdminAuthorizationLevel `json:"required_level"`
	RequiredRoles   []AdminRole             `json:"required_roles"`
	MinimumSigners  int                     `json:"minimum_signers"`
	TimeDelay       time.Duration           `json:"time_delay"`
	ExpirationTime  time.Duration           `json:"expiration_time"`
	AllowEmergency  bool                    `json:"allow_emergency"`
	AuditRequired   bool                    `json:"audit_required"`
	Description     string                  `json:"description"`
}

// AdminAuthorizationManager manages administrative authorizations
type AdminAuthorizationManager struct {
	// Core data
	admins            map[string]*AdminIdentity
	requests          map[string]*AuthorizationRequest
	policies          map[OperationType]*AuthorizationPolicy
	emergencyOverride *AdminIdentity

	// Configuration
	defaultExpiration time.Duration
	auditLog          []AuthorizationAuditEntry
	sessionManager    *AdminSessionManager

	// Synchronization
	mutex sync.RWMutex
}

// AuthorizationAuditEntry records authorization events for audit
type AuthorizationAuditEntry struct {
	Timestamp   time.Time     `json:"timestamp"`
	RequestID   string        `json:"request_id"`
	AdminID     string        `json:"admin_id"`
	Operation   OperationType `json:"operation"`
	Action      string        `json:"action"`
	Result      string        `json:"result"`
	IPAddress   string        `json:"ip_address"`
	UserAgent   string        `json:"user_agent"`
	Details     map[string]interface{} `json:"details"`
}

// AdminSession represents an active admin session
type AdminSession struct {
	SessionID    string    `json:"session_id"`
	AdminID      string    `json:"admin_id"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	IPAddress    string    `json:"ip_address"`
	UserAgent    string    `json:"user_agent"`
	LastActivity time.Time `json:"last_activity"`
	Status       string    `json:"status"` // "active", "expired", "terminated"
}

// AdminSessionManager manages admin sessions
type AdminSessionManager struct {
	sessions       map[string]*AdminSession
	sessionTimeout time.Duration
	mutex          sync.RWMutex
}

// NewAdminAuthorizationManager creates a new authorization manager
func NewAdminAuthorizationManager() *AdminAuthorizationManager {
	return &AdminAuthorizationManager{
		admins:            make(map[string]*AdminIdentity),
		requests:          make(map[string]*AuthorizationRequest),
		policies:          make(map[OperationType]*AuthorizationPolicy),
		defaultExpiration: 24 * time.Hour,
		auditLog:         make([]AuthorizationAuditEntry, 0),
		sessionManager:   NewAdminSessionManager(),
	}
}

// NewAdminSessionManager creates a new session manager
func NewAdminSessionManager() *AdminSessionManager {
	return &AdminSessionManager{
		sessions:       make(map[string]*AdminSession),
		sessionTimeout: 8 * time.Hour, // 8 hour sessions
	}
}

// Initialize sets up the authorization manager with default policies
func (aam *AdminAuthorizationManager) Initialize() error {
	aam.mutex.Lock()
	defer aam.mutex.Unlock()

	// Create default authorization policies
	aam.createDefaultPolicies()

	// Log initialization
	aam.auditLog = append(aam.auditLog, AuthorizationAuditEntry{
		Timestamp: time.Now(),
		RequestID: "system-init",
		AdminID:   "system",
		Operation: OpTypeSystemConfig,
		Action:    "initialize",
		Result:    "success",
		Details:   map[string]interface{}{"policies_created": len(aam.policies)},
	})

	return nil
}

// AddAdmin adds a new administrator to the system
func (aam *AdminAuthorizationManager) AddAdmin(admin *AdminIdentity) error {
	aam.mutex.Lock()
	defer aam.mutex.Unlock()

	// Validate admin identity
	if err := aam.validateAdminIdentity(admin); err != nil {
		return fmt.Errorf("admin validation failed: %v", err)
	}

	// Check for duplicate ID
	if _, exists := aam.admins[admin.AdminID]; exists {
		return fmt.Errorf("admin with ID %s already exists", admin.AdminID)
	}

	// Set status and timestamps
	admin.Status = "active"
	admin.CreatedAt = time.Now()
	admin.LastActive = time.Now()

	// Store admin
	aam.admins[admin.AdminID] = admin

	// Log addition
	aam.auditLog = append(aam.auditLog, AuthorizationAuditEntry{
		Timestamp: time.Now(),
		RequestID: uuid.New().String(),
		AdminID:   "system",
		Operation: OpTypeUserManagement,
		Action:    "add_admin",
		Result:    "success",
		Details: map[string]interface{}{
			"new_admin_id":   admin.AdminID,
			"new_admin_role": admin.Role,
		},
	})

	return nil
}

// CreateAuthorizationRequest creates a new authorization request
func (aam *AdminAuthorizationManager) CreateAuthorizationRequest(
	operation OperationType,
	description string,
	requestedBy string,
	payload map[string]interface{}) (*AuthorizationRequest, error) {

	aam.mutex.Lock()
	defer aam.mutex.Unlock()

	// Get policy for operation
	policy, exists := aam.policies[operation]
	if !exists {
		return nil, fmt.Errorf("no authorization policy found for operation %s", operation)
	}

	// Create request
	request := &AuthorizationRequest{
		RequestID:       uuid.New().String(),
		Operation:       operation,
		RequiredLevel:   policy.RequiredLevel,
		Description:     description,
		RequestedBy:     requestedBy,
		RequestedAt:     time.Now(),
		ExpiresAt:       time.Now().Add(policy.ExpirationTime),
		Payload:         payload,
		RequiredRoles:   policy.RequiredRoles,
		MinimumSigners:  policy.MinimumSigners,
		TimeDelay:       policy.TimeDelay,
		Status:          "pending",
		Signatures:      make([]AdminSignature, 0),
	}

	// Store request
	aam.requests[request.RequestID] = request

	// Log request creation
	aam.auditLog = append(aam.auditLog, AuthorizationAuditEntry{
		Timestamp: time.Now(),
		RequestID: request.RequestID,
		AdminID:   requestedBy,
		Operation: operation,
		Action:    "create_request",
		Result:    "success",
		Details: map[string]interface{}{
			"required_level":  policy.RequiredLevel,
			"minimum_signers": policy.MinimumSigners,
		},
	})

	return request, nil
}

// SignAuthorizationRequest signs an authorization request
func (aam *AdminAuthorizationManager) SignAuthorizationRequest(
	requestID string,
	signerID string,
	decision string,
	comments string,
	signature string,
	ipAddress string,
	userAgent string) error {

	aam.mutex.Lock()
	defer aam.mutex.Unlock()

	// Get request
	request, exists := aam.requests[requestID]
	if !exists {
		return fmt.Errorf("authorization request %s not found", requestID)
	}

	// Check request status
	if request.Status != "pending" {
		return fmt.Errorf("request %s is not pending", requestID)
	}

	// Check expiration
	if time.Now().After(request.ExpiresAt) {
		request.Status = "expired"
		return fmt.Errorf("request %s has expired", requestID)
	}

	// Get admin
	admin, exists := aam.admins[signerID]
	if !exists {
		return fmt.Errorf("admin %s not found", signerID)
	}

	// Check admin status
	if admin.Status != "active" {
		return fmt.Errorf("admin %s is not active", signerID)
	}

	// Check if admin already signed
	for _, sig := range request.Signatures {
		if sig.SignerID == signerID {
			return fmt.Errorf("admin %s has already signed this request", signerID)
		}
	}

	// Verify signature
	if err := aam.verifyRequestSignature(request, admin.PublicKey, signature, decision); err != nil {
		return fmt.Errorf("signature verification failed: %v", err)
	}

	// Check role authorization
	if !aam.hasRequiredRole(admin.Role, request.RequiredRoles) {
		return fmt.Errorf("admin role %s not authorized for this operation", admin.Role)
	}

	// Add signature
	adminSig := AdminSignature{
		SignerID:   signerID,
		SignerRole: admin.Role,
		SignedAt:   time.Now(),
		Signature:  signature,
		Decision:   decision,
		Comments:   comments,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
	}

	request.Signatures = append(request.Signatures, adminSig)

	// Update admin last active time
	admin.LastActive = time.Now()

	// Check if request is now approved or denied
	aam.evaluateRequestStatus(request)

	// Log signature
	aam.auditLog = append(aam.auditLog, AuthorizationAuditEntry{
		Timestamp: time.Now(),
		RequestID: requestID,
		AdminID:   signerID,
		Operation: request.Operation,
		Action:    "sign_request",
		Result:    decision,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Details: map[string]interface{}{
			"decision": decision,
			"comments": comments,
		},
	})

	return nil
}

// IsAuthorized checks if a request has sufficient authorization
func (aam *AdminAuthorizationManager) IsAuthorized(requestID string) (bool, error) {
	aam.mutex.RLock()
	defer aam.mutex.RUnlock()

	request, exists := aam.requests[requestID]
	if !exists {
		return false, fmt.Errorf("request %s not found", requestID)
	}

	// Check if approved
	if request.Status == "approved" {
		// Check time delay if required
		if request.TimeDelay > 0 && request.ApprovedAt != nil {
			if time.Since(*request.ApprovedAt) < request.TimeDelay {
				return false, fmt.Errorf("time delay not met, %v remaining",
					request.TimeDelay-time.Since(*request.ApprovedAt))
			}
		}
		return true, nil
	}

	return false, fmt.Errorf("request not authorized, status: %s", request.Status)
}

// CreateEmergencyAuthorization creates an emergency authorization bypass
func (aam *AdminAuthorizationManager) CreateEmergencyAuthorization(
	operation OperationType,
	adminID string,
	justification string,
	signature string) (*AuthorizationRequest, error) {

	aam.mutex.Lock()
	defer aam.mutex.Unlock()

	// Check if emergency override is configured
	if aam.emergencyOverride == nil {
		return nil, fmt.Errorf("emergency override not configured")
	}

	// Verify emergency admin
	admin, exists := aam.admins[adminID]
	if !exists {
		return nil, fmt.Errorf("admin %s not found", adminID)
	}

	if admin.Role != RoleEmergencyAdmin {
		return nil, fmt.Errorf("admin %s does not have emergency authorization role", adminID)
	}

	// Verify emergency signature
	emergencyData := fmt.Sprintf("EMERGENCY:%s:%s:%s:%d",
		operation, adminID, justification, time.Now().Unix())

	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %v", err)
	}

	if !ed25519.Verify(admin.PublicKey, []byte(emergencyData), signatureBytes) {
		return nil, fmt.Errorf("emergency signature verification failed")
	}

	// Create emergency request
	request := &AuthorizationRequest{
		RequestID:     uuid.New().String(),
		Operation:     operation,
		RequiredLevel: AuthLevelEmergency,
		Description:   fmt.Sprintf("EMERGENCY: %s", justification),
		RequestedBy:   adminID,
		RequestedAt:   time.Now(),
		ExpiresAt:     time.Now().Add(1 * time.Hour), // 1 hour emergency window
		Status:        "approved", // Auto-approved
		Signatures: []AdminSignature{{
			SignerID:   adminID,
			SignerRole: admin.Role,
			SignedAt:   time.Now(),
			Signature:  signature,
			Decision:   "approve",
			Comments:   fmt.Sprintf("EMERGENCY AUTHORIZATION: %s", justification),
		}},
	}

	now := time.Now()
	request.ApprovedAt = &now

	// Store request
	aam.requests[request.RequestID] = request

	// Log emergency authorization
	aam.auditLog = append(aam.auditLog, AuthorizationAuditEntry{
		Timestamp: time.Now(),
		RequestID: request.RequestID,
		AdminID:   adminID,
		Operation: operation,
		Action:    "emergency_authorization",
		Result:    "approved",
		Details: map[string]interface{}{
			"justification": justification,
			"emergency":     true,
		},
	})

	return request, nil
}

// Helper functions

func (aam *AdminAuthorizationManager) createDefaultPolicies() {
	// Wipe policy authorization (critical level)
	aam.policies[OpTypeWipePolicy] = &AuthorizationPolicy{
		PolicyID:       uuid.New().String(),
		Operation:      OpTypeWipePolicy,
		RequiredLevel:  AuthLevelCritical,
		RequiredRoles:  []AdminRole{RoleSystemAdmin, RoleSecurityAdmin},
		MinimumSigners: 2,
		TimeDelay:      1 * time.Hour, // 1 hour cooling off period
		ExpirationTime: 24 * time.Hour,
		AllowEmergency: true,
		AuditRequired:  true,
		Description:    "Authorization required for wipe policy creation/modification",
	}

	// System configuration (elevated level)
	aam.policies[OpTypeSystemConfig] = &AuthorizationPolicy{
		PolicyID:       uuid.New().String(),
		Operation:      OpTypeSystemConfig,
		RequiredLevel:  AuthLevelElevated,
		RequiredRoles:  []AdminRole{RoleSystemAdmin},
		MinimumSigners: 1,
		TimeDelay:      0,
		ExpirationTime: 8 * time.Hour,
		AllowEmergency: true,
		AuditRequired:  true,
		Description:    "Authorization required for system configuration changes",
	}

	// Emergency stop (basic level)
	aam.policies[OpTypeEmergencyStop] = &AuthorizationPolicy{
		PolicyID:       uuid.New().String(),
		Operation:      OpTypeEmergencyStop,
		RequiredLevel:  AuthLevelBasic,
		RequiredRoles:  []AdminRole{RoleSystemAdmin, RoleSecurityAdmin, RoleEmergencyAdmin},
		MinimumSigners: 1,
		TimeDelay:      0,
		ExpirationTime: 1 * time.Hour,
		AllowEmergency: true,
		AuditRequired:  true,
		Description:    "Authorization for emergency stop operations",
	}

	// System wipe (critical level - highest security)
	aam.policies[OpTypeSystemWipe] = &AuthorizationPolicy{
		PolicyID:       uuid.New().String(),
		Operation:      OpTypeSystemWipe,
		RequiredLevel:  AuthLevelCritical,
		RequiredRoles:  []AdminRole{RoleSystemAdmin, RoleSecurityAdmin},
		MinimumSigners: 3, // Require 3 admins
		TimeDelay:      24 * time.Hour, // 24 hour delay
		ExpirationTime: 48 * time.Hour,
		AllowEmergency: false, // No emergency bypass for system wipe
		AuditRequired:  true,
		Description:    "Authorization required for system-wide wipe operations",
	}
}

func (aam *AdminAuthorizationManager) validateAdminIdentity(admin *AdminIdentity) error {
	if admin.AdminID == "" {
		return fmt.Errorf("admin ID is required")
	}

	if _, err := uuid.Parse(admin.AdminID); err != nil {
		return fmt.Errorf("admin ID must be a valid UUID")
	}

	if admin.Name == "" {
		return fmt.Errorf("admin name is required")
	}

	if admin.Email == "" {
		return fmt.Errorf("admin email is required")
	}

	if len(admin.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size")
	}

	validRoles := []AdminRole{
		RoleSystemAdmin, RoleSecurityAdmin, RoleOperationsAdmin,
		RoleAuditAdmin, RoleEmergencyAdmin,
	}

	found := false
	for _, validRole := range validRoles {
		if admin.Role == validRole {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("invalid admin role: %s", admin.Role)
	}

	return nil
}

func (aam *AdminAuthorizationManager) verifyRequestSignature(
	request *AuthorizationRequest,
	publicKey ed25519.PublicKey,
	signature string,
	decision string) error {

	// Create signing data
	signingData := fmt.Sprintf("%s:%s:%s:%s:%d",
		request.RequestID,
		request.Operation,
		request.Description,
		decision,
		request.RequestedAt.Unix())

	// Decode signature
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %v", err)
	}

	// Verify signature
	if !ed25519.Verify(publicKey, []byte(signingData), signatureBytes) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

func (aam *AdminAuthorizationManager) hasRequiredRole(adminRole AdminRole, requiredRoles []AdminRole) bool {
	for _, required := range requiredRoles {
		if adminRole == required {
			return true
		}
	}
	return false
}

func (aam *AdminAuthorizationManager) evaluateRequestStatus(request *AuthorizationRequest) {
	approvals := 0
	denials := 0

	for _, sig := range request.Signatures {
		switch sig.Decision {
		case "approve":
			approvals++
		case "deny":
			denials++
		}
	}

	// Check for denials (any denial blocks approval)
	if denials > 0 {
		request.Status = "denied"
		now := time.Now()
		request.DeniedAt = &now
		return
	}

	// Check for sufficient approvals
	if approvals >= request.MinimumSigners {
		request.Status = "approved"
		now := time.Now()
		request.ApprovedAt = &now
	}
}

// Getter functions

func (aam *AdminAuthorizationManager) GetRequest(requestID string) (*AuthorizationRequest, error) {
	aam.mutex.RLock()
	defer aam.mutex.RUnlock()

	request, exists := aam.requests[requestID]
	if !exists {
		return nil, fmt.Errorf("request %s not found", requestID)
	}

	return request, nil
}

func (aam *AdminAuthorizationManager) GetAuditLog() []AuthorizationAuditEntry {
	aam.mutex.RLock()
	defer aam.mutex.RUnlock()

	// Return copy to prevent external modification
	log := make([]AuthorizationAuditEntry, len(aam.auditLog))
	copy(log, aam.auditLog)
	return log
}

func (aam *AdminAuthorizationManager) GetAdmins() []*AdminIdentity {
	aam.mutex.RLock()
	defer aam.mutex.RUnlock()

	admins := make([]*AdminIdentity, 0, len(aam.admins))
	for _, admin := range aam.admins {
		admins = append(admins, admin)
	}
	return admins
}

func (aam *AdminAuthorizationManager) GetPendingRequests() []*AuthorizationRequest {
	aam.mutex.RLock()
	defer aam.mutex.RUnlock()

	pending := make([]*AuthorizationRequest, 0)
	for _, request := range aam.requests {
		if request.Status == "pending" {
			pending = append(pending, request)
		}
	}
	return pending
}