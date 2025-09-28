// Package keyfile provides secure keyfile format handling for Ephemeral Messenger
//
// This module defines the standard keyfile format and provides validation,
// parsing, and signature verification functions.
//
// SECURITY NOTE: This module is read-only and performs no destructive operations.
package keyfile

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// KeyFileVersion defines the current keyfile format version
const KeyFileVersion = 1

// KeyFile represents the structure of a hardware keyfile
// This format is cryptographically signed and tamper-evident
type KeyFile struct {
	// Version of the keyfile format
	Version int `json:"version"`

	// Unique identifier for the user
	UserID string `json:"user_id"`

	// Base64-encoded Ed25519 public key for identity and signatures
	PubIdentityEd string `json:"pub_identity_ed25519"`

	// Base64-encoded X25519 public key for key exchange
	PubX25519 string `json:"pub_x25519"`

	// Age public key for age encryption compatibility
	PubAge string `json:"pub_age"`

	// Optional device identifier for device binding
	DeviceID string `json:"device_id,omitempty"`

	// Keyfile creation timestamp
	CreatedAt time.Time `json:"created_at"`

	// Keyfile expiration timestamp
	ExpiresAt time.Time `json:"expires_at"`

	// Ed25519 signature over canonical JSON (excluding this field)
	Signature string `json:"signature"`
}

// ValidatedKeyFile represents a keyfile that has passed all validation checks
type ValidatedKeyFile struct {
	KeyFile

	// Additional validation metadata
	ValidatedAt     time.Time `json:"validated_at"`
	ValidatedBy     string    `json:"validated_by"`
	Fingerprint     string    `json:"fingerprint"`
	SignatureValid  bool      `json:"signature_valid"`
	NotExpired      bool      `json:"not_expired"`
	StructureValid  bool      `json:"structure_valid"`
}

// KeyFileError represents errors that can occur during keyfile operations
type KeyFileError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Field   string `json:"field,omitempty"`
}

func (e *KeyFileError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("keyfile error [%s]: %s (field: %s)", e.Code, e.Message, e.Field)
	}
	return fmt.Sprintf("keyfile error [%s]: %s", e.Code, e.Message)
}

// ParseKeyFile parses a JSON keyfile from bytes
func ParseKeyFile(data []byte) (*KeyFile, error) {
	var keyFile KeyFile

	if err := json.Unmarshal(data, &keyFile); err != nil {
		return nil, &KeyFileError{
			Code:    "PARSE_ERROR",
			Message: fmt.Sprintf("failed to parse JSON: %v", err),
		}
	}

	return &keyFile, nil
}

// ValidateStructure performs basic structural validation of a keyfile
func (kf *KeyFile) ValidateStructure() error {
	// Check version
	if kf.Version != KeyFileVersion {
		return &KeyFileError{
			Code:    "INVALID_VERSION",
			Message: fmt.Sprintf("unsupported keyfile version: %d (expected: %d)", kf.Version, KeyFileVersion),
			Field:   "version",
		}
	}

	// Validate user ID format (should be valid UUID)
	if _, err := uuid.Parse(kf.UserID); err != nil {
		return &KeyFileError{
			Code:    "INVALID_USER_ID",
			Message: "user_id must be a valid UUID",
			Field:   "user_id",
		}
	}

	// Check required fields
	if kf.PubIdentityEd == "" {
		return &KeyFileError{
			Code:    "MISSING_FIELD",
			Message: "pub_identity_ed25519 is required",
			Field:   "pub_identity_ed25519",
		}
	}

	if kf.PubX25519 == "" {
		return &KeyFileError{
			Code:    "MISSING_FIELD",
			Message: "pub_x25519 is required",
			Field:   "pub_x25519",
		}
	}

	if kf.Signature == "" {
		return &KeyFileError{
			Code:    "MISSING_FIELD",
			Message: "signature is required",
			Field:   "signature",
		}
	}

	// Validate timestamps
	if kf.CreatedAt.IsZero() {
		return &KeyFileError{
			Code:    "INVALID_TIMESTAMP",
			Message: "created_at must be a valid timestamp",
			Field:   "created_at",
		}
	}

	if kf.ExpiresAt.IsZero() {
		return &KeyFileError{
			Code:    "INVALID_TIMESTAMP",
			Message: "expires_at must be a valid timestamp",
			Field:   "expires_at",
		}
	}

	if kf.ExpiresAt.Before(kf.CreatedAt) {
		return &KeyFileError{
			Code:    "INVALID_TIMESTAMP",
			Message: "expires_at must be after created_at",
			Field:   "expires_at",
		}
	}

	// Validate base64 encoded fields
	if err := validateBase64Field(kf.PubIdentityEd, "pub_identity_ed25519", 32); err != nil {
		return err
	}

	if err := validateBase64Field(kf.PubX25519, "pub_x25519", 32); err != nil {
		return err
	}

	if err := validateBase64Field(kf.Signature, "signature", 64); err != nil {
		return err
	}

	return nil
}

// ValidateExpiration checks if the keyfile has expired
func (kf *KeyFile) ValidateExpiration() error {
	now := time.Now()

	if now.After(kf.ExpiresAt) {
		return &KeyFileError{
			Code:    "EXPIRED",
			Message: fmt.Sprintf("keyfile expired at %v (current time: %v)", kf.ExpiresAt, now),
			Field:   "expires_at",
		}
	}

	// Optional: warn if expiring soon (within 7 days)
	if now.Add(7 * 24 * time.Hour).After(kf.ExpiresAt) {
		// This is a warning, not an error - log it but don't fail validation
		fmt.Printf("WARNING: Keyfile expires soon at %v\n", kf.ExpiresAt)
	}

	return nil
}

// ValidateSignature verifies the Ed25519 signature on the keyfile
func (kf *KeyFile) ValidateSignature() error {
	// Decode the Ed25519 public key
	pubKeyBytes, err := base64.StdEncoding.DecodeString(kf.PubIdentityEd)
	if err != nil {
		return &KeyFileError{
			Code:    "INVALID_PUBLIC_KEY",
			Message: fmt.Sprintf("failed to decode public key: %v", err),
			Field:   "pub_identity_ed25519",
		}
	}

	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return &KeyFileError{
			Code:    "INVALID_PUBLIC_KEY",
			Message: fmt.Sprintf("invalid public key size: %d (expected: %d)", len(pubKeyBytes), ed25519.PublicKeySize),
			Field:   "pub_identity_ed25519",
		}
	}

	publicKey := ed25519.PublicKey(pubKeyBytes)

	// Decode the signature
	signatureBytes, err := base64.StdEncoding.DecodeString(kf.Signature)
	if err != nil {
		return &KeyFileError{
			Code:    "INVALID_SIGNATURE",
			Message: fmt.Sprintf("failed to decode signature: %v", err),
			Field:   "signature",
		}
	}

	if len(signatureBytes) != ed25519.SignatureSize {
		return &KeyFileError{
			Code:    "INVALID_SIGNATURE",
			Message: fmt.Sprintf("invalid signature size: %d (expected: %d)", len(signatureBytes), ed25519.SignatureSize),
			Field:   "signature",
		}
	}

	// Create canonical signing data (excludes signature field)
	signingData, err := kf.createSigningData()
	if err != nil {
		return &KeyFileError{
			Code:    "SIGNING_DATA_ERROR",
			Message: fmt.Sprintf("failed to create signing data: %v", err),
		}
	}

	// Verify the signature
	if !ed25519.Verify(publicKey, signingData, signatureBytes) {
		return &KeyFileError{
			Code:    "SIGNATURE_VERIFICATION_FAILED",
			Message: "Ed25519 signature verification failed",
			Field:   "signature",
		}
	}

	return nil
}

// FullValidation performs complete validation of a keyfile
func (kf *KeyFile) FullValidation() (*ValidatedKeyFile, error) {
	validated := &ValidatedKeyFile{
		KeyFile:     *kf,
		ValidatedAt: time.Now(),
		ValidatedBy: "ephemeral-messenger-keydetect",
	}

	// Structural validation
	if err := kf.ValidateStructure(); err != nil {
		validated.StructureValid = false
		return validated, err
	}
	validated.StructureValid = true

	// Expiration validation
	if err := kf.ValidateExpiration(); err != nil {
		validated.NotExpired = false
		return validated, err
	}
	validated.NotExpired = true

	// Signature validation
	if err := kf.ValidateSignature(); err != nil {
		validated.SignatureValid = false
		return validated, err
	}
	validated.SignatureValid = true

	// Generate fingerprint
	validated.Fingerprint = kf.GenerateFingerprint()

	return validated, nil
}

// GenerateFingerprint creates a human-readable fingerprint for the keyfile
func (kf *KeyFile) GenerateFingerprint() string {
	// Create fingerprint from user ID and public key
	hash := sha256.New()
	hash.Write([]byte(kf.UserID))
	hash.Write([]byte(kf.PubIdentityEd))

	hashBytes := hash.Sum(nil)

	// Format as hex string with colons
	fingerprint := fmt.Sprintf("%x", hashBytes[:16]) // First 16 bytes (128 bits)

	// Add colons every 4 characters for readability
	formatted := ""
	for i, r := range fingerprint {
		if i > 0 && i%4 == 0 {
			formatted += ":"
		}
		formatted += string(r)
	}

	return formatted
}

// GetIdentityPublicKey returns the Ed25519 public key as bytes
func (kf *KeyFile) GetIdentityPublicKey() (ed25519.PublicKey, error) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(kf.PubIdentityEd)
	if err != nil {
		return nil, err
	}

	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size")
	}

	return ed25519.PublicKey(pubKeyBytes), nil
}

// GetX25519PublicKey returns the X25519 public key as bytes
func (kf *KeyFile) GetX25519PublicKey() ([]byte, error) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(kf.PubX25519)
	if err != nil {
		return nil, err
	}

	if len(pubKeyBytes) != 32 { // X25519 key size
		return nil, fmt.Errorf("invalid X25519 key size")
	}

	return pubKeyBytes, nil
}

// IsExpired returns true if the keyfile has expired
func (kf *KeyFile) IsExpired() bool {
	return time.Now().After(kf.ExpiresAt)
}

// TimeUntilExpiration returns the duration until expiration
func (kf *KeyFile) TimeUntilExpiration() time.Duration {
	if kf.IsExpired() {
		return 0
	}
	return time.Until(kf.ExpiresAt)
}

// createSigningData creates the canonical JSON for signature verification
func (kf *KeyFile) createSigningData() ([]byte, error) {
	// Create signing structure (excludes signature field)
	signingStruct := struct {
		Version       int       `json:"version"`
		UserID        string    `json:"user_id"`
		PubIdentityEd string    `json:"pub_identity_ed25519"`
		PubX25519     string    `json:"pub_x25519"`
		PubAge        string    `json:"pub_age"`
		DeviceID      string    `json:"device_id,omitempty"`
		CreatedAt     time.Time `json:"created_at"`
		ExpiresAt     time.Time `json:"expires_at"`
	}{
		Version:       kf.Version,
		UserID:        kf.UserID,
		PubIdentityEd: kf.PubIdentityEd,
		PubX25519:     kf.PubX25519,
		PubAge:        kf.PubAge,
		DeviceID:      kf.DeviceID,
		CreatedAt:     kf.CreatedAt,
		ExpiresAt:     kf.ExpiresAt,
	}

	// Marshal to canonical JSON
	return json.Marshal(signingStruct)
}

// validateBase64Field validates that a field contains valid base64 data of expected length
func validateBase64Field(value, fieldName string, expectedLength int) error {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return &KeyFileError{
			Code:    "INVALID_BASE64",
			Message: fmt.Sprintf("invalid base64 encoding: %v", err),
			Field:   fieldName,
		}
	}

	if len(decoded) != expectedLength {
		return &KeyFileError{
			Code:    "INVALID_LENGTH",
			Message: fmt.Sprintf("invalid length: %d (expected: %d)", len(decoded), expectedLength),
			Field:   fieldName,
		}
	}

	return nil
}

// ToJSON marshals the keyfile to JSON with proper formatting
func (kf *KeyFile) ToJSON() ([]byte, error) {
	return json.MarshalIndent(kf, "", "  ")
}

// Summary returns a human-readable summary of the keyfile
func (kf *KeyFile) Summary() string {
	status := "valid"
	if kf.IsExpired() {
		status = "EXPIRED"
	}

	return fmt.Sprintf("KeyFile{UserID: %s, Fingerprint: %s, Status: %s, ExpiresAt: %v}",
		kf.UserID,
		kf.GenerateFingerprint(),
		status,
		kf.ExpiresAt)
}