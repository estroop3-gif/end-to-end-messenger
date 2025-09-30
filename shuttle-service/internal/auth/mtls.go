package auth

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// MTLSConfig contains mutual TLS authentication configuration
type MTLSConfig struct {
	// Enabled indicates whether mTLS is enabled
	Enabled bool `json:"enabled"`

	// RequireClientCert requires all clients to present valid certificates
	RequireClientCert bool `json:"require_client_cert"`

	// TrustedCAs contains paths to trusted CA certificate files
	TrustedCAs []string `json:"trusted_cas"`

	// AllowedClientCerts contains fingerprints of allowed client certificates
	AllowedClientCerts []string `json:"allowed_client_certs"`

	// CRLDistributionPoints contains URLs for certificate revocation lists
	CRLDistributionPoints []string `json:"crl_distribution_points"`

	// OCSPEnabled enables Online Certificate Status Protocol checking
	OCSPEnabled bool `json:"ocsp_enabled"`

	// CertificateBinding binds client identities to certificate subjects
	CertificateBinding map[string]ClientIdentity `json:"certificate_binding"`

	// CacheTimeout for certificate validation results
	CacheTimeout time.Duration `json:"cache_timeout"`
}

// ClientIdentity represents a client authenticated via certificate
type ClientIdentity struct {
	// ClientID is the unique identifier for this client
	ClientID string `json:"client_id"`

	// Subject contains the certificate subject information
	Subject pkix.Name `json:"subject"`

	// Fingerprint is the SHA-256 fingerprint of the certificate
	Fingerprint string `json:"fingerprint"`

	// Permissions granted to this client
	Permissions []string `json:"permissions"`

	// RateLimit specific to this client (requests per minute)
	RateLimit int `json:"rate_limit"`

	// ExpiresAt contains the certificate expiration time
	ExpiresAt time.Time `json:"expires_at"`

	// IsRevoked indicates if the certificate has been revoked
	IsRevoked bool `json:"is_revoked"`
}

// MTLSAuthenticator handles mutual TLS authentication
type MTLSAuthenticator struct {
	config     MTLSConfig
	logger     *zap.Logger
	trustedCAs *x509.CertPool
	cache      *validationCache
	mu         sync.RWMutex
}

type validationCache struct {
	entries map[string]*cacheEntry
	mu      sync.RWMutex
}

type cacheEntry struct {
	identity  *ClientIdentity
	valid     bool
	expiresAt time.Time
}

// ValidationResult represents the result of certificate validation
type ValidationResult struct {
	Valid        bool
	ClientID     string
	Identity     *ClientIdentity
	ErrorMessage string
	ErrorCode    string
}

// NewMTLSAuthenticator creates a new mutual TLS authenticator
func NewMTLSAuthenticator(config MTLSConfig, logger *zap.Logger) (*MTLSAuthenticator, error) {
	auth := &MTLSAuthenticator{
		config: config,
		logger: logger,
		cache: &validationCache{
			entries: make(map[string]*cacheEntry),
		},
	}

	if config.Enabled {
		if err := auth.loadTrustedCAs(); err != nil {
			return nil, fmt.Errorf("failed to load trusted CAs: %w", err)
		}

		logger.Info("Mutual TLS authentication enabled",
			zap.Int("trusted_cas", len(config.TrustedCAs)),
			zap.Int("allowed_certs", len(config.AllowedClientCerts)),
			zap.Bool("require_client_cert", config.RequireClientCert))
	}

	return auth, nil
}

// ValidateRequest validates an HTTP request with mTLS
func (m *MTLSAuthenticator) ValidateRequest(r *http.Request) ValidationResult {
	if !m.config.Enabled {
		return ValidationResult{Valid: true, ClientID: "anonymous"}
	}

	// Check if client certificate is present
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		if m.config.RequireClientCert {
			return ValidationResult{
				Valid:        false,
				ErrorCode:    "NO_CLIENT_CERT",
				ErrorMessage: "Client certificate required but not provided",
			}
		}
		return ValidationResult{Valid: true, ClientID: "anonymous"}
	}

	clientCert := r.TLS.PeerCertificates[0]
	fingerprint := calculateFingerprint(clientCert)

	// Check cache first
	if cached := m.getCachedValidation(fingerprint); cached != nil {
		if cached.valid {
			return ValidationResult{
				Valid:    true,
				ClientID: cached.identity.ClientID,
				Identity: cached.identity,
			}
		}
		return ValidationResult{
			Valid:        false,
			ErrorCode:    "CACHED_INVALID",
			ErrorMessage: "Certificate validation failed (cached result)",
		}
	}

	// Validate certificate chain
	if err := m.validateCertificateChain(r.TLS.PeerCertificates); err != nil {
		m.cacheValidation(fingerprint, nil, false)
		return ValidationResult{
			Valid:        false,
			ErrorCode:    "CERT_CHAIN_INVALID",
			ErrorMessage: fmt.Sprintf("Certificate chain validation failed: %v", err),
		}
	}

	// Check if certificate is explicitly allowed
	identity, err := m.getClientIdentity(clientCert, fingerprint)
	if err != nil {
		m.cacheValidation(fingerprint, nil, false)
		return ValidationResult{
			Valid:        false,
			ErrorCode:    "CERT_NOT_ALLOWED",
			ErrorMessage: fmt.Sprintf("Certificate not in allowed list: %v", err),
		}
	}

	// Check certificate revocation
	if m.config.OCSPEnabled {
		if revoked, err := m.checkRevocation(clientCert); err != nil {
			m.logger.Warn("OCSP check failed", zap.Error(err))
		} else if revoked {
			identity.IsRevoked = true
			m.cacheValidation(fingerprint, identity, false)
			return ValidationResult{
				Valid:        false,
				ErrorCode:    "CERT_REVOKED",
				ErrorMessage: "Certificate has been revoked",
			}
		}
	}

	// Check certificate expiration
	if time.Now().After(clientCert.NotAfter) {
		m.cacheValidation(fingerprint, identity, false)
		return ValidationResult{
			Valid:        false,
			ErrorCode:    "CERT_EXPIRED",
			ErrorMessage: "Certificate has expired",
		}
	}

	// Check certificate not yet valid
	if time.Now().Before(clientCert.NotBefore) {
		m.cacheValidation(fingerprint, identity, false)
		return ValidationResult{
			Valid:        false,
			ErrorCode:    "CERT_NOT_YET_VALID",
			ErrorMessage: "Certificate is not yet valid",
		}
	}

	// Cache successful validation
	m.cacheValidation(fingerprint, identity, true)

	m.logger.Debug("Client certificate validated",
		zap.String("client_id", identity.ClientID),
		zap.String("subject", identity.Subject.String()),
		zap.String("fingerprint", fingerprint))

	return ValidationResult{
		Valid:    true,
		ClientID: identity.ClientID,
		Identity: identity,
	}
}

// loadTrustedCAs loads trusted CA certificates
func (m *MTLSAuthenticator) loadTrustedCAs() error {
	m.trustedCAs = x509.NewCertPool()

	for _, caPath := range m.config.TrustedCAs {
		caCert, err := loadCertificateFromFile(caPath)
		if err != nil {
			return fmt.Errorf("failed to load CA certificate from %s: %w", caPath, err)
		}
		m.trustedCAs.AddCert(caCert)
	}

	return nil
}

// validateCertificateChain validates the client certificate chain
func (m *MTLSAuthenticator) validateCertificateChain(certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return fmt.Errorf("no certificates provided")
	}

	clientCert := certs[0]
	intermediates := x509.NewCertPool()

	// Add intermediate certificates to pool
	for i := 1; i < len(certs); i++ {
		intermediates.AddCert(certs[i])
	}

	// Verify certificate chain
	opts := x509.VerifyOptions{
		Roots:         m.trustedCAs,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	_, err := clientCert.Verify(opts)
	return err
}

// getClientIdentity retrieves client identity based on certificate
func (m *MTLSAuthenticator) getClientIdentity(cert *x509.Certificate, fingerprint string) (*ClientIdentity, error) {
	// Check if certificate fingerprint is in allowed list
	allowed := false
	for _, allowedFingerprint := range m.config.AllowedClientCerts {
		if strings.EqualFold(fingerprint, allowedFingerprint) {
			allowed = true
			break
		}
	}

	if !allowed {
		return nil, fmt.Errorf("certificate fingerprint not in allowed list")
	}

	// Check for explicit binding
	subjectKey := cert.Subject.String()
	if identity, exists := m.config.CertificateBinding[subjectKey]; exists {
		identity.Fingerprint = fingerprint
		identity.ExpiresAt = cert.NotAfter
		return &identity, nil
	}

	// Create default identity based on certificate subject
	clientID := generateClientIDFromSubject(cert.Subject)

	identity := &ClientIdentity{
		ClientID:    clientID,
		Subject:     cert.Subject,
		Fingerprint: fingerprint,
		Permissions: []string{"basic"}, // Default permissions
		RateLimit:   100,               // Default rate limit
		ExpiresAt:   cert.NotAfter,
		IsRevoked:   false,
	}

	return identity, nil
}

// checkRevocation checks if a certificate has been revoked
func (m *MTLSAuthenticator) checkRevocation(cert *x509.Certificate) (bool, error) {
	// OCSP check implementation would go here
	// For now, just return false (not revoked)
	// In a real implementation, you would:
	// 1. Extract OCSP responder URL from certificate
	// 2. Build OCSP request
	// 3. Send request to OCSP responder
	// 4. Parse and validate response

	return false, nil
}

// getCachedValidation retrieves cached validation result
func (m *MTLSAuthenticator) getCachedValidation(fingerprint string) *cacheEntry {
	m.cache.mu.RLock()
	defer m.cache.mu.RUnlock()

	entry, exists := m.cache.entries[fingerprint]
	if !exists {
		return nil
	}

	// Check if cache entry has expired
	if time.Now().After(entry.expiresAt) {
		// Remove expired entry
		delete(m.cache.entries, fingerprint)
		return nil
	}

	return entry
}

// cacheValidation caches validation result
func (m *MTLSAuthenticator) cacheValidation(fingerprint string, identity *ClientIdentity, valid bool) {
	m.cache.mu.Lock()
	defer m.cache.mu.Unlock()

	expiresAt := time.Now().Add(m.config.CacheTimeout)
	if m.config.CacheTimeout == 0 {
		expiresAt = time.Now().Add(5 * time.Minute) // Default 5 minutes
	}

	m.cache.entries[fingerprint] = &cacheEntry{
		identity:  identity,
		valid:     valid,
		expiresAt: expiresAt,
	}
}

// ClearCache clears the validation cache
func (m *MTLSAuthenticator) ClearCache() {
	m.cache.mu.Lock()
	defer m.cache.mu.Unlock()
	m.cache.entries = make(map[string]*cacheEntry)
	m.logger.Info("mTLS validation cache cleared")
}

// GetCacheStats returns cache statistics
func (m *MTLSAuthenticator) GetCacheStats() map[string]interface{} {
	m.cache.mu.RLock()
	defer m.cache.mu.RUnlock()

	validEntries := 0
	expiredEntries := 0
	now := time.Now()

	for _, entry := range m.cache.entries {
		if now.After(entry.expiresAt) {
			expiredEntries++
		} else if entry.valid {
			validEntries++
		}
	}

	return map[string]interface{}{
		"total_entries":   len(m.cache.entries),
		"valid_entries":   validEntries,
		"expired_entries": expiredEntries,
		"cache_timeout":   m.config.CacheTimeout.String(),
	}
}

// UpdateConfig updates the mTLS configuration
func (m *MTLSAuthenticator) UpdateConfig(config MTLSConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	oldConfig := m.config
	m.config = config

	// Reload trusted CAs if they changed
	if config.Enabled && !equalStringSlices(oldConfig.TrustedCAs, config.TrustedCAs) {
		if err := m.loadTrustedCAs(); err != nil {
			m.config = oldConfig // Rollback on error
			return fmt.Errorf("failed to reload trusted CAs: %w", err)
		}
	}

	// Clear cache on configuration change
	m.ClearCache()

	m.logger.Info("mTLS configuration updated",
		zap.Bool("enabled", config.Enabled),
		zap.Bool("require_client_cert", config.RequireClientCert))

	return nil
}

// Utility functions

func calculateFingerprint(cert *x509.Certificate) string {
	h := sha256.New()
	h.Write(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

func loadCertificateFromFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	return x509.ParseCertificate(block.Bytes)
}

func generateClientIDFromSubject(subject pkix.Name) string {
	// Generate a client ID based on certificate subject
	// This is a simple implementation; you might want more sophisticated logic
	if subject.CommonName != "" {
		return subject.CommonName
	}

	if len(subject.Organization) > 0 {
		return subject.Organization[0]
	}

	// Fallback to serialized subject
	h := sha256.New()
	h.Write([]byte(subject.String()))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// Required imports that should be added to the top of the file
import (
	"crypto/sha256"
	"crypto/x509/pem"
	"encoding/hex"
	"os"
)