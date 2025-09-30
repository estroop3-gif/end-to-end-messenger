use std::collections::HashMap;
use std::sync::Arc;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use tokio::sync::RwLock;
use tracing::{info, warn, error};

/// Certificate pinning configuration and validation
#[derive(Debug, Clone)]
pub struct CertificatePinner {
    /// Map of hostname to pinned certificate hashes
    pins: Arc<RwLock<HashMap<String, Vec<PinnedCertificate>>>>,
    /// Whether to enforce pinning (fail on mismatch) or just warn
    enforcement_mode: PinningMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedCertificate {
    /// SHA-256 hash of the certificate's Subject Public Key Info (SPKI)
    pub spki_sha256: String,
    /// Optional description for logging
    pub description: Option<String>,
    /// Expiration time for this pin (Unix timestamp)
    pub expires_at: Option<u64>,
    /// Whether this is a backup pin
    pub is_backup: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PinningMode {
    /// Enforce pinning - fail connections on mismatch
    Enforce,
    /// Report only - log mismatches but allow connections
    ReportOnly,
    /// Disabled - no pinning validation
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinningConfig {
    pub mode: String, // "enforce", "report_only", "disabled"
    pub pins: HashMap<String, Vec<PinnedCertificate>>,
    pub update_url: Option<String>,
    pub backup_pins: HashMap<String, Vec<PinnedCertificate>>,
}

impl CertificatePinner {
    pub fn new(mode: PinningMode) -> Self {
        Self {
            pins: Arc::new(RwLock::new(HashMap::new())),
            enforcement_mode: mode,
        }
    }

    pub async fn load_config(config: PinningConfig) -> Result<Self> {
        let mode = match config.mode.as_str() {
            "enforce" => PinningMode::Enforce,
            "report_only" => PinningMode::ReportOnly,
            "disabled" => PinningMode::Disabled,
            _ => return Err(anyhow!("Invalid pinning mode: {}", config.mode)),
        };

        let pinner = Self::new(mode);

        // Load primary pins
        for (hostname, pins) in config.pins {
            pinner.add_pins(&hostname, pins).await?;
        }

        // Load backup pins
        for (hostname, backup_pins) in config.backup_pins {
            let mut existing_pins = pinner.pins.read().await
                .get(&hostname)
                .cloned()
                .unwrap_or_default();

            for mut pin in backup_pins {
                pin.is_backup = true;
                existing_pins.push(pin);
            }

            pinner.pins.write().await.insert(hostname, existing_pins);
        }

        info!("Certificate pinning loaded with {} hostnames",
              pinner.pins.read().await.len());

        Ok(pinner)
    }

    pub async fn add_pins(&self, hostname: &str, pins: Vec<PinnedCertificate>) -> Result<()> {
        // Validate pins
        for pin in &pins {
            if pin.spki_sha256.len() != 64 {
                return Err(anyhow!("Invalid SPKI SHA-256 hash length for {}: {}",
                                 hostname, pin.spki_sha256));
            }

            // Verify it's valid hex
            if hex::decode(&pin.spki_sha256).is_err() {
                return Err(anyhow!("Invalid SPKI SHA-256 hex for {}: {}",
                                 hostname, pin.spki_sha256));
            }
        }

        self.pins.write().await.insert(hostname.to_string(), pins);
        info!("Added {} certificate pins for {}", pins.len(), hostname);
        Ok(())
    }

    pub async fn validate_certificate_chain(
        &self,
        hostname: &str,
        cert_chain: &[Vec<u8>],
    ) -> Result<ValidationResult> {
        if self.enforcement_mode == PinningMode::Disabled {
            return Ok(ValidationResult::Disabled);
        }

        let pins = match self.pins.read().await.get(hostname) {
            Some(pins) => pins.clone(),
            None => {
                warn!("No certificate pins configured for hostname: {}", hostname);
                return Ok(ValidationResult::NoPinsConfigured);
            }
        };

        // Check if any pins have expired
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let valid_pins: Vec<_> = pins.iter()
            .filter(|pin| {
                pin.expires_at.map_or(true, |expires| expires > current_time)
            })
            .collect();

        if valid_pins.is_empty() {
            warn!("All certificate pins for {} have expired", hostname);
            return Ok(ValidationResult::AllPinsExpired);
        }

        // Validate each certificate in the chain
        for (i, cert_der) in cert_chain.iter().enumerate() {
            if let Ok(spki_hash) = extract_spki_hash(cert_der) {
                // Check if this certificate matches any pin
                for pin in &valid_pins {
                    if pin.spki_sha256.to_lowercase() == spki_hash.to_lowercase() {
                        info!("Certificate pin validated for {} (cert {} in chain, pin: {})",
                              hostname, i, pin.description.as_deref().unwrap_or("unknown"));
                        return Ok(ValidationResult::Valid);
                    }
                }
            }
        }

        // No matching pins found
        let result = ValidationResult::PinMismatch {
            expected_pins: valid_pins.iter().map(|p| p.spki_sha256.clone()).collect(),
            actual_spki_hashes: cert_chain.iter()
                .filter_map(|cert| extract_spki_hash(cert).ok())
                .collect(),
        };

        match self.enforcement_mode {
            PinningMode::Enforce => {
                error!("Certificate pinning validation failed for {}: {:?}", hostname, result);
            }
            PinningMode::ReportOnly => {
                warn!("Certificate pinning mismatch for {} (report-only mode): {:?}",
                      hostname, result);
            }
            PinningMode::Disabled => unreachable!(),
        }

        Ok(result)
    }

    pub fn should_fail_connection(&self, result: &ValidationResult) -> bool {
        match self.enforcement_mode {
            PinningMode::Enforce => matches!(result, ValidationResult::PinMismatch { .. }),
            PinningMode::ReportOnly | PinningMode::Disabled => false,
        }
    }

    pub async fn update_pins_from_url(&self, update_url: &str) -> Result<()> {
        // Fetch updated pins from a secure endpoint
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let response = client.get(update_url).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!("Failed to fetch pin updates: {}", response.status()));
        }

        let config: PinningConfig = response.json().await?;

        // Validate and apply updates
        for (hostname, new_pins) in config.pins {
            self.add_pins(&hostname, new_pins).await?;
        }

        info!("Successfully updated certificate pins from {}", update_url);
        Ok(())
    }

    pub async fn get_pins_for_hostname(&self, hostname: &str) -> Vec<PinnedCertificate> {
        self.pins.read().await
            .get(hostname)
            .cloned()
            .unwrap_or_default()
    }

    pub async fn remove_expired_pins(&self) -> Result<usize> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let mut pins = self.pins.write().await;
        let mut removed_count = 0;

        for (hostname, host_pins) in pins.iter_mut() {
            let original_len = host_pins.len();
            host_pins.retain(|pin| {
                pin.expires_at.map_or(true, |expires| expires > current_time)
            });
            let removed = original_len - host_pins.len();
            if removed > 0 {
                info!("Removed {} expired pins for {}", removed, hostname);
                removed_count += removed;
            }
        }

        // Remove hostnames with no pins left
        pins.retain(|_, host_pins| !host_pins.is_empty());

        Ok(removed_count)
    }
}

#[derive(Debug, Clone)]
pub enum ValidationResult {
    /// Pinning is disabled
    Disabled,
    /// No pins configured for this hostname
    NoPinsConfigured,
    /// All pins for this hostname have expired
    AllPinsExpired,
    /// Certificate chain validated successfully
    Valid,
    /// Pin mismatch detected
    PinMismatch {
        expected_pins: Vec<String>,
        actual_spki_hashes: Vec<String>,
    },
}

/// Extract the SHA-256 hash of the Subject Public Key Info (SPKI) from a DER-encoded certificate
fn extract_spki_hash(cert_der: &[u8]) -> Result<String> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| anyhow!("Failed to parse certificate: {}", e))?;

    // Extract the SubjectPublicKeyInfo
    let spki_der = cert.public_key().raw;

    // Compute SHA-256 hash
    let mut hasher = Sha256::new();
    hasher.update(spki_der);
    let hash = hasher.finalize();

    Ok(hex::encode(hash))
}

/// Generate SPKI hash for a given certificate (utility function)
pub fn generate_spki_hash(cert_pem: &str) -> Result<String> {
    use x509_parser::pem::parse_x509_pem;

    let (_, cert) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| anyhow!("Failed to parse PEM certificate: {}", e))?;

    extract_spki_hash(&cert.contents)
}

/// Default certificate pins for known services
pub fn default_pins() -> HashMap<String, Vec<PinnedCertificate>> {
    let mut pins = HashMap::new();

    // Example pins for common services (these should be updated with real values)
    pins.insert("shuttle.yourdomain.com".to_string(), vec![
        PinnedCertificate {
            spki_sha256: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            description: Some("Primary certificate".to_string()),
            expires_at: Some(1735689600), // 2025-01-01
            is_backup: false,
        },
        PinnedCertificate {
            spki_sha256: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
            description: Some("Backup certificate".to_string()),
            expires_at: Some(1735689600), // 2025-01-01
            is_backup: true,
        },
    ]);

    pins.insert("relay.yourdomain.com".to_string(), vec![
        PinnedCertificate {
            spki_sha256: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".to_string(),
            description: Some("Relay primary certificate".to_string()),
            expires_at: Some(1735689600), // 2025-01-01
            is_backup: false,
        },
    ]);

    pins
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_certificate_pinning() {
        let pinner = CertificatePinner::new(PinningMode::Enforce);

        let pins = vec![
            PinnedCertificate {
                spki_sha256: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
                description: Some("Test pin".to_string()),
                expires_at: None,
                is_backup: false,
            }
        ];

        pinner.add_pins("test.example.com", pins).await.unwrap();

        // Test with no pins configured
        let result = pinner.validate_certificate_chain("unknown.com", &[]).await.unwrap();
        assert!(matches!(result, ValidationResult::NoPinsConfigured));

        // Test with configured pins but no certificates
        let result = pinner.validate_certificate_chain("test.example.com", &[]).await.unwrap();
        assert!(matches!(result, ValidationResult::PinMismatch { .. }));
    }

    #[test]
    fn test_spki_hash_generation() {
        // This would need a real certificate for testing
        // For now, just test that the function exists and handles errors
        let result = generate_spki_hash("invalid pem");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_expired_pin_removal() {
        let pinner = CertificatePinner::new(PinningMode::Enforce);

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let pins = vec![
            PinnedCertificate {
                spki_sha256: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
                description: Some("Expired pin".to_string()),
                expires_at: Some(current_time - 3600), // Expired 1 hour ago
                is_backup: false,
            },
            PinnedCertificate {
                spki_sha256: "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321".to_string(),
                description: Some("Valid pin".to_string()),
                expires_at: Some(current_time + 3600), // Expires in 1 hour
                is_backup: false,
            }
        ];

        pinner.add_pins("test.example.com", pins).await.unwrap();

        let removed = pinner.remove_expired_pins().await.unwrap();
        assert_eq!(removed, 1);

        let remaining_pins = pinner.get_pins_for_hostname("test.example.com").await;
        assert_eq!(remaining_pins.len(), 1);
        assert_eq!(remaining_pins[0].description.as_ref().unwrap(), "Valid pin");
    }
}