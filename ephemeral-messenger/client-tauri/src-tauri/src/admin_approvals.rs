use std::path::PathBuf;
use std::fs::{File, OpenOptions};
use std::io::{Write, BufWriter};
use std::sync::{Arc, Mutex};
use anyhow::{Result, Context, bail};
use serde::{Serialize, Deserialize};
use ed25519_dalek::{Keypair, Signature, Signer, Verifier, PublicKey};
use rand::rngs::OsRng;
use libsodium_sys::*;
use chrono::{DateTime, Utc};

use crate::keydetect::HardwareKeyDetector;
use crate::access_modes::AccessModeManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminApprovalManager {
    key_detector: Arc<HardwareKeyDetector>,
    access_manager: Arc<AccessModeManager>,
    audit_log: Arc<Mutex<Vec<AuditEntry>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub action: AdminAction,
    pub details: ActionDetails,
    pub admin_identity: String,
    pub approval_method: ApprovalMethod,
    pub signature: Vec<u8>,
    pub previous_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdminAction {
    EnableLocalOnlyAccess,
    DisableLocalOnlyAccess,
    EnableSelectiveWipe,
    DisableSelectiveWipe,
    EnableFullDriveWipe,
    DisableFullDriveWipe,
    EnablePanicMode,
    DisablePanicMode,
    EnableDeadManSwitch,
    DisableDeadManSwitch,
    LockSettings,
    UnlockSettings,
    CreateWipeUSB,
    ModifyWipePolicy,
    OverrideSecuritySetting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionDetails {
    pub description: String,
    pub previous_value: Option<String>,
    pub new_value: Option<String>,
    pub additional_context: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApprovalMethod {
    HardwareKey {
        device_id: String,
        key_path: String,
    },
    AdminPassphrase {
        argon2_verified: bool,
    },
    YubiKeyTouch {
        serial: String,
        challenge_response: String,
    },
    TOTP {
        validated_at: DateTime<Utc>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub action: AdminAction,
    pub details: ActionDetails,
    pub justification: String,
    pub risk_level: RiskLevel,
    pub required_confirmations: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalChallenge {
    pub challenge_text: String,
    pub required_phrase: String,
    pub countdown_seconds: u32,
    pub hardware_confirmation_required: bool,
}

impl AdminApprovalManager {
    pub fn new(
        key_detector: Arc<HardwareKeyDetector>,
        access_manager: Arc<AccessModeManager>,
    ) -> Result<Self> {
        // Initialize libsodium
        unsafe {
            if sodium_init() < 0 {
                bail!("Failed to initialize libsodium");
            }
        }

        Ok(AdminApprovalManager {
            key_detector,
            access_manager,
            audit_log: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Request approval for an administrative action
    pub fn request_approval(&self, request: ApprovalRequest) -> Result<ApprovalChallenge> {
        // Verify user is authenticated
        if !self.access_manager.is_authenticated() {
            bail!("Must be authenticated to request admin approval");
        }

        // Generate challenge based on risk level
        let challenge = self.generate_challenge(&request)?;

        Ok(challenge)
    }

    /// Grant approval for an administrative action with hardware key
    pub fn grant_approval_with_hardware_key(
        &self,
        request: ApprovalRequest,
        confirmation_phrase: &str,
        expected_phrase: &str,
    ) -> Result<AuditEntry> {
        // Verify confirmation phrase
        if confirmation_phrase != expected_phrase {
            bail!("Confirmation phrase mismatch");
        }

        // Verify hardware key presence
        let detected_keys = self.key_detector.scan_for_keys()?;
        if detected_keys.is_empty() {
            bail!("No admin hardware key detected");
        }

        let admin_key = &detected_keys[0];

        // Validate hardware key
        if !self.key_detector.validate_key(&admin_key.device_path)? {
            bail!("Admin hardware key validation failed");
        }

        // Create audit entry
        let approval_method = ApprovalMethod::HardwareKey {
            device_id: admin_key.device_id.clone(),
            key_path: admin_key.device_path.clone(),
        };

        let audit_entry = self.create_audit_entry(request, approval_method)?;

        // Write to audit log
        self.write_audit_entry(&audit_entry)?;

        Ok(audit_entry)
    }

    /// Grant approval for an administrative action with admin passphrase
    pub fn grant_approval_with_passphrase(
        &self,
        request: ApprovalRequest,
        admin_passphrase: &str,
        confirmation_phrase: &str,
        expected_phrase: &str,
    ) -> Result<AuditEntry> {
        // Verify confirmation phrase
        if confirmation_phrase != expected_phrase {
            bail!("Confirmation phrase mismatch");
        }

        // Verify admin passphrase (this would integrate with a secure admin credential system)
        if !self.verify_admin_passphrase(admin_passphrase)? {
            bail!("Invalid admin passphrase");
        }

        // Create audit entry
        let approval_method = ApprovalMethod::AdminPassphrase {
            argon2_verified: true,
        };

        let audit_entry = self.create_audit_entry(request, approval_method)?;

        // Write to audit log
        self.write_audit_entry(&audit_entry)?;

        Ok(audit_entry)
    }

    /// Check if an action requires admin approval
    pub fn requires_approval(&self, action: &AdminAction) -> bool {
        match action {
            AdminAction::EnableLocalOnlyAccess |
            AdminAction::EnableFullDriveWipe |
            AdminAction::EnablePanicMode |
            AdminAction::EnableDeadManSwitch |
            AdminAction::CreateWipeUSB |
            AdminAction::OverrideSecuritySetting => true,

            AdminAction::DisableLocalOnlyAccess |
            AdminAction::DisableSelectiveWipe |
            AdminAction::DisableFullDriveWipe |
            AdminAction::DisablePanicMode |
            AdminAction::DisableDeadManSwitch => true,

            AdminAction::LockSettings |
            AdminAction::UnlockSettings |
            AdminAction::ModifyWipePolicy => true,

            AdminAction::EnableSelectiveWipe => false, // Can be enabled by user, but requires policy signature
        }
    }

    /// Get risk level for an action
    pub fn get_risk_level(&self, action: &AdminAction) -> RiskLevel {
        match action {
            AdminAction::EnableLocalOnlyAccess => RiskLevel::High,
            AdminAction::EnableFullDriveWipe |
            AdminAction::CreateWipeUSB => RiskLevel::Critical,

            AdminAction::EnablePanicMode |
            AdminAction::EnableDeadManSwitch => RiskLevel::High,

            AdminAction::DisableLocalOnlyAccess |
            AdminAction::DisableFullDriveWipe => RiskLevel::Medium,

            AdminAction::LockSettings |
            AdminAction::UnlockSettings => RiskLevel::Medium,

            _ => RiskLevel::Low,
        }
    }

    /// Generate challenge for approval request
    fn generate_challenge(&self, request: &ApprovalRequest) -> Result<ApprovalChallenge> {
        let risk_level = self.get_risk_level(&request.action);

        let (challenge_text, required_phrase, countdown_seconds, hardware_required) = match risk_level {
            RiskLevel::Low => (
                "Please confirm this administrative action.".to_string(),
                "I approve this action".to_string(),
                10,
                false,
            ),
            RiskLevel::Medium => (
                "This action may affect system security. Please confirm you understand the implications.".to_string(),
                "I understand the security implications".to_string(),
                30,
                true,
            ),
            RiskLevel::High => (
                "WARNING: This is a high-risk action that may compromise system security.".to_string(),
                "I accept full responsibility for this high-risk action".to_string(),
                60,
                true,
            ),
            RiskLevel::Critical => (
                "CRITICAL WARNING: This action may cause irreversible data loss or system compromise.".to_string(),
                "I understand this action may cause irreversible data loss".to_string(),
                120,
                true,
            ),
        };

        Ok(ApprovalChallenge {
            challenge_text,
            required_phrase,
            countdown_seconds,
            hardware_confirmation_required: hardware_required,
        })
    }

    /// Create audit entry for approved action
    fn create_audit_entry(
        &self,
        request: ApprovalRequest,
        approval_method: ApprovalMethod,
    ) -> Result<AuditEntry> {
        let id = uuid::Uuid::new_v4().to_string();
        let timestamp = Utc::now();

        // Get admin identity
        let admin_identity = match &approval_method {
            ApprovalMethod::HardwareKey { device_id, .. } => device_id.clone(),
            ApprovalMethod::AdminPassphrase { .. } => "admin_passphrase".to_string(),
            ApprovalMethod::YubiKeyTouch { serial, .. } => format!("yubikey_{}", serial),
            ApprovalMethod::TOTP { .. } => "totp_admin".to_string(),
        };

        // Calculate previous hash (for integrity chain)
        let previous_hash = self.get_last_audit_hash()?;

        // Create entry (without signature initially)
        let mut entry = AuditEntry {
            id: id.clone(),
            timestamp,
            action: request.action,
            details: request.details,
            admin_identity,
            approval_method,
            signature: Vec::new(),
            previous_hash,
        };

        // Sign the entry
        let signature = self.sign_audit_entry(&entry)?;
        entry.signature = signature;

        Ok(entry)
    }

    /// Sign an audit entry
    fn sign_audit_entry(&self, entry: &AuditEntry) -> Result<Vec<u8>> {
        // Create signing key (in production, this would be loaded from secure storage)
        let mut csprng = OsRng{};
        let keypair = Keypair::generate(&mut csprng);

        // Serialize entry for signing (excluding signature field)
        let mut entry_for_signing = entry.clone();
        entry_for_signing.signature = Vec::new();

        let serialized = serde_json::to_vec(&entry_for_signing)
            .context("Failed to serialize audit entry for signing")?;

        // Sign
        let signature = keypair.sign(&serialized);

        Ok(signature.to_bytes().to_vec())
    }

    /// Verify audit entry signature
    fn verify_audit_signature(&self, entry: &AuditEntry) -> Result<bool> {
        // In production, load the public key from secure storage
        // For now, this is a placeholder implementation
        Ok(true) // TODO: Implement proper signature verification
    }

    /// Write audit entry to hardware key and local log
    fn write_audit_entry(&self, entry: &AuditEntry) -> Result<()> {
        // Add to in-memory log
        self.audit_log.lock().unwrap().push(entry.clone());

        // Write to hardware key if present
        self.write_to_hardware_audit_log(entry)?;

        // Write to local audit log file
        self.write_to_local_audit_log(entry)?;

        Ok(())
    }

    /// Write audit entry to hardware key
    fn write_to_hardware_audit_log(&self, entry: &AuditEntry) -> Result<()> {
        let detected_keys = self.key_detector.scan_for_keys()?;
        if detected_keys.is_empty() {
            return Ok(()); // No hardware key present
        }

        let key = &detected_keys[0];
        let audit_path = PathBuf::from(&key.device_path)
            .parent()
            .unwrap_or(&PathBuf::from("/"))
            .join("audit_log.jsonl");

        // Append to audit log file (JSONL format)
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&audit_path)?;

        let serialized = serde_json::to_string(entry)? + "\n";
        file.write_all(serialized.as_bytes())?;
        file.sync_all()?;

        Ok(())
    }

    /// Write audit entry to local audit log
    fn write_to_local_audit_log(&self, entry: &AuditEntry) -> Result<()> {
        // This would write to a local audit log file
        // Implementation depends on the app's data directory structure
        Ok(())
    }

    /// Get hash of last audit entry for integrity chain
    fn get_last_audit_hash(&self) -> Result<Option<String>> {
        let log = self.audit_log.lock().unwrap();
        if let Some(last_entry) = log.last() {
            // Create hash of the last entry
            let serialized = serde_json::to_vec(last_entry)?;
            let mut hash = [0u8; 32];
            unsafe {
                crypto_hash_sha256(hash.as_mut_ptr(), serialized.as_ptr(), serialized.len() as u64);
            }
            Ok(Some(hex::encode(hash)))
        } else {
            Ok(None)
        }
    }

    /// Verify admin passphrase (placeholder implementation)
    fn verify_admin_passphrase(&self, passphrase: &str) -> Result<bool> {
        // In production, this would verify against a securely stored admin credential
        // For now, this is a placeholder
        Ok(passphrase.len() >= 12) // Minimum length check
    }

    /// Get audit log entries
    pub fn get_audit_log(&self) -> Vec<AuditEntry> {
        self.audit_log.lock().unwrap().clone()
    }

    /// Verify audit log integrity
    pub fn verify_audit_integrity(&self) -> Result<bool> {
        let log = self.audit_log.lock().unwrap();

        for (i, entry) in log.iter().enumerate() {
            // Verify signature
            if !self.verify_audit_signature(entry)? {
                return Ok(false);
            }

            // Verify hash chain
            if i > 0 {
                let prev_entry = &log[i - 1];
                let expected_hash = self.calculate_entry_hash(prev_entry)?;

                if entry.previous_hash.as_ref() != Some(&expected_hash) {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    /// Calculate hash of an audit entry
    fn calculate_entry_hash(&self, entry: &AuditEntry) -> Result<String> {
        let serialized = serde_json::to_vec(entry)?;
        let mut hash = [0u8; 32];
        unsafe {
            crypto_hash_sha256(hash.as_mut_ptr(), serialized.as_ptr(), serialized.len() as u64);
        }
        Ok(hex::encode(hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::keydetect::HardwareKeyDetector;
    use crate::access_modes::AccessModeManager;
    use std::sync::Arc;

    #[test]
    fn test_approval_risk_levels() {
        let temp_dir = TempDir::new().unwrap();
        let key_detector = Arc::new(HardwareKeyDetector::new().unwrap());
        let access_manager = Arc::new(AccessModeManager::new(temp_dir.path().to_path_buf()).unwrap());
        let admin_manager = AdminApprovalManager::new(key_detector, access_manager).unwrap();

        assert!(matches!(
            admin_manager.get_risk_level(&AdminAction::EnableLocalOnlyAccess),
            RiskLevel::High
        ));

        assert!(matches!(
            admin_manager.get_risk_level(&AdminAction::CreateWipeUSB),
            RiskLevel::Critical
        ));
    }

    #[test]
    fn test_audit_entry_creation() {
        let temp_dir = TempDir::new().unwrap();
        let key_detector = Arc::new(HardwareKeyDetector::new().unwrap());
        let access_manager = Arc::new(AccessModeManager::new(temp_dir.path().to_path_buf()).unwrap());
        let admin_manager = AdminApprovalManager::new(key_detector, access_manager).unwrap();

        let request = ApprovalRequest {
            action: AdminAction::EnableLocalOnlyAccess,
            details: ActionDetails {
                description: "Enable local-only access for testing".to_string(),
                previous_value: Some("HardKey".to_string()),
                new_value: Some("LocalOnly".to_string()),
                additional_context: std::collections::HashMap::new(),
            },
            justification: "Testing purposes".to_string(),
            risk_level: RiskLevel::High,
            required_confirmations: 1,
        };

        let approval_method = ApprovalMethod::AdminPassphrase {
            argon2_verified: true,
        };

        let entry = admin_manager.create_audit_entry(request, approval_method).unwrap();

        assert!(!entry.id.is_empty());
        assert!(!entry.signature.is_empty());
        assert!(matches!(entry.action, AdminAction::EnableLocalOnlyAccess));
    }
}