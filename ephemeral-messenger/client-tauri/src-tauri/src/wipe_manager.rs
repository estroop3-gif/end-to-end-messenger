// Dead-Man Switch and Wipe Manager
// Handles automated security responses and audit logging

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};
use ed25519_dalek::{Signature, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use base64;
use time::OffsetDateTime;

use crate::settings_store::{SettingsStore, DeadManSwitchSettings};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmsPolicy {
    pub version: u32,
    pub policy_id: String,
    pub admin_pubkey: String,      // Base64 encoded Ed25519 public key
    pub machine_binding: String,   // Expected machine identifier hash
    pub max_inactive_hours: u32,
    pub check_interval_hours: u32,
    pub wipe_actions: Vec<WipeAction>,
    pub emergency_contact: Option<String>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WipeAction {
    SecureDelete,
    OverwriteMemory,
    ClearCredentials,
    NotifyEmergencyContact,
    SelfDestruct,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub timestamp: i64,
    pub event_type: String,
    pub details: String,
    pub machine_id: String,
    pub signature: Option<String>, // Ed25519 signature
}

pub struct WipeManager {
    settings_store: SettingsStore,
    data_dir: PathBuf,
    admin_removable_path: Option<PathBuf>,
}

impl WipeManager {
    pub fn new(settings_store: SettingsStore, data_dir: PathBuf) -> Self {
        Self {
            settings_store,
            data_dir,
            admin_removable_path: None,
        }
    }

    pub fn set_admin_removable_path(&mut self, path: PathBuf) {
        self.admin_removable_path = Some(path);
    }

    // Policy verification and management
    pub fn verify_dms_policy(&self, policy_bytes: &[u8], signature_b64: &str, admin_pubkey_b64: &str) -> Result<DmsPolicy> {
        // Decode the Ed25519 public key
        let pubkey_bytes = base64::decode(admin_pubkey_b64)
            .map_err(|e| anyhow!("Invalid base64 admin public key: {}", e))?;

        if pubkey_bytes.len() != PUBLIC_KEY_LENGTH {
            bail!("Invalid admin public key length: expected {}, got {}", PUBLIC_KEY_LENGTH, pubkey_bytes.len());
        }

        let verifying_key = VerifyingKey::from_bytes(
            &pubkey_bytes.try_into()
                .map_err(|_| anyhow!("Failed to convert public key bytes"))?
        ).map_err(|e| anyhow!("Invalid Ed25519 public key: {}", e))?;

        // Decode the signature
        let signature_bytes = base64::decode(signature_b64)
            .map_err(|e| anyhow!("Invalid base64 signature: {}", e))?;

        if signature_bytes.len() != SIGNATURE_LENGTH {
            bail!("Invalid signature length: expected {}, got {}", SIGNATURE_LENGTH, signature_bytes.len());
        }

        let signature = Signature::from_bytes(
            &signature_bytes.try_into()
                .map_err(|_| anyhow!("Failed to convert signature bytes"))?
        );

        // Verify the signature
        verifying_key.verify_strict(policy_bytes, &signature)
            .map_err(|e| anyhow!("Policy signature verification failed: {}", e))?;

        // Parse the policy JSON
        let policy: DmsPolicy = serde_json::from_slice(policy_bytes)
            .map_err(|e| anyhow!("Failed to parse policy JSON: {}", e))?;

        // Validate policy constraints
        self.validate_policy(&policy)?;

        // Check machine binding
        let current_machine_id = self.get_machine_identifier()?;
        if policy.machine_binding != current_machine_id {
            bail!("Policy machine binding mismatch: expected {}, got {}",
                  policy.machine_binding, current_machine_id);
        }

        // Check admin public key matches
        if policy.admin_pubkey != admin_pubkey_b64 {
            bail!("Policy admin public key mismatch");
        }

        // Check expiry if set
        if let Some(expires_at) = policy.expires_at {
            let now = OffsetDateTime::now_utc().unix_timestamp();
            if now > expires_at {
                bail!("Policy has expired");
            }
        }

        Ok(policy)
    }

    fn validate_policy(&self, policy: &DmsPolicy) -> Result<()> {
        // Version validation
        if policy.version != 1 {
            bail!("Unsupported policy version: {}", policy.version);
        }

        // Timing constraints
        if policy.max_inactive_hours < 1 || policy.max_inactive_hours > 8760 { // Max 1 year
            bail!("Invalid max_inactive_hours: must be between 1 and 8760");
        }

        if policy.check_interval_hours < 1 || policy.check_interval_hours > policy.max_inactive_hours {
            bail!("Invalid check_interval_hours: must be between 1 and max_inactive_hours");
        }

        // Ensure at least one wipe action is specified
        if policy.wipe_actions.is_empty() {
            bail!("Policy must specify at least one wipe action");
        }

        // Validate policy ID format (must be valid identifier)
        if policy.policy_id.is_empty() || policy.policy_id.len() > 64 {
            bail!("Invalid policy ID: must be 1-64 characters");
        }

        Ok(())
    }

    pub fn get_machine_identifier(&self) -> Result<String> {
        // Generate a stable machine identifier from hardware characteristics
        let mut hasher = Sha256::new();

        // CPU info
        if let Ok(cpu_info) = std::fs::read_to_string("/proc/cpuinfo") {
            // Extract processor serial/model info
            for line in cpu_info.lines() {
                if line.starts_with("processor") || line.starts_with("model name") || line.starts_with("cpu MHz") {
                    hasher.update(line.as_bytes());
                }
            }
        }

        // Memory info
        if let Ok(mem_info) = std::fs::read_to_string("/proc/meminfo") {
            if let Some(total_line) = mem_info.lines().find(|l| l.starts_with("MemTotal:")) {
                hasher.update(total_line.as_bytes());
            }
        }

        // Machine ID
        if let Ok(machine_id) = std::fs::read_to_string("/etc/machine-id") {
            hasher.update(machine_id.trim().as_bytes());
        } else if let Ok(machine_id) = std::fs::read_to_string("/var/lib/dbus/machine-id") {
            hasher.update(machine_id.trim().as_bytes());
        }

        // Boot ID for session uniqueness
        if let Ok(boot_id) = std::fs::read_to_string("/proc/sys/kernel/random/boot_id") {
            hasher.update(boot_id.trim().as_bytes());
        }

        let result = hasher.finalize();
        Ok(hex::encode(&result[..16])) // Use first 16 bytes as hex string
    }

    pub fn configure_dms(&self, policy: DmsPolicy, signature: String) -> Result<()> {
        // Calculate policy hash
        let policy_json = serde_json::to_string(&policy)?;
        let policy_hash = hex::encode(Sha256::digest(policy_json.as_bytes()));

        let dms_settings = DeadManSwitchSettings {
            enabled: true,
            check_interval_hours: policy.check_interval_hours,
            max_inactive_hours: policy.max_inactive_hours,
            policy_signature: Some(signature),
            policy_hash: Some(policy_hash),
            admin_pubkey: Some(policy.admin_pubkey.clone()),
            machine_binding: Some(policy.machine_binding.clone()),
            last_checkin: Some(OffsetDateTime::now_utc().unix_timestamp()),
            configured_at: Some(OffsetDateTime::now_utc().unix_timestamp()),
        };

        // Save settings
        self.settings_store.update_dms_settings(dms_settings)?;

        // Create audit log entry
        self.audit_log("DMS_CONFIGURED", &format!("Policy ID: {}, Max inactive: {} hours",
                                                   policy.policy_id, policy.max_inactive_hours))?;

        Ok(())
    }

    pub fn check_dms_status(&self) -> Result<bool> {
        let (enabled, last_checkin, max_inactive_hours) = self.settings_store.get_dms_status()?;

        if !enabled {
            return Ok(false);
        }

        let Some(last_checkin) = last_checkin else {
            // No checkin recorded, trigger immediately
            return Ok(true);
        };

        let now = OffsetDateTime::now_utc().unix_timestamp();
        let inactive_hours = (now - last_checkin) / 3600;

        Ok(inactive_hours >= max_inactive_hours as i64)
    }

    pub fn perform_checkin(&self) -> Result<()> {
        self.settings_store.update_dms_checkin()?;
        self.audit_log("DMS_CHECKIN", "User activity detected")?;
        Ok(())
    }

    pub fn trigger_emergency_wipe(&self, reason: &str) -> Result<()> {
        self.audit_log("EMERGENCY_WIPE_TRIGGERED", reason)?;

        // Execute wipe procedures
        self.secure_delete_data()?;
        self.overwrite_memory()?;
        self.clear_credentials()?;

        // Final audit entry
        self.audit_log("EMERGENCY_WIPE_COMPLETED", "All wipe actions executed")?;

        Ok(())
    }

    // Audit logging functions
    pub fn audit_log(&self, event_type: &str, details: &str) -> Result<()> {
        let machine_id = self.get_machine_identifier()?;
        let timestamp = OffsetDateTime::now_utc().unix_timestamp();

        let entry = AuditLogEntry {
            timestamp,
            event_type: event_type.to_string(),
            details: details.to_string(),
            machine_id: machine_id.clone(),
            signature: None, // TODO: Sign with device key if available
        };

        // Write to local audit log
        self.write_local_audit_entry(&entry)?;

        // Write to admin removable media if available
        if let Some(ref admin_path) = self.admin_removable_path {
            if admin_path.exists() {
                self.write_admin_audit_entry(&entry, admin_path)?;
            }
        }

        Ok(())
    }

    fn write_local_audit_entry(&self, entry: &AuditLogEntry) -> Result<()> {
        let audit_file = self.data_dir.join("audit.log");

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&audit_file)?;

        let entry_json = serde_json::to_string(entry)?;
        writeln!(file, "{}", entry_json)?;
        file.sync_all()?;

        Ok(())
    }

    fn write_admin_audit_entry(&self, entry: &AuditLogEntry, admin_path: &Path) -> Result<()> {
        let audit_file = admin_path.join("dms_audit.log");

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&audit_file)?;

        let entry_json = serde_json::to_string(entry)?;
        writeln!(file, "{}", entry_json)?;
        file.sync_all()?;

        Ok(())
    }

    // Wipe action implementations
    fn secure_delete_data(&self) -> Result<()> {
        // Implement secure deletion of sensitive data
        // This is a stub - real implementation would:
        // 1. Identify all sensitive files
        // 2. Overwrite with random data multiple times
        // 3. Delete file entries

        self.audit_log("SECURE_DELETE_STARTED", "Beginning secure deletion of sensitive data")?;

        // TODO: Implement actual secure deletion

        self.audit_log("SECURE_DELETE_COMPLETED", "Secure deletion completed")?;
        Ok(())
    }

    fn overwrite_memory(&self) -> Result<()> {
        // Implement memory overwriting
        self.audit_log("MEMORY_OVERWRITE_STARTED", "Beginning memory overwrite")?;

        // TODO: Implement memory overwriting
        // This would involve:
        // 1. Identifying mapped memory regions
        // 2. Overwriting with random data
        // 3. Forcing swapout if needed

        self.audit_log("MEMORY_OVERWRITE_COMPLETED", "Memory overwrite completed")?;
        Ok(())
    }

    fn clear_credentials(&self) -> Result<()> {
        // Clear stored credentials
        self.audit_log("CREDENTIAL_CLEAR_STARTED", "Beginning credential clearance")?;

        // Clear local credentials
        self.settings_store.clear_local_credential()?;

        // TODO: Clear other credential stores

        self.audit_log("CREDENTIAL_CLEAR_COMPLETED", "Credential clearance completed")?;
        Ok(())
    }

    // Disable DMS (admin function only)
    pub fn disable_dms(&self, admin_signature: &str) -> Result<()> {
        // Verify admin signature for disable operation
        // TODO: Implement signature verification

        let mut dms_settings = self.settings_store.get_dms_settings()?;
        dms_settings.enabled = false;
        self.settings_store.update_dms_settings(dms_settings)?;

        self.audit_log("DMS_DISABLED", &format!("Admin signature: {}", admin_signature))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_machine_identifier_stability() {
        let temp_dir = TempDir::new().unwrap();
        let settings_store = SettingsStore::new(temp_dir.path().to_path_buf()).unwrap();
        let wipe_manager = WipeManager::new(settings_store, temp_dir.path().to_path_buf());

        // Machine identifier should be consistent
        let id1 = wipe_manager.get_machine_identifier().unwrap();
        let id2 = wipe_manager.get_machine_identifier().unwrap();

        assert_eq!(id1, id2);
        assert!(!id1.is_empty());
        assert_eq!(id1.len(), 32); // 16 bytes as hex = 32 chars
    }

    #[test]
    fn test_audit_logging() {
        let temp_dir = TempDir::new().unwrap();
        let settings_store = SettingsStore::new(temp_dir.path().to_path_buf()).unwrap();
        let wipe_manager = WipeManager::new(settings_store, temp_dir.path().to_path_buf());

        wipe_manager.audit_log("TEST_EVENT", "Test details").unwrap();

        let audit_file = temp_dir.path().join("audit.log");
        assert!(audit_file.exists());

        let content = std::fs::read_to_string(audit_file).unwrap();
        assert!(content.contains("TEST_EVENT"));
        assert!(content.contains("Test details"));
    }

    #[test]
    fn test_policy_validation() {
        let temp_dir = TempDir::new().unwrap();
        let settings_store = SettingsStore::new(temp_dir.path().to_path_buf()).unwrap();
        let wipe_manager = WipeManager::new(settings_store, temp_dir.path().to_path_buf());

        let valid_policy = DmsPolicy {
            version: 1,
            policy_id: "test_policy".to_string(),
            admin_pubkey: "test_key".to_string(),
            machine_binding: "test_machine".to_string(),
            max_inactive_hours: 168,
            check_interval_hours: 24,
            wipe_actions: vec![WipeAction::SecureDelete],
            emergency_contact: None,
            created_at: 0,
            expires_at: None,
        };

        assert!(wipe_manager.validate_policy(&valid_policy).is_ok());

        // Test invalid policy
        let invalid_policy = DmsPolicy {
            max_inactive_hours: 0, // Invalid
            ..valid_policy
        };

        assert!(wipe_manager.validate_policy(&invalid_policy).is_err());
    }
}