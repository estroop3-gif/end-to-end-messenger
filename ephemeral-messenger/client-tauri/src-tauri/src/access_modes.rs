use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use anyhow::{Result, Context, bail};
use serde::{Serialize, Deserialize};
use libsodium_sys::*;

use crate::settings_store::{SecureSettings, Settings, AccessMode};
use crate::keydetect::HardwareKeyDetector;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessModeManager {
    settings: Arc<SecureSettings>,
    key_detector: Arc<HardwareKeyDetector>,
    current_session: Arc<Mutex<Option<AuthenticatedSession>>>,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedSession {
    pub user_id: String,
    pub access_mode: AccessMode,
    pub session_key: [u8; 32],
    pub created_at: i64,
    pub last_activity: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginAttempt {
    pub mode: LoginMode,
    pub timestamp: i64,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoginMode {
    HardKey { device_id: String },
    LocalOnly { passphrase_provided: bool },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HazardWarning {
    pub title: String,
    pub message: String,
    pub risks: Vec<String>,
    pub mitigation: Vec<String>,
    pub acknowledgment_required: String,
}

impl AccessModeManager {
    pub fn new(data_dir: PathBuf) -> Result<Self> {
        // Initialize libsodium
        unsafe {
            if sodium_init() < 0 {
                bail!("Failed to initialize libsodium");
            }
        }

        Ok(AccessModeManager {
            settings: Arc::new(SecureSettings::new(data_dir)?),
            key_detector: Arc::new(HardwareKeyDetector::new()?),
            current_session: Arc::new(Mutex::new(None)),
        })
    }

    /// Attempt to authenticate using hardware key
    pub fn authenticate_with_hardware_key(&self) -> Result<AuthenticatedSession> {
        // Check if hardware key is present
        let detected_keys = self.key_detector.scan_for_keys()?;
        if detected_keys.is_empty() {
            bail!("No hardware key detected");
        }

        let primary_key = &detected_keys[0];

        // Validate key
        if !self.key_detector.validate_key(&primary_key.device_path)? {
            bail!("Hardware key validation failed");
        }

        // Load settings using hardware key
        let settings = self.settings.load_with_hardware_key()
            .context("Failed to load settings with hardware key")?;

        // Ensure access mode is set to hardware key
        if !matches!(settings.access_mode, AccessMode::HardKey) {
            bail!("Settings not configured for hardware key access");
        }

        // Generate session key
        let mut session_key = [0u8; 32];
        unsafe {
            randombytes_buf(session_key.as_mut_ptr() as *mut _, session_key.len());
        }

        let session = AuthenticatedSession {
            user_id: primary_key.device_id.clone(),
            access_mode: settings.access_mode,
            session_key,
            created_at: chrono::Utc::now().timestamp(),
            last_activity: chrono::Utc::now().timestamp(),
        };

        // Store session
        *self.current_session.lock().unwrap() = Some(session.clone());

        Ok(session)
    }

    /// Attempt to authenticate using local passphrase
    pub fn authenticate_with_passphrase(&self, passphrase: &str) -> Result<AuthenticatedSession> {
        // Load settings using passphrase
        let settings = self.settings.load_with_passphrase(passphrase)
            .context("Failed to load settings - invalid passphrase or settings not found")?;

        // Ensure access mode is set to local-only
        match &settings.access_mode {
            AccessMode::LocalOnly { .. } => {
                // Verify passphrase against stored credential
                self.settings.verify_local_login(passphrase, &settings.access_mode)?;
            }
            AccessMode::HardKey => {
                bail!("Settings configured for hardware key access, not local passphrase");
            }
        }

        // Generate session key
        let mut session_key = [0u8; 32];
        unsafe {
            randombytes_buf(session_key.as_mut_ptr() as *mut _, session_key.len());
        }

        let session = AuthenticatedSession {
            user_id: "local_user".to_string(),
            access_mode: settings.access_mode,
            session_key,
            created_at: chrono::Utc::now().timestamp(),
            last_activity: chrono::Utc::now().timestamp(),
        };

        // Store session
        *self.current_session.lock().unwrap() = Some(session.clone());

        Ok(session)
    }

    /// Enable local-only access mode (requires existing authentication)
    pub fn enable_local_access(&self, passphrase: &str, confirmation: &str) -> Result<()> {
        // Verify user is currently authenticated
        let session = self.get_current_session()
            .ok_or_else(|| anyhow::anyhow!("Not authenticated"))?;

        // Verify confirmation phrase
        let expected_confirmation = "I understand the security risks of local-only access";
        if confirmation != expected_confirmation {
            bail!("Confirmation phrase mismatch");
        }

        // Create local login credential
        let new_access_mode = self.settings.create_local_login(passphrase)?;

        // Load current settings
        let mut settings = match &session.access_mode {
            AccessMode::HardKey => self.settings.load_with_hardware_key()?,
            AccessMode::LocalOnly { .. } => {
                bail!("Already in local-only mode");
            }
        };

        // Update access mode
        settings.access_mode = new_access_mode;

        // Save updated settings
        self.settings.save(&settings)?;

        Ok(())
    }

    /// Disable local-only access mode (return to hardware key only)
    pub fn disable_local_access(&self) -> Result<()> {
        // Verify user is currently authenticated
        let session = self.get_current_session()
            .ok_or_else(|| anyhow::anyhow!("Not authenticated"))?;

        // Verify hardware key is present
        let detected_keys = self.key_detector.scan_for_keys()?;
        if detected_keys.is_empty() {
            bail!("Cannot disable local access - no hardware key detected");
        }

        // Load current settings
        let mut settings = match &session.access_mode {
            AccessMode::HardKey => {
                bail!("Already in hardware key mode");
            }
            AccessMode::LocalOnly { .. } => {
                // We need to load with the current session, but then transition to hardware key
                // This is a special case - we'll load the current settings without key validation
                self.settings.load_with_hardware_key()
                    .context("Failed to transition to hardware key mode")?
            }
        };

        // Update access mode
        settings.access_mode = AccessMode::HardKey;

        // Save updated settings
        self.settings.save(&settings)?;

        Ok(())
    }

    /// Get current authenticated session
    pub fn get_current_session(&self) -> Option<AuthenticatedSession> {
        self.current_session.lock().unwrap().clone()
    }

    /// Check if user is authenticated
    pub fn is_authenticated(&self) -> bool {
        self.current_session.lock().unwrap().is_some()
    }

    /// Update last activity timestamp
    pub fn update_activity(&self) -> Result<()> {
        if let Some(ref mut session) = *self.current_session.lock().unwrap() {
            session.last_activity = chrono::Utc::now().timestamp();
        }
        Ok(())
    }

    /// Lock the session (clear sensitive data)
    pub fn lock(&self) {
        // Clear session data
        if let Some(mut session) = self.current_session.lock().unwrap().take() {
            // Securely clear session key
            unsafe {
                sodium_memzero(session.session_key.as_mut_ptr() as *mut _, session.session_key.len());
            }
        }

        // Lock settings
        self.settings.lock();
    }

    /// Check hardware key requirement
    pub fn check_hardware_key_requirement(&self) -> Result<bool> {
        // Try to determine the required access mode without authentication
        // This is tricky since we need to peek at settings without decrypting them
        // For now, we'll assume hardware key is required if no local-only mode is configured

        let detected_keys = self.key_detector.scan_for_keys()?;
        if detected_keys.is_empty() {
            // No hardware key present - check if local-only is available
            // We can't check this without decrypting settings, so we'll assume hardware key is required
            return Ok(true);
        }

        // Hardware key is present, so we can load settings
        match self.settings.load_with_hardware_key() {
            Ok(settings) => Ok(matches!(settings.access_mode, AccessMode::HardKey)),
            Err(_) => Ok(true), // If we can't load, assume hardware key is required
        }
    }

    /// Get hazard warning for local-only access
    pub fn get_local_access_warning(&self) -> HazardWarning {
        HazardWarning {
            title: "Security Warning: Local-Only Access".to_string(),
            message: "You are about to enable local-only access mode. This stores your login credentials locally (encrypted) instead of requiring a physical hardware key.".to_string(),
            risks: vec![
                "Your encrypted credentials will be stored on this device".to_string(),
                "If this device is seized, your credentials may be at risk".to_string(),
                "No physical key requirement means weaker access control".to_string(),
                "Compromise of this device could lead to account access".to_string(),
            ],
            mitigation: vec![
                "Use a strong passphrase (minimum 20 characters)".to_string(),
                "Enable full disk encryption on this device".to_string(),
                "Consider using a hardware key instead".to_string(),
                "Keep this device physically secure".to_string(),
            ],
            acknowledgment_required: "I understand the security risks of local-only access".to_string(),
        }
    }

    /// Validate passphrase strength for local-only access
    pub fn validate_passphrase_strength(&self, passphrase: &str) -> Result<PasswordStrength> {
        let length = passphrase.len();
        let mut score = 0;
        let mut feedback = Vec::new();

        // Length checks
        if length < 12 {
            feedback.push("Passphrase should be at least 12 characters".to_string());
        } else if length >= 20 {
            score += 2;
        } else if length >= 16 {
            score += 1;
        }

        // Character variety
        let has_upper = passphrase.chars().any(|c| c.is_uppercase());
        let has_lower = passphrase.chars().any(|c| c.is_lowercase());
        let has_digit = passphrase.chars().any(|c| c.is_numeric());
        let has_special = passphrase.chars().any(|c| !c.is_alphanumeric());

        let variety_count = [has_upper, has_lower, has_digit, has_special]
            .iter()
            .filter(|&&x| x)
            .count();

        match variety_count {
            4 => score += 2,
            3 => score += 1,
            _ => feedback.push("Use a mix of uppercase, lowercase, numbers, and symbols".to_string()),
        }

        // Common patterns (basic check)
        if passphrase.to_lowercase().contains("password") ||
           passphrase.to_lowercase().contains("jesus") ||
           passphrase.contains("123") {
            feedback.push("Avoid common words or patterns".to_string());
            score = score.saturating_sub(1);
        }

        let strength = match score {
            0..=1 => PasswordStrength::Weak,
            2..=3 => PasswordStrength::Medium,
            4..=5 => PasswordStrength::Strong,
            _ => PasswordStrength::VeryStrong,
        };

        Ok(PasswordStrength {
            level: strength,
            score,
            feedback,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordStrength {
    pub level: PasswordStrengthLevel,
    pub score: i32,
    pub feedback: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PasswordStrengthLevel {
    Weak,
    Medium,
    Strong,
    VeryStrong,
}

impl Drop for AccessModeManager {
    fn drop(&mut self) {
        self.lock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_password_strength_validation() {
        let temp_dir = TempDir::new().unwrap();
        let manager = AccessModeManager::new(temp_dir.path().to_path_buf()).unwrap();

        // Weak password
        let strength = manager.validate_passphrase_strength("weak").unwrap();
        assert!(matches!(strength.level, PasswordStrengthLevel::Weak));

        // Strong password
        let strength = manager.validate_passphrase_strength("MyVerySecurePassphrase123!").unwrap();
        assert!(matches!(strength.level, PasswordStrengthLevel::Strong | PasswordStrengthLevel::VeryStrong));
    }

    #[test]
    fn test_local_access_warning() {
        let temp_dir = TempDir::new().unwrap();
        let manager = AccessModeManager::new(temp_dir.path().to_path_buf()).unwrap();

        let warning = manager.get_local_access_warning();
        assert!(!warning.risks.is_empty());
        assert!(!warning.mitigation.is_empty());
        assert!(!warning.acknowledgment_required.is_empty());
    }
}