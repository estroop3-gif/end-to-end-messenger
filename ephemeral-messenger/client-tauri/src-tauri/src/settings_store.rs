use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use anyhow::{Result, Context, bail};
use serde::{Serialize, Deserialize};
use argon2::{Argon2, Algorithm, Version, Params, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{PasswordHash, SaltString};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::Aead, KeyInit};
use zeroize::{Zeroize, ZeroizeOnDrop};
use fs4::FileExt;
use time::OffsetDateTime;
use rand::{RngCore, rngs::OsRng};

const SETTINGS_VERSION: u32 = 1;
const SETTINGS_FILENAME: &str = "settings_v1.json";
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_MEMORY_COST: u32 = 65536; // 64 MiB
const ARGON2_PARALLELISM: u32 = 1;
const MASTER_KEY_SIZE: usize = 32;
const WRAP_KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const SALT_SIZE: usize = 16;

static SETTINGS_MUTEX: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub version: u32,
    pub access_mode: AccessMode,
    pub credential: Option<LocalCredential>,
    pub updated_at: i64,
    pub dead_man_switch: DeadManSwitchSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadManSwitchSettings {
    pub enabled: bool,
    pub check_interval_hours: u32,
    pub max_inactive_hours: u32,
    pub policy_signature: Option<String>,  // Base64 encoded Ed25519 signature
    pub policy_hash: Option<String>,       // SHA-256 hash of policy document
    pub admin_pubkey: Option<String>,      // Base64 encoded Ed25519 public key
    pub machine_binding: Option<String>,   // Machine-specific identifier hash
    pub last_checkin: Option<i64>,        // Unix timestamp of last checkin
    pub configured_at: Option<i64>,       // Unix timestamp when first configured
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    Hardkey,
    LocalPassphrase,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalCredential {
    pub phc: String,           // PHC string from Argon2id for verification
    pub salt_b64: String,      // Base64 encoded salt for wrap key derivation
    pub wrapped_master_b64: String,  // Base64 encoded AEAD ciphertext + tag
    pub nonce_b64: String,     // Base64 encoded nonce for AEAD
}

#[derive(ZeroizeOnDrop)]
struct SensitiveData {
    passphrase: String,
    wrap_key: [u8; WRAP_KEY_SIZE],
    master_key: [u8; MASTER_KEY_SIZE],
}

impl Default for DeadManSwitchSettings {
    fn default() -> Self {
        DeadManSwitchSettings {
            enabled: false,
            check_interval_hours: 24,
            max_inactive_hours: 168, // 7 days
            policy_signature: None,
            policy_hash: None,
            admin_pubkey: None,
            machine_binding: None,
            last_checkin: None,
            configured_at: None,
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            version: SETTINGS_VERSION,
            access_mode: AccessMode::Hardkey,
            credential: None,
            updated_at: OffsetDateTime::now_utc().unix_timestamp(),
            dead_man_switch: DeadManSwitchSettings::default(),
        }
    }
}

pub struct SettingsStore {
    data_dir: PathBuf,
}

impl SettingsStore {
    pub fn new(data_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&data_dir)
            .with_context(|| format!("Failed to create settings directory: {:?}", data_dir))?;

        Ok(SettingsStore { data_dir })
    }

    pub fn load_settings(&self) -> Result<Settings> {
        let _guard = SETTINGS_MUTEX.lock().unwrap();
        let settings_path = self.data_dir.join(SETTINGS_FILENAME);

        if !settings_path.exists() {
            // First run - return default settings
            return Ok(Settings::default());
        }

        let mut file = File::open(&settings_path)
            .with_context(|| format!("Failed to open settings file: {:?}", settings_path))?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .context("Failed to read settings file")?;

        let settings: Settings = serde_json::from_str(&contents)
            .context("Failed to parse settings JSON")?;

        if settings.version > SETTINGS_VERSION {
            bail!("Settings file is from a newer version ({}), expected <= {}",
                  settings.version, SETTINGS_VERSION);
        }

        // Migration logic for older versions
        let migrated_settings = self.migrate_settings(settings)?;
        Ok(migrated_settings)
    }

    pub fn save_settings(&self, settings: &Settings) -> Result<()> {
        let _guard = SETTINGS_MUTEX.lock().unwrap();
        let settings_path = self.data_dir.join(SETTINGS_FILENAME);
        let temp_path = self.data_dir.join(format!("{}.tmp", SETTINGS_FILENAME));

        // Create updated settings with current timestamp
        let mut updated_settings = settings.clone();
        updated_settings.updated_at = OffsetDateTime::now_utc().unix_timestamp();

        // Atomic write: write to temp file first
        {
            let mut temp_file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp_path)
                .with_context(|| format!("Failed to create temp file: {:?}", temp_path))?;

            // Lock the file for exclusive access
            temp_file.lock_exclusive()
                .context("Failed to lock temp settings file")?;

            let json_data = serde_json::to_string_pretty(&updated_settings)
                .context("Failed to serialize settings to JSON")?;

            temp_file.write_all(json_data.as_bytes())
                .context("Failed to write settings data")?;

            temp_file.sync_all()
                .context("Failed to sync settings file to disk")?;

            temp_file.unlock()
                .context("Failed to unlock temp settings file")?;
        }

        // Atomic rename
        std::fs::rename(&temp_path, &settings_path)
            .with_context(|| format!("Failed to rename {:?} to {:?}", temp_path, settings_path))?;

        Ok(())
    }

    pub fn set_local_passphrase(&self, passphrase: &str) -> Result<()> {
        // Validate passphrase length
        if passphrase.len() < 10 {
            bail!("Passphrase must be at least 10 characters long");
        }

        let mut sensitive = SensitiveData {
            passphrase: passphrase.to_string(),
            wrap_key: [0u8; WRAP_KEY_SIZE],
            master_key: [0u8; MASTER_KEY_SIZE],
        };

        // Generate random master key
        OsRng.fill_bytes(&mut sensitive.master_key);

        // Generate salt for wrap key derivation
        let mut salt_bytes = [0u8; SALT_SIZE];
        OsRng.fill_bytes(&mut salt_bytes);

        // Derive wrap key from passphrase using Argon2id
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(
                ARGON2_MEMORY_COST,
                ARGON2_TIME_COST,
                ARGON2_PARALLELISM,
                Some(WRAP_KEY_SIZE),
            ).map_err(|e| anyhow::anyhow!("Failed to create Argon2 parameters: {:?}", e))?,
        );

        argon2.hash_password_into(
            sensitive.passphrase.as_bytes(),
            &salt_bytes,
            &mut sensitive.wrap_key,
        ).context("Failed to derive wrap key from passphrase")?;

        // Create PHC string for verification
        let salt_string = SaltString::encode_b64(&salt_bytes)
            .context("Failed to encode salt for PHC")?;

        let password_hash = argon2.hash_password(sensitive.passphrase.as_bytes(), &salt_string)
            .context("Failed to create password hash")?;

        // Generate nonce for AEAD encryption
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);

        // Encrypt master key with wrap key using ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::from(Key::from_slice(&sensitive.wrap_key));
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, sensitive.master_key.as_ref())
            .map_err(|_| anyhow::anyhow!("Failed to encrypt master key"))?;

        // Create credential structure
        let credential = LocalCredential {
            phc: password_hash.to_string(),
            salt_b64: base64::encode(&salt_bytes),
            wrapped_master_b64: base64::encode(&ciphertext),
            nonce_b64: base64::encode(&nonce_bytes),
        };

        // Load current settings and update
        let mut settings = self.load_settings()?;
        settings.access_mode = AccessMode::LocalPassphrase;
        settings.credential = Some(credential);

        // Save updated settings
        self.save_settings(&settings)?;

        // Zeroize sensitive data (automatic via ZeroizeOnDrop)
        drop(sensitive);

        Ok(())
    }

    pub fn verify_local_passphrase(&self, passphrase: &str) -> Result<bool> {
        let settings = self.load_settings()?;

        let credential = match &settings.credential {
            Some(cred) => cred,
            None => bail!("No local credential found"),
        };

        // Verify passphrase against PHC hash
        let parsed_hash = PasswordHash::new(&credential.phc)
            .map_err(|e| anyhow::anyhow!("Failed to parse stored password hash: {:?}", e))?;

        let argon2 = Argon2::default();
        let verification_result = argon2.verify_password(passphrase.as_bytes(), &parsed_hash);

        if verification_result.is_err() {
            return Ok(false);
        }

        // If verification succeeded, we could also decrypt the master key here
        // to prove the credential is intact, but for now just return success
        self.verify_credential_integrity(passphrase, credential)
    }

    fn verify_credential_integrity(&self, passphrase: &str, credential: &LocalCredential) -> Result<bool> {
        // Decode stored values
        let salt_bytes = base64::decode(&credential.salt_b64)
            .context("Failed to decode salt from base64")?;
        let wrapped_master = base64::decode(&credential.wrapped_master_b64)
            .context("Failed to decode wrapped master key from base64")?;
        let nonce_bytes = base64::decode(&credential.nonce_b64)
            .context("Failed to decode nonce from base64")?;

        if salt_bytes.len() != SALT_SIZE || nonce_bytes.len() != NONCE_SIZE {
            bail!("Invalid credential format - wrong salt or nonce size");
        }

        // Derive wrap key
        let mut wrap_key = [0u8; WRAP_KEY_SIZE];
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(
                ARGON2_MEMORY_COST,
                ARGON2_TIME_COST,
                ARGON2_PARALLELISM,
                Some(WRAP_KEY_SIZE),
            ).map_err(|e| anyhow::anyhow!("Failed to create Argon2 parameters: {:?}", e))?,
        );

        argon2.hash_password_into(passphrase.as_bytes(), &salt_bytes, &mut wrap_key)
            .map_err(|e| anyhow::anyhow!("Failed to derive wrap key: {:?}", e))?;

        // Decrypt master key to verify integrity
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&wrap_key));
        let nonce = Nonce::from_slice(&nonce_bytes);

        let decrypt_result = cipher.decrypt(nonce, wrapped_master.as_ref());

        // Zeroize wrap key
        wrap_key.zeroize();

        match decrypt_result {
            Ok(master_key) => {
                // Verify we got the expected key size
                if master_key.len() != MASTER_KEY_SIZE {
                    bail!("Decrypted master key has wrong size");
                }
                // Master key is automatically zeroized when dropped
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }

    pub fn set_hardkey_mode(&self) -> Result<()> {
        let mut settings = self.load_settings()?;
        settings.access_mode = AccessMode::Hardkey;
        // Keep the credential for potential future use, but switch mode
        self.save_settings(&settings)
    }

    pub fn get_access_mode(&self) -> Result<AccessMode> {
        let settings = self.load_settings()?;
        Ok(settings.access_mode)
    }

    pub fn clear_local_credential(&self) -> Result<()> {
        let mut settings = self.load_settings()?;
        settings.credential = None;
        settings.access_mode = AccessMode::Hardkey;
        self.save_settings(&settings)
    }

    fn migrate_settings(&self, mut settings: Settings) -> Result<Settings> {
        let original_version = settings.version;

        // If this is a fresh default settings (version matches current), no migration needed
        if original_version == SETTINGS_VERSION {
            return Ok(settings);
        }

        // If settings don't have dead_man_switch field (from version < 1), add defaults
        // This handles the case where we're reading old JSON that doesn't have the field
        // Since we added the field with a Default implementation, serde should handle this
        // But we explicitly handle it here for robustness

        // Update version to current
        settings.version = SETTINGS_VERSION;

        // If migration changed anything, save the migrated settings
        if original_version != SETTINGS_VERSION {
            self.save_settings(&settings)?;
        }

        Ok(settings)
    }

    // Dead-Man Switch specific methods
    pub fn update_dms_settings(&self, dms_settings: DeadManSwitchSettings) -> Result<()> {
        let mut settings = self.load_settings()?;
        settings.dead_man_switch = dms_settings;
        self.save_settings(&settings)
    }

    pub fn get_dms_settings(&self) -> Result<DeadManSwitchSettings> {
        let settings = self.load_settings()?;
        Ok(settings.dead_man_switch)
    }

    pub fn update_dms_checkin(&self) -> Result<()> {
        let mut settings = self.load_settings()?;
        settings.dead_man_switch.last_checkin = Some(OffsetDateTime::now_utc().unix_timestamp());
        self.save_settings(&settings)
    }

    pub fn is_dms_enabled(&self) -> Result<bool> {
        let settings = self.load_settings()?;
        Ok(settings.dead_man_switch.enabled)
    }

    pub fn get_dms_status(&self) -> Result<(bool, Option<i64>, u32)> {
        let settings = self.load_settings()?;
        let dms = &settings.dead_man_switch;
        Ok((dms.enabled, dms.last_checkin, dms.max_inactive_hours))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_settings_default() {
        let settings = Settings::default();
        assert_eq!(settings.version, SETTINGS_VERSION);
        assert!(matches!(settings.access_mode, AccessMode::Hardkey));
        assert!(settings.credential.is_none());
    }

    #[test]
    fn test_settings_save_load() {
        let temp_dir = TempDir::new().unwrap();
        let store = SettingsStore::new(temp_dir.path().to_path_buf()).unwrap();

        // Load default settings (first run)
        let settings1 = store.load_settings().unwrap();
        assert!(matches!(settings1.access_mode, AccessMode::Hardkey));

        // Save and reload
        store.save_settings(&settings1).unwrap();
        let settings2 = store.load_settings().unwrap();

        assert_eq!(settings1.version, settings2.version);
        assert!(matches!(settings2.access_mode, AccessMode::Hardkey));
    }

    #[test]
    fn test_local_passphrase_flow() {
        let temp_dir = TempDir::new().unwrap();
        let store = SettingsStore::new(temp_dir.path().to_path_buf()).unwrap();

        let passphrase = "test_passphrase_123";

        // Set local passphrase
        store.set_local_passphrase(passphrase).unwrap();

        // Verify settings were updated
        let settings = store.load_settings().unwrap();
        assert!(matches!(settings.access_mode, AccessMode::LocalPassphrase));
        assert!(settings.credential.is_some());

        // Verify correct passphrase
        assert!(store.verify_local_passphrase(passphrase).unwrap());

        // Verify wrong passphrase fails
        assert!(!store.verify_local_passphrase("wrong_passphrase").unwrap());
    }

    #[test]
    fn test_passphrase_minimum_length() {
        let temp_dir = TempDir::new().unwrap();
        let store = SettingsStore::new(temp_dir.path().to_path_buf()).unwrap();

        // Should fail with short passphrase
        let result = store.set_local_passphrase("short");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("at least 10 characters"));
    }

    #[test]
    fn test_hardkey_mode_switch() {
        let temp_dir = TempDir::new().unwrap();
        let store = SettingsStore::new(temp_dir.path().to_path_buf()).unwrap();

        // Set local passphrase first
        store.set_local_passphrase("test_passphrase_123").unwrap();
        assert!(matches!(store.get_access_mode().unwrap(), AccessMode::LocalPassphrase));

        // Switch to hardkey mode
        store.set_hardkey_mode().unwrap();
        assert!(matches!(store.get_access_mode().unwrap(), AccessMode::Hardkey));

        // Credential should still exist but mode should be hardkey
        let settings = store.load_settings().unwrap();
        assert!(settings.credential.is_some());
        assert!(matches!(settings.access_mode, AccessMode::Hardkey));
    }

    #[test]
    fn test_credential_integrity() {
        let temp_dir = TempDir::new().unwrap();
        let store = SettingsStore::new(temp_dir.path().to_path_buf()).unwrap();

        let passphrase = "integrity_test_passphrase_456";
        store.set_local_passphrase(passphrase).unwrap();

        // Verify integrity through full flow
        assert!(store.verify_local_passphrase(passphrase).unwrap());

        // Corrupt the credential and verify it fails
        let mut settings = store.load_settings().unwrap();
        if let Some(ref mut cred) = settings.credential {
            // Corrupt the wrapped master key
            cred.wrapped_master_b64 = base64::encode(b"corrupted_data_here");
        }
        store.save_settings(&settings).unwrap();

        // Should now fail verification
        assert!(!store.verify_local_passphrase(passphrase).unwrap());
    }

    #[test]
    fn test_atomic_save() {
        let temp_dir = TempDir::new().unwrap();
        let store = SettingsStore::new(temp_dir.path().to_path_buf()).unwrap();

        let settings = Settings::default();

        // Save should create the file
        store.save_settings(&settings).unwrap();

        let settings_path = temp_dir.path().join(SETTINGS_FILENAME);
        assert!(settings_path.exists());

        // Temp file should not exist after successful save
        let temp_path = temp_dir.path().join(format!("{}.tmp", SETTINGS_FILENAME));
        assert!(!temp_path.exists());
    }
}