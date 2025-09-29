use anyhow::{anyhow, Result};
use base64::prelude::*;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng as AeadOsRng},
    ChaCha20Poly1305, Nonce,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareKeyConfig {
    pub key_id: String,
    pub key_type: KeyType,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub description: String,
    pub encrypted_private_key: String,
    pub public_key: String,
    pub salt: String,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyType {
    USBKey,
    SmartCard,
    YubiKey,
    FileKey,
    BiometricKey,
}

#[derive(ZeroizeOnDrop)]
pub struct HardwareKey {
    pub config: HardwareKeyConfig,
    private_key: Option<SecretKey>,
    public_key: PublicKey,
    cipher: ChaCha20Poly1305,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationChallenge {
    pub challenge_id: String,
    pub challenge_data: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationResponse {
    pub challenge_id: String,
    pub signature: String,
    pub public_key: String,
    pub key_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl HardwareKey {
    /// Create a new hardware key with the specified type and passphrase protection
    pub fn create_new(key_type: KeyType, description: String, passphrase: &str) -> Result<Self> {
        let mut csprng = OsRng {};
        let keypair = Keypair::generate(&mut csprng);

        let key_id = uuid::Uuid::new_v4().to_string();
        let salt = Self::generate_salt();
        let derived_key = Self::derive_key_from_passphrase(passphrase, &salt)?;

        let cipher = ChaCha20Poly1305::new(&derived_key.into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut AeadOsRng);

        // Encrypt the private key
        let encrypted_private_key = cipher.encrypt(&nonce, keypair.secret.as_bytes())
            .map_err(|e| anyhow!("Failed to encrypt private key: {}", e))?;

        let config = HardwareKeyConfig {
            key_id: key_id.clone(),
            key_type,
            created_at: chrono::Utc::now(),
            description,
            encrypted_private_key: BASE64_STANDARD.encode(&encrypted_private_key),
            public_key: BASE64_STANDARD.encode(keypair.public.as_bytes()),
            salt: BASE64_STANDARD.encode(&salt),
            nonce: BASE64_STANDARD.encode(&nonce),
        };

        Ok(HardwareKey {
            config,
            private_key: Some(keypair.secret),
            public_key: keypair.public,
            cipher,
        })
    }

    /// Load an existing hardware key from configuration
    pub fn load_from_config(config: HardwareKeyConfig, passphrase: &str) -> Result<Self> {
        let salt = BASE64_STANDARD.decode(&config.salt)
            .map_err(|e| anyhow!("Invalid salt: {}", e))?;

        let derived_key = Self::derive_key_from_passphrase(passphrase, &salt)?;
        let cipher = ChaCha20Poly1305::new(&derived_key.into());

        let nonce_bytes = BASE64_STANDARD.decode(&config.nonce)
            .map_err(|e| anyhow!("Invalid nonce: {}", e))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted_private_key = BASE64_STANDARD.decode(&config.encrypted_private_key)
            .map_err(|e| anyhow!("Invalid encrypted private key: {}", e))?;

        // Decrypt the private key
        let private_key_bytes = cipher.decrypt(nonce, encrypted_private_key.as_ref())
            .map_err(|e| anyhow!("Failed to decrypt private key: {}", e))?;

        let private_key = SecretKey::from_bytes(&private_key_bytes)
            .map_err(|e| anyhow!("Invalid private key: {}", e))?;

        let public_key_bytes = BASE64_STANDARD.decode(&config.public_key)
            .map_err(|e| anyhow!("Invalid public key: {}", e))?;

        let public_key = PublicKey::from_bytes(&public_key_bytes)
            .map_err(|e| anyhow!("Invalid public key: {}", e))?;

        Ok(HardwareKey {
            config,
            private_key: Some(private_key),
            public_key,
            cipher,
        })
    }

    /// Load hardware key from file
    pub fn load_from_file<P: AsRef<Path>>(file_path: P, passphrase: &str) -> Result<Self> {
        let config_data = fs::read_to_string(file_path)
            .map_err(|e| anyhow!("Failed to read key file: {}", e))?;

        let config: HardwareKeyConfig = serde_json::from_str(&config_data)
            .map_err(|e| anyhow!("Failed to parse key file: {}", e))?;

        Self::load_from_config(config, passphrase)
    }

    /// Save hardware key to file
    pub fn save_to_file<P: AsRef<Path>>(&self, file_path: P) -> Result<()> {
        let config_json = serde_json::to_string_pretty(&self.config)
            .map_err(|e| anyhow!("Failed to serialize config: {}", e))?;

        fs::write(file_path, config_json)
            .map_err(|e| anyhow!("Failed to write key file: {}", e))?;

        Ok(())
    }

    /// Create an authentication challenge
    pub fn create_challenge() -> AuthenticationChallenge {
        let challenge_id = uuid::Uuid::new_v4().to_string();
        let challenge_data = BASE64_STANDARD.encode(&uuid::Uuid::new_v4().as_bytes());
        let timestamp = chrono::Utc::now();
        let expires_at = timestamp + chrono::Duration::minutes(5);

        AuthenticationChallenge {
            challenge_id,
            challenge_data,
            timestamp,
            expires_at,
        }
    }

    /// Sign an authentication challenge
    pub fn sign_challenge(&self, challenge: &AuthenticationChallenge) -> Result<AuthenticationResponse> {
        let private_key = self.private_key.as_ref()
            .ok_or_else(|| anyhow!("Private key not available"))?;

        // Create message to sign
        let message = format!("{}:{}:{}",
            challenge.challenge_id,
            challenge.challenge_data,
            challenge.timestamp.timestamp()
        );

        let signature = private_key.sign(message.as_bytes());

        Ok(AuthenticationResponse {
            challenge_id: challenge.challenge_id.clone(),
            signature: BASE64_STANDARD.encode(signature.to_bytes()),
            public_key: self.config.public_key.clone(),
            key_id: self.config.key_id.clone(),
            timestamp: chrono::Utc::now(),
        })
    }

    /// Verify an authentication response
    pub fn verify_response(challenge: &AuthenticationChallenge, response: &AuthenticationResponse) -> Result<bool> {
        // Check if challenge has expired
        if chrono::Utc::now() > challenge.expires_at {
            return Ok(false);
        }

        // Check challenge ID matches
        if challenge.challenge_id != response.challenge_id {
            return Ok(false);
        }

        // Decode public key and signature
        let public_key_bytes = BASE64_STANDARD.decode(&response.public_key)
            .map_err(|e| anyhow!("Invalid public key: {}", e))?;

        let public_key = PublicKey::from_bytes(&public_key_bytes)
            .map_err(|e| anyhow!("Invalid public key format: {}", e))?;

        let signature_bytes = BASE64_STANDARD.decode(&response.signature)
            .map_err(|e| anyhow!("Invalid signature: {}", e))?;

        let signature = Signature::from_bytes(&signature_bytes)
            .map_err(|e| anyhow!("Invalid signature format: {}", e))?;

        // Reconstruct the signed message
        let message = format!("{}:{}:{}",
            challenge.challenge_id,
            challenge.challenge_data,
            challenge.timestamp.timestamp()
        );

        // Verify signature
        Ok(public_key.verify(message.as_bytes(), &signature).is_ok())
    }

    /// Get public key as base64 string
    pub fn get_public_key_b64(&self) -> String {
        self.config.public_key.clone()
    }

    /// Get key ID
    pub fn get_key_id(&self) -> &str {
        &self.config.key_id
    }

    /// Check if hardware key is present (simulate hardware detection)
    pub fn is_hardware_present(&self) -> bool {
        match self.config.key_type {
            KeyType::USBKey => Self::check_usb_key_present(),
            KeyType::SmartCard => Self::check_smart_card_present(),
            KeyType::YubiKey => Self::check_yubikey_present(),
            KeyType::FileKey => true, // File keys are always "present"
            KeyType::BiometricKey => Self::check_biometric_available(),
        }
    }

    /// Lock the hardware key (clear private key from memory)
    pub fn lock(&mut self) {
        if let Some(mut private_key) = self.private_key.take() {
            private_key.zeroize();
        }
    }

    /// Check if the key is unlocked (private key available)
    pub fn is_unlocked(&self) -> bool {
        self.private_key.is_some()
    }

    // Private helper methods
    fn generate_salt() -> [u8; 32] {
        let mut salt = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut salt);
        salt
    }

    fn derive_key_from_passphrase(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
        use argon2::{Argon2, PasswordHash, PasswordHasher};
        use argon2::password_hash::{SaltString, rand_core::OsRng};

        let salt_string = SaltString::encode_b64(salt)
            .map_err(|e| anyhow!("Failed to encode salt: {}", e))?;

        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(passphrase.as_bytes(), &salt_string)
            .map_err(|e| anyhow!("Failed to hash password: {}", e))?;

        let hash = password_hash.hash
            .ok_or_else(|| anyhow!("No hash generated"))?;

        let mut key = [0u8; 32];
        key.copy_from_slice(&hash.as_bytes()[..32]);
        Ok(key)
    }

    fn check_usb_key_present() -> bool {
        // Simulate USB key detection
        // In real implementation, this would check for specific USB devices
        std::path::Path::new("/dev/usb_security_key").exists()
    }

    fn check_smart_card_present() -> bool {
        // Simulate smart card detection
        // In real implementation, this would use PC/SC interface
        std::path::Path::new("/dev/smart_card").exists()
    }

    fn check_yubikey_present() -> bool {
        // Simulate YubiKey detection
        // In real implementation, this would use YubiKey SDK
        std::path::Path::new("/dev/yubikey").exists()
    }

    fn check_biometric_available() -> bool {
        // Simulate biometric availability
        // In real implementation, this would check for fingerprint readers, etc.
        std::path::Path::new("/dev/biometric").exists()
    }
}

/// Hardware Key Manager for managing multiple keys
pub struct HardwareKeyManager {
    keys: Vec<HardwareKeyConfig>,
    config_dir: PathBuf,
}

impl HardwareKeyManager {
    pub fn new<P: AsRef<Path>>(config_dir: P) -> Result<Self> {
        let config_dir = config_dir.as_ref().to_path_buf();

        // Create config directory if it doesn't exist
        if !config_dir.exists() {
            fs::create_dir_all(&config_dir)
                .map_err(|e| anyhow!("Failed to create config directory: {}", e))?;
        }

        let mut manager = HardwareKeyManager {
            keys: Vec::new(),
            config_dir,
        };

        manager.load_all_keys()?;
        Ok(manager)
    }

    pub fn add_key(&mut self, key: &HardwareKey) -> Result<()> {
        let key_file = self.config_dir.join(format!("{}.key", key.config.key_id));
        key.save_to_file(&key_file)?;

        self.keys.push(key.config.clone());
        Ok(())
    }

    pub fn remove_key(&mut self, key_id: &str) -> Result<()> {
        let key_file = self.config_dir.join(format!("{}.key", key_id));

        if key_file.exists() {
            fs::remove_file(&key_file)
                .map_err(|e| anyhow!("Failed to remove key file: {}", e))?;
        }

        self.keys.retain(|k| k.key_id != key_id);
        Ok(())
    }

    pub fn get_key(&self, key_id: &str, passphrase: &str) -> Result<HardwareKey> {
        let config = self.keys.iter()
            .find(|k| k.key_id == key_id)
            .ok_or_else(|| anyhow!("Key not found: {}", key_id))?;

        let key_file = self.config_dir.join(format!("{}.key", key_id));
        HardwareKey::load_from_file(&key_file, passphrase)
    }

    pub fn list_keys(&self) -> &[HardwareKeyConfig] {
        &self.keys
    }

    pub fn get_available_keys(&self) -> Vec<&HardwareKeyConfig> {
        self.keys.iter()
            .filter(|config| {
                // Check if hardware is present for this key type
                match config.key_type {
                    KeyType::USBKey => HardwareKey::check_usb_key_present(),
                    KeyType::SmartCard => HardwareKey::check_smart_card_present(),
                    KeyType::YubiKey => HardwareKey::check_yubikey_present(),
                    KeyType::FileKey => true,
                    KeyType::BiometricKey => HardwareKey::check_biometric_available(),
                }
            })
            .collect()
    }

    fn load_all_keys(&mut self) -> Result<()> {
        if !self.config_dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(&self.config_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("key") {
                match fs::read_to_string(&path) {
                    Ok(content) => {
                        if let Ok(config) = serde_json::from_str::<HardwareKeyConfig>(&content) {
                            self.keys.push(config);
                        }
                    }
                    Err(_) => continue,
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_hardware_key_creation() {
        let key = HardwareKey::create_new(
            KeyType::FileKey,
            "Test Key".to_string(),
            "test_passphrase"
        ).unwrap();

        assert!(!key.config.key_id.is_empty());
        assert!(key.is_unlocked());
    }

    #[test]
    fn test_challenge_response() {
        let key = HardwareKey::create_new(
            KeyType::FileKey,
            "Test Key".to_string(),
            "test_passphrase"
        ).unwrap();

        let challenge = HardwareKey::create_challenge();
        let response = key.sign_challenge(&challenge).unwrap();

        assert!(HardwareKey::verify_response(&challenge, &response).unwrap());
    }

    #[test]
    fn test_key_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let key_file = temp_dir.path().join("test.key");

        let original_key = HardwareKey::create_new(
            KeyType::FileKey,
            "Test Key".to_string(),
            "test_passphrase"
        ).unwrap();

        original_key.save_to_file(&key_file).unwrap();

        let loaded_key = HardwareKey::load_from_file(&key_file, "test_passphrase").unwrap();

        assert_eq!(original_key.config.key_id, loaded_key.config.key_id);
        assert_eq!(original_key.config.public_key, loaded_key.config.public_key);
    }

    #[test]
    fn test_key_manager() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = HardwareKeyManager::new(temp_dir.path()).unwrap();

        let key = HardwareKey::create_new(
            KeyType::FileKey,
            "Test Key".to_string(),
            "test_passphrase"
        ).unwrap();

        let key_id = key.config.key_id.clone();
        manager.add_key(&key).unwrap();

        assert_eq!(manager.list_keys().len(), 1);

        let retrieved_key = manager.get_key(&key_id, "test_passphrase").unwrap();
        assert_eq!(retrieved_key.config.key_id, key_id);
    }
}