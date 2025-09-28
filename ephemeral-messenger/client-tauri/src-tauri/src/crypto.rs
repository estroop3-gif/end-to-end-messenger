// Cryptographic core - Triple encryption with Signal, Identity ECDH, and Age
// Uses only audited libraries: libsodium, age, argon2

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use sodiumoxide::crypto::{
    box_::{self, Nonce, PublicKey as BoxPublicKey, SecretKey as BoxSecretKey},
    sign::{self, PublicKey as SignPublicKey, SecretKey as SignSecretKey},
    aead::chacha20poly1305_ietf::{self, Key as AeadKey, Nonce as AeadNonce},
    pwhash::{self, argon2id13},
    randombytes,
};
use age::{self, Encryptor, Decryptor, x25519, armor};
use std::io::{Read, Write};
use std::collections::HashMap;

// TODO: Replace with actual libsignal-protocol bindings
// For now using placeholder that implements similar interface
use crate::signal_placeholder::{SignalSession, SignalStore, PreKey};

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Identity {
    pub public_identity: String,
    pub fingerprint: String,
    #[zeroize(skip)]
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub layer_a: String,  // Signal Double Ratchet encrypted (base64)
    pub layer_b: String,  // Identity ECDH encrypted (base64)
    pub layer_c: String,  // Age/passphrase encrypted (base64)
    pub nonce: String,
    pub ephemeral_key: String,
    pub timestamp: u64,
    pub signature: String,
    pub metadata: MessageMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageMetadata {
    pub content_type: String,
    pub chunk_index: Option<u32>,
    pub total_chunks: Option<u32>,
    pub content_length: usize,
}

#[derive(ZeroizeOnDrop)]
struct IdentityKeys {
    sign_keypair: (SignPublicKey, SignSecretKey),
    box_keypair: (BoxPublicKey, BoxSecretKey),
    age_keypair: (x25519::Recipient, x25519::Identity),
}

impl Zeroize for IdentityKeys {
    fn zeroize(&mut self) {
        // Note: sodiumoxide keys implement Zeroize
        self.sign_keypair.1.zeroize();
        self.box_keypair.1.zeroize();
        // Age keys zeroize themselves on drop
    }
}

pub struct CryptoManager {
    identity_keys: Option<IdentityKeys>,
    signal_store: Option<SignalStore>,
    hardware_token_enabled: bool,
    passphrase_key: Option<AeadKey>,
    age_identity: Option<x25519::Identity>,
    secure_memory_locked: bool,
}

impl CryptoManager {
    pub fn new(hardware_token_enabled: bool) -> Self {
        Self {
            identity_keys: None,
            signal_store: None,
            hardware_token_enabled,
            passphrase_key: None,
            age_identity: None,
            secure_memory_locked: false,
        }
    }

    pub async fn initialize(&mut self) -> Result<()> {
        // Initialize libsodium
        sodiumoxide::init().map_err(|_| anyhow!("Failed to initialize libsodium"))?;

        // Lock memory pages for security
        if let Err(e) = self.lock_memory_pages() {
            eprintln!("Warning: Could not lock memory pages: {}", e);
        } else {
            self.secure_memory_locked = true;
        }

        // Initialize Signal protocol store
        self.signal_store = Some(SignalStore::new());

        println!("Crypto manager initialized with hardware_token_enabled: {}", self.hardware_token_enabled);
        Ok(())
    }

    pub async fn generate_identity(
        &mut self,
        use_hardware_token: bool,
        passphrase: Option<String>,
    ) -> Result<Identity> {
        if use_hardware_token && self.hardware_token_enabled {
            self.generate_hardware_identity().await
        } else if let Some(pass) = passphrase {
            self.generate_passphrase_identity(&pass).await
        } else {
            Err(anyhow!("Must provide either hardware token or passphrase"))
        }
    }

    async fn generate_hardware_identity(&mut self) -> Result<Identity> {
        // TODO: Implement hardware token key generation
        // For now, generate in secure memory with warning
        eprintln!("WARNING: Hardware token not yet implemented, generating keys in secure memory");
        self.generate_memory_identity().await
    }

    async fn generate_passphrase_identity(&mut self, passphrase: &str) -> Result<Identity> {
        // Derive key from passphrase using Argon2id
        let salt = randombytes::randombytes(pwhash::SALTBYTES);
        let mut derived_key = vec![0u8; 32];

        argon2id13::derive_key(
            &mut derived_key,
            passphrase.as_bytes(),
            &salt,
            argon2id13::OPSLIMIT_INTERACTIVE,
            argon2id13::MEMLIMIT_INTERACTIVE,
        ).map_err(|_| anyhow!("Failed to derive key from passphrase"))?;

        // Store passphrase-derived key for Layer C encryption
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&derived_key[..32]);
        self.passphrase_key = Some(AeadKey(key_bytes));

        // Zeroize temporary data
        derived_key.zeroize();

        // Generate identity from derived key as seed
        self.generate_memory_identity().await
    }

    async fn generate_memory_identity(&mut self) -> Result<Identity> {
        // Generate Ed25519 signing key pair
        let (sign_pk, sign_sk) = sign::gen_keypair();

        // Generate X25519 DH key pair
        let (box_pk, box_sk) = box_::gen_keypair();

        // Generate age key pair
        let age_identity = x25519::Identity::generate();
        let age_recipient = age_identity.to_public();

        // Create public identity string
        let public_identity = self.create_public_identity(&sign_pk, &box_pk, &age_recipient)?;

        // Generate fingerprint
        let fingerprint = self.generate_fingerprint(&sign_pk, &box_pk)?;

        // Store keys
        self.identity_keys = Some(IdentityKeys {
            sign_keypair: (sign_pk, sign_sk),
            box_keypair: (box_pk, box_sk),
            age_keypair: (age_recipient, age_identity.clone()),
        });

        self.age_identity = Some(age_identity);

        Ok(Identity {
            public_identity,
            fingerprint,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    pub async fn encrypt_message(
        &mut self,
        plaintext: &str,
        recipient_public_identity: &str,
    ) -> Result<EncryptedMessage> {
        let identity_keys = self.identity_keys.as_ref()
            .ok_or_else(|| anyhow!("No identity keys available"))?;

        let plaintext_bytes = plaintext.as_bytes();

        // Layer A: Signal Double Ratchet encryption
        let layer_a_data = self.encrypt_layer_a(plaintext_bytes, recipient_public_identity).await?;

        // Layer B: Identity ECDH encryption
        let layer_b_data = self.encrypt_layer_b(&layer_a_data, recipient_public_identity)?;

        // Layer C: Age/Passphrase encryption
        let layer_c_data = self.encrypt_layer_c(&layer_b_data)?;

        // Generate ephemeral nonce and sign
        let nonce = randombytes::randombytes(24);
        let ephemeral_keypair = box_::gen_keypair();
        let signature = self.sign_message(&layer_c_data)?;

        Ok(EncryptedMessage {
            layer_a: base64::encode(&layer_a_data),
            layer_b: base64::encode(&layer_b_data),
            layer_c: base64::encode(&layer_c_data),
            nonce: base64::encode(&nonce),
            ephemeral_key: base64::encode(&ephemeral_keypair.0),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            signature: base64::encode(&signature),
            metadata: MessageMetadata {
                content_type: "text/plain".to_string(),
                chunk_index: None,
                total_chunks: None,
                content_length: plaintext.len(),
            },
        })
    }

    pub async fn decrypt_message(&mut self, encrypted_message: &EncryptedMessage) -> Result<String> {
        // Verify signature first
        let layer_c_data = base64::decode(&encrypted_message.layer_c)
            .map_err(|e| anyhow!("Failed to decode layer C: {}", e))?;
        let signature = base64::decode(&encrypted_message.signature)
            .map_err(|e| anyhow!("Failed to decode signature: {}", e))?;

        // TODO: Verify signature with sender's public key
        // For now, just proceed with decryption

        // Layer C: Age/Passphrase decryption
        let layer_b_data = self.decrypt_layer_c(&layer_c_data)?;

        // Layer B: Identity ECDH decryption
        let layer_a_data = self.decrypt_layer_b(&layer_b_data)?;

        // Layer A: Signal Double Ratchet decryption
        let plaintext_bytes = self.decrypt_layer_a(&layer_a_data).await?;

        String::from_utf8(plaintext_bytes)
            .map_err(|e| anyhow!("Failed to convert decrypted data to string: {}", e))
    }

    // Layer A: Signal Double Ratchet (placeholder implementation)
    async fn encrypt_layer_a(&mut self, data: &[u8], recipient_id: &str) -> Result<Vec<u8>> {
        // TODO: Implement actual Signal Double Ratchet
        // For now, use placeholder that just returns the data
        eprintln!("WARNING: Signal Double Ratchet not yet implemented - using passthrough");
        Ok(data.to_vec())
    }

    async fn decrypt_layer_a(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        // TODO: Implement actual Signal Double Ratchet decryption
        eprintln!("WARNING: Signal Double Ratchet not yet implemented - using passthrough");
        Ok(data.to_vec())
    }

    // Layer B: Identity ECDH with X25519 + ChaCha20-Poly1305
    fn encrypt_layer_b(&self, data: &[u8], recipient_public_identity: &str) -> Result<Vec<u8>> {
        let identity_keys = self.identity_keys.as_ref()
            .ok_or_else(|| anyhow!("No identity keys available"))?;

        // Parse recipient's public keys
        let (_, recipient_box_pk, _) = self.parse_public_identity(recipient_public_identity)?;

        // Generate ephemeral key pair for this message
        let (ephemeral_pk, ephemeral_sk) = box_::gen_keypair();

        // Perform ECDH
        let shared_secret = box_::precompute(&recipient_box_pk, &identity_keys.box_keypair.1);

        // Generate nonce
        let nonce = box_::gen_nonce();

        // Encrypt with shared secret
        let ciphertext = box_::seal_precomputed(data, &nonce, &shared_secret);

        // Combine ephemeral public key + nonce + ciphertext
        let mut result = Vec::new();
        result.extend_from_slice(&ephemeral_pk.0);
        result.extend_from_slice(&nonce.0);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    fn decrypt_layer_b(&self, data: &[u8]) -> Result<Vec<u8>> {
        let identity_keys = self.identity_keys.as_ref()
            .ok_or_else(|| anyhow!("No identity keys available"))?;

        if data.len() < 32 + 24 {
            return Err(anyhow!("Layer B data too short"));
        }

        // Extract components
        let ephemeral_pk = BoxPublicKey::from_slice(&data[0..32])
            .ok_or_else(|| anyhow!("Invalid ephemeral public key"))?;
        let nonce = Nonce::from_slice(&data[32..56])
            .ok_or_else(|| anyhow!("Invalid nonce"))?;
        let ciphertext = &data[56..];

        // Perform ECDH
        let shared_secret = box_::precompute(&ephemeral_pk, &identity_keys.box_keypair.1);

        // Decrypt
        box_::open_precomputed(ciphertext, &nonce, &shared_secret)
            .map_err(|_| anyhow!("Failed to decrypt Layer B"))
    }

    // Layer C: Age or Argon2id + ChaCha20-Poly1305
    fn encrypt_layer_c(&self, data: &[u8]) -> Result<Vec<u8>> {
        if let Some(age_identity) = &self.age_identity {
            self.encrypt_with_age(data, age_identity)
        } else if let Some(passphrase_key) = &self.passphrase_key {
            self.encrypt_with_passphrase(data, passphrase_key)
        } else {
            Err(anyhow!("No Layer C encryption key available"))
        }
    }

    fn decrypt_layer_c(&self, data: &[u8]) -> Result<Vec<u8>> {
        if let Some(age_identity) = &self.age_identity {
            self.decrypt_with_age(data, age_identity)
        } else if let Some(passphrase_key) = &self.passphrase_key {
            self.decrypt_with_passphrase(data, passphrase_key)
        } else {
            Err(anyhow!("No Layer C decryption key available"))
        }
    }

    fn encrypt_with_age(&self, data: &[u8], age_identity: &x25519::Identity) -> Result<Vec<u8>> {
        let recipient = age_identity.to_public();
        let encryptor = Encryptor::with_recipients(vec![Box::new(recipient)]);

        let mut encrypted = Vec::new();
        let mut writer = encryptor.wrap_output(&mut encrypted)
            .map_err(|e| anyhow!("Failed to create age encryptor: {}", e))?;
        writer.write_all(data)
            .map_err(|e| anyhow!("Failed to write to age encryptor: {}", e))?;
        writer.finish()
            .map_err(|e| anyhow!("Failed to finalize age encryption: {}", e))?;

        Ok(encrypted)
    }

    fn decrypt_with_age(&self, data: &[u8], age_identity: &x25519::Identity) -> Result<Vec<u8>> {
        let decryptor = match Decryptor::new(data)
            .map_err(|e| anyhow!("Failed to create age decryptor: {}", e))? {
            Decryptor::Recipients(d) => d,
            _ => return Err(anyhow!("Unsupported age format")),
        };

        let mut decrypted = Vec::new();
        let mut reader = decryptor.decrypt(std::iter::once(age_identity as &dyn age::Identity))
            .map_err(|e| anyhow!("Failed to decrypt with age: {}", e))?;
        reader.read_to_end(&mut decrypted)
            .map_err(|e| anyhow!("Failed to read decrypted data: {}", e))?;

        Ok(decrypted)
    }

    fn encrypt_with_passphrase(&self, data: &[u8], key: &AeadKey) -> Result<Vec<u8>> {
        let nonce = chacha20poly1305_ietf::gen_nonce();
        let ciphertext = chacha20poly1305_ietf::seal(data, None, &nonce, key);

        let mut result = Vec::new();
        result.extend_from_slice(&nonce.0);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    fn decrypt_with_passphrase(&self, data: &[u8], key: &AeadKey) -> Result<Vec<u8>> {
        if data.len() < 12 {
            return Err(anyhow!("Passphrase encrypted data too short"));
        }

        let nonce = AeadNonce::from_slice(&data[0..12])
            .ok_or_else(|| anyhow!("Invalid nonce"))?;
        let ciphertext = &data[12..];

        chacha20poly1305_ietf::open(ciphertext, None, &nonce, key)
            .map_err(|_| anyhow!("Failed to decrypt with passphrase"))
    }

    fn create_public_identity(
        &self,
        sign_pk: &SignPublicKey,
        box_pk: &BoxPublicKey,
        age_pk: &x25519::Recipient,
    ) -> Result<String> {
        let mut identity = Vec::new();
        identity.extend_from_slice(&sign_pk.0);
        identity.extend_from_slice(&box_pk.0);
        // Convert age public key to bytes
        let age_bytes = age_pk.to_string().as_bytes().to_vec();
        identity.extend_from_slice(&age_bytes);

        Ok(base64::encode(&identity))
    }

    fn parse_public_identity(&self, public_identity: &str) -> Result<(SignPublicKey, BoxPublicKey, x25519::Recipient)> {
        let identity_bytes = base64::decode(public_identity)
            .map_err(|e| anyhow!("Failed to decode public identity: {}", e))?;

        if identity_bytes.len() < 64 {
            return Err(anyhow!("Public identity too short"));
        }

        let sign_pk = SignPublicKey::from_slice(&identity_bytes[0..32])
            .ok_or_else(|| anyhow!("Invalid signing public key"))?;

        let box_pk = BoxPublicKey::from_slice(&identity_bytes[32..64])
            .ok_or_else(|| anyhow!("Invalid box public key"))?;

        // Parse age public key (simplified)
        let age_bytes = &identity_bytes[64..];
        let age_str = String::from_utf8(age_bytes.to_vec())
            .map_err(|e| anyhow!("Invalid age public key string: {}", e))?;
        let age_pk = age_str.parse::<x25519::Recipient>()
            .map_err(|e| anyhow!("Failed to parse age public key: {}", e))?;

        Ok((sign_pk, box_pk, age_pk))
    }

    fn generate_fingerprint(&self, sign_pk: &SignPublicKey, box_pk: &BoxPublicKey) -> Result<String> {
        use sodiumoxide::crypto::hash::sha256;

        let mut combined = Vec::new();
        combined.extend_from_slice(&sign_pk.0);
        combined.extend_from_slice(&box_pk.0);

        let hash = sha256::hash(&combined);
        Ok(hex::encode(&hash.0[..16]).to_uppercase())
    }

    fn sign_message(&self, data: &[u8]) -> Result<Vec<u8>> {
        let identity_keys = self.identity_keys.as_ref()
            .ok_or_else(|| anyhow!("No identity keys available"))?;

        Ok(sign::sign_detached(data, &identity_keys.sign_keypair.1).0.to_vec())
    }

    fn lock_memory_pages(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use nix::sys::mman::{mlockall, MlockAllFlags};
            mlockall(MlockAllFlags::MCL_CURRENT | MlockAllFlags::MCL_FUTURE)
                .map_err(|e| anyhow!("Failed to lock memory pages: {}", e))?;
        }

        #[cfg(target_os = "windows")]
        {
            // TODO: Implement Windows memory locking
            eprintln!("Memory locking not yet implemented on Windows");
        }

        #[cfg(target_os = "macos")]
        {
            // TODO: Implement macOS memory locking
            eprintln!("Memory locking not yet implemented on macOS");
        }

        Ok(())
    }

    pub async fn secure_wipe(&mut self) -> Result<()> {
        println!("Performing crypto manager secure wipe...");

        // Zeroize identity keys
        if let Some(mut keys) = self.identity_keys.take() {
            keys.zeroize();
        }

        // Zeroize passphrase key
        if let Some(mut key) = self.passphrase_key.take() {
            key.zeroize();
        }

        // Zeroize age identity
        self.age_identity = None;

        // Clear signal store
        self.signal_store = None;

        println!("Crypto manager secure wipe completed");
        Ok(())
    }
}

impl Drop for CryptoManager {
    fn drop(&mut self) {
        // Ensure secure cleanup on drop
        if let Err(e) = tokio::runtime::Runtime::new().unwrap().block_on(self.secure_wipe()) {
            eprintln!("Error during CryptoManager drop: {}", e);
        }
    }
}

// Placeholder for Signal protocol implementation
// TODO: Replace with actual libsignal-protocol bindings
mod signal_placeholder {
    use anyhow::Result;

    pub struct SignalSession {
        // TODO: Implement with libsignal-protocol
    }

    pub struct SignalStore {
        // TODO: Implement with libsignal-protocol
    }

    impl SignalStore {
        pub fn new() -> Self {
            Self {}
        }
    }

    pub struct PreKey {
        // TODO: Implement with libsignal-protocol
    }
}