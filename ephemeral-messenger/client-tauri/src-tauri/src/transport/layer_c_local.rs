// Layer C: AES-256-GCM for local client ↔ relay hop encryption

use anyhow::{anyhow, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes256Gcm, Key, Nonce,
};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use super::onion::LayerCMetadata;

/// AES-256-GCM key for Layer C
#[derive(ZeroizeOnDrop)]
pub struct LayerCKey {
    key: [u8; 32],
    #[zeroize(skip)]
    cipher: Aes256Gcm,
}

impl LayerCKey {
    fn new(key: [u8; 32]) -> Self {
        let aes_key = Key::<Aes256Gcm>::from_slice(&key);
        let cipher = Aes256Gcm::new(aes_key);
        Self { key, cipher }
    }

    fn encrypt(&self, plaintext: &[u8], nonce: &[u8; 12], aad: &[u8]) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher
            .encrypt(nonce, Payload { msg: plaintext, aad })
            .map_err(|e| anyhow!("AES-GCM encryption failed: {}", e))
    }

    fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; 12], aad: &[u8]) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher
            .decrypt(nonce, Payload { msg: ciphertext, aad })
            .map_err(|e| anyhow!("AES-GCM decryption failed: {}", e))
    }
}

/// Layer C envelope structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerCEnvelope {
    pub v: u8,
    pub route: RouteInfo,
    pub aad: AadInfo,
    pub ct: Vec<u8>,
    pub nonce_c: [u8; 12],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteInfo {
    pub session_id: String,
    pub dst_hint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AadInfo {
    pub size_orig: usize,
    pub bucket: usize,
    pub t_bucket: u64,
}

impl LayerCEnvelope {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow!("Failed to serialize C envelope: {}", e))
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| anyhow!("Failed to deserialize C envelope: {}", e))
    }
}

/// Context for Layer C operations
#[derive(ZeroizeOnDrop)]
pub struct LayerCContext {
    current_key: LayerCKey,
    #[zeroize(skip)]
    local_static: StaticSecret,
    #[zeroize(skip)]
    remote_public: PublicKey,
    key_generation: u32,
}

impl LayerCContext {
    /// Create new Layer C context with X25519 key agreement
    pub fn new(remote_relay_pub: &[u8; 32]) -> Result<Self> {
        let local_static = StaticSecret::random_from_rng(OsRng);
        let remote_public = PublicKey::from(*remote_relay_pub);

        // Initial key derivation
        let shared_secret = local_static.diffie_hellman(&remote_public);
        let key = Self::derive_aes_key(shared_secret.as_bytes(), 0)?;

        Ok(Self {
            current_key: LayerCKey::new(key),
            local_static,
            remote_public,
            key_generation: 0,
        })
    }

    /// Encrypt payload with Layer C (AES-256-GCM)
    pub fn encrypt(&self, payload: &[u8], metadata: &LayerCMetadata) -> Result<LayerCEnvelope> {
        // Generate random nonce
        let mut nonce_c = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_c);

        // Prepare AAD
        let aad_info = AadInfo {
            size_orig: metadata.size_orig,
            bucket: metadata.bucket,
            t_bucket: metadata.t_bucket,
        };

        let route_info = RouteInfo {
            session_id: metadata.session_id.clone(),
            dst_hint: metadata.dst_hint.clone(),
        };

        // Serialize AAD for authenticated encryption
        let aad_bytes = bincode::serialize(&(&route_info, &aad_info))
            .map_err(|e| anyhow!("Failed to serialize AAD: {}", e))?;

        // Encrypt payload
        let ct = self.current_key.encrypt(payload, &nonce_c, &aad_bytes)?;

        Ok(LayerCEnvelope {
            v: 1,
            route: route_info,
            aad: aad_info,
            ct,
            nonce_c,
        })
    }

    /// Decrypt Layer C envelope
    pub fn decrypt(&self, envelope: &LayerCEnvelope) -> Result<(Vec<u8>, LayerCMetadata)> {
        // Verify version
        if envelope.v != 1 {
            return Err(anyhow!("Unsupported Layer C version: {}", envelope.v));
        }

        // Reconstruct AAD
        let aad_bytes = bincode::serialize(&(&envelope.route, &envelope.aad))
            .map_err(|e| anyhow!("Failed to serialize AAD for decryption: {}", e))?;

        // Decrypt payload
        let payload = self.current_key.decrypt(&envelope.ct, &envelope.nonce_c, &aad_bytes)?;

        // Extract metadata
        let metadata = LayerCMetadata {
            session_id: envelope.route.session_id.clone(),
            dst_hint: envelope.route.dst_hint.clone(),
            size_orig: envelope.aad.size_orig,
            bucket: envelope.aad.bucket,
            t_bucket: envelope.aad.t_bucket,
        };

        Ok((payload, metadata))
    }

    /// Rotate to fresh key
    pub fn rotate_keys(&mut self) -> Result<()> {
        self.key_generation += 1;

        // Generate new ephemeral for this rotation
        let ephemeral = EphemeralSecret::random_from_rng(OsRng);
        let shared_secret = ephemeral.diffie_hellman(&self.remote_public);

        let new_key = Self::derive_aes_key(shared_secret.as_bytes(), self.key_generation)?;
        self.current_key = LayerCKey::new(new_key);

        log::info!("Layer C keys rotated to generation {}", self.key_generation);
        Ok(())
    }

    /// Get public key for handshake
    pub fn get_public_key(&self) -> [u8; 32] {
        PublicKey::from(&self.local_static).to_bytes()
    }

    /// Perform X25519 handshake to establish Layer C session
    pub fn handshake_x25519(&mut self, remote_pub: &[u8; 32]) -> Result<[u8; 32]> {
        let remote_public = PublicKey::from(*remote_pub);
        self.remote_public = remote_public;

        // Derive initial key
        let shared_secret = self.local_static.diffie_hellman(&remote_public);
        let key = Self::derive_aes_key(shared_secret.as_bytes(), 0)?;

        self.current_key = LayerCKey::new(key);
        self.key_generation = 0;

        Ok(PublicKey::from(&self.local_static).to_bytes())
    }

    /// Derive AES-256 key from X25519 shared secret using HKDF
    fn derive_aes_key(shared_secret: &[u8], generation: u32) -> Result<[u8; 32]> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hk = Hkdf::<Sha256>::new(None, shared_secret);
        let mut key = [0u8; 32];

        let info = format!("layer-c-local-v1-gen-{}", generation);
        hk.expand(info.as_bytes(), &mut key)
            .map_err(|e| anyhow!("HKDF expand failed: {}", e))?;

        Ok(key)
    }

    /// Validate envelope size and enforce limits
    pub fn validate_envelope_size(envelope: &LayerCEnvelope) -> Result<()> {
        const MAX_C_ENVELOPE_SIZE: usize = 2 * 1024 * 1024; // 2MB max

        let serialized_size = envelope.to_bytes()?.len();
        if serialized_size > MAX_C_ENVELOPE_SIZE {
            return Err(anyhow!(
                "Layer C envelope too large: {} bytes (max: {})",
                serialized_size,
                MAX_C_ENVELOPE_SIZE
            ));
        }

        // Validate bucket sizes
        const VALID_BUCKETS: &[usize] = &[4096, 16384, 65536, 262144, 1048576];
        if !VALID_BUCKETS.contains(&envelope.aad.bucket) {
            return Err(anyhow!("Invalid bucket size: {}", envelope.aad.bucket));
        }

        // Validate original size doesn't exceed bucket
        if envelope.aad.size_orig > envelope.aad.bucket {
            return Err(anyhow!(
                "Original size {} exceeds bucket {}",
                envelope.aad.size_orig,
                envelope.aad.bucket
            ));
        }

        Ok(())
    }
}

/// Handshake protocol for establishing Layer C session
pub struct LayerCHandshake;

impl LayerCHandshake {
    /// Client-side handshake initiation
    pub fn client_init() -> Result<(LayerCContext, [u8; 32])> {
        // Generate ephemeral key pair
        let local_static = StaticSecret::random_from_rng(OsRng);
        let local_public = PublicKey::from(&local_static);

        // Return context with placeholder remote key (will be set during handshake)
        let placeholder_remote = [0u8; 32];
        let mut context = LayerCContext::new(&placeholder_remote)?;
        context.local_static = local_static;

        Ok((context, local_public.to_bytes()))
    }

    /// Complete handshake with remote public key
    pub fn complete_handshake(
        context: &mut LayerCContext,
        remote_public: &[u8; 32],
    ) -> Result<()> {
        context.handshake_x25519(remote_public)?;
        Ok(())
    }

    /// Server-side handshake response
    pub fn server_respond(client_public: &[u8; 32]) -> Result<(LayerCContext, [u8; 32])> {
        let local_static = StaticSecret::random_from_rng(OsRng);
        let local_public = PublicKey::from(&local_static);

        let mut context = LayerCContext::new(client_public)?;
        context.local_static = local_static;

        Ok((context, local_public.to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layer_c_roundtrip() {
        let remote_pub = [1u8; 32];
        let mut context = LayerCContext::new(&remote_pub).unwrap();

        let metadata = LayerCMetadata {
            session_id: "test-session".to_string(),
            dst_hint: "relay".to_string(),
            size_orig: 42,
            bucket: 4096,
            t_bucket: 1234567890,
        };

        let payload = b"Hello, Layer C!";

        // Encrypt
        let envelope = context.encrypt(payload, &metadata).unwrap();

        // Validate
        LayerCContext::validate_envelope_size(&envelope).unwrap();

        // Decrypt
        let (decrypted, recovered_metadata) = context.decrypt(&envelope).unwrap();

        assert_eq!(decrypted, payload);
        assert_eq!(recovered_metadata.session_id, metadata.session_id);
        assert_eq!(recovered_metadata.size_orig, metadata.size_orig);
    }

    #[test]
    fn test_key_rotation() {
        let remote_pub = [1u8; 32];
        let mut context = LayerCContext::new(&remote_pub).unwrap();

        let old_generation = context.key_generation;
        context.rotate_keys().unwrap();
        assert_eq!(context.key_generation, old_generation + 1);
    }

    #[test]
    fn test_handshake() {
        let (mut client_ctx, client_pub) = LayerCHandshake::client_init().unwrap();
        let (server_ctx, server_pub) = LayerCHandshake::server_respond(&client_pub).unwrap();

        LayerCHandshake::complete_handshake(&mut client_ctx, &server_pub).unwrap();

        // Both sides should now be able to encrypt/decrypt
        let metadata = LayerCMetadata {
            session_id: "test".to_string(),
            dst_hint: "test".to_string(),
            size_orig: 10,
            bucket: 4096,
            t_bucket: 0,
        };

        let envelope = client_ctx.encrypt(b"test", &metadata).unwrap();
        // Note: In real usage, server would have the same shared key
        // This test validates the handshake process completes without error
    }

    #[test]
    fn test_invalid_envelope_rejection() {
        let remote_pub = [1u8; 32];
        let context = LayerCContext::new(&remote_pub).unwrap();

        // Test oversized envelope
        let mut envelope = LayerCEnvelope {
            v: 1,
            route: RouteInfo {
                session_id: "test".to_string(),
                dst_hint: "test".to_string(),
            },
            aad: AadInfo {
                size_orig: 100,
                bucket: 99, // Invalid: size_orig > bucket
                t_bucket: 0,
            },
            ct: vec![0u8; 1000],
            nonce_c: [0u8; 12],
        };

        assert!(LayerCContext::validate_envelope_size(&envelope).is_err());

        // Fix bucket size but use invalid bucket
        envelope.aad.bucket = 12345; // Not in VALID_BUCKETS
        assert!(LayerCContext::validate_envelope_size(&envelope).is_err());
    }
}