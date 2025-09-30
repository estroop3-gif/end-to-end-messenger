// Layer B: X25519 + ChaCha20-Poly1305 for inter-relay transport encryption

use anyhow::{anyhow, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use super::onion::LayerBMetadata;

/// ChaCha20-Poly1305 key for Layer B
#[derive(ZeroizeOnDrop)]
pub struct LayerBKey {
    key: [u8; 32],
    cipher: ChaCha20Poly1305,
}

impl LayerBKey {
    fn new(key: [u8; 32]) -> Self {
        let chacha_key = Key::from_slice(&key);
        let cipher = ChaCha20Poly1305::new(chacha_key);
        Self { key, cipher }
    }

    fn encrypt(&self, plaintext: &[u8], nonce: &[u8; 12], aad: &[u8]) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher
            .encrypt(nonce, chacha20poly1305::aead::Payload { msg: plaintext, aad })
            .map_err(|e| anyhow!("ChaCha20-Poly1305 encryption failed: {}", e))
    }

    fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; 12], aad: &[u8]) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher
            .decrypt(nonce, chacha20poly1305::aead::Payload { msg: ciphertext, aad })
            .map_err(|e| anyhow!("ChaCha20-Poly1305 decryption failed: {}", e))
    }
}

/// Layer B envelope structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerBEnvelope {
    pub v: u8,
    pub sess: SessionInfo,
    pub aad: LayerBAad,
    pub ct: Vec<u8>,
    pub nonce_b: [u8; 12],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub eph_pub: [u8; 32],
    pub peer_id_hint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerBAad {
    pub hop: String,
    pub bucket_size: usize,
    pub original_size: usize,
    pub timestamp: u64,
}

impl LayerBEnvelope {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow!("Failed to serialize B envelope: {}", e))
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| anyhow!("Failed to deserialize B envelope: {}", e))
    }
}

/// Context for Layer B operations
#[derive(ZeroizeOnDrop)]
pub struct LayerBContext {
    send_key: LayerBKey,
    recv_key: Option<LayerBKey>,
    #[zeroize(skip)]
    local_ephemeral: EphemeralSecret,
    #[zeroize(skip)]
    local_ephemeral_pub: PublicKey,
    #[zeroize(skip)]
    remote_public: PublicKey,
    #[zeroize(skip)]
    session_direction: SessionDirection,
    key_generation: u32,
}

#[derive(Debug, Clone)]
pub enum SessionDirection {
    ClientToShuttle,
    ShuttleToReceiver,
}

impl LayerBContext {
    /// Create new Layer B context for client→shuttle direction
    pub fn new(shuttle_pub: &[u8; 32]) -> Result<Self> {
        let local_ephemeral = EphemeralSecret::random_from_rng(OsRng);
        let local_ephemeral_pub = PublicKey::from(&local_ephemeral);
        let remote_public = PublicKey::from(*shuttle_pub);

        // Derive keys for client→shuttle direction
        let shared_secret = local_ephemeral.diffie_hellman(&remote_public);
        let send_key = Self::derive_chacha_key(shared_secret.as_bytes(), "send", 0)?;

        // Generate new ephemeral for storage (since the previous one was consumed)
        let new_ephemeral = EphemeralSecret::random_from_rng(OsRng);

        Ok(Self {
            send_key: LayerBKey::new(send_key),
            recv_key: None, // Will be set up for receive direction if needed
            local_ephemeral: new_ephemeral,
            local_ephemeral_pub,
            remote_public,
            session_direction: SessionDirection::ClientToShuttle,
            key_generation: 0,
        })
    }

    /// Create Layer B context for shuttle→receiver direction
    pub fn new_receive_context(
        sender_eph_pub: &[u8; 32],
        receiver_static_priv: &[u8; 32],
    ) -> Result<Self> {
        let local_ephemeral = EphemeralSecret::random_from_rng(OsRng);
        let local_ephemeral_pub = PublicKey::from(&local_ephemeral);
        let sender_public = PublicKey::from(*sender_eph_pub);

        // Use receiver's static key for this direction
        let receiver_static = StaticSecret::from(*receiver_static_priv);
        let shared_secret = receiver_static.diffie_hellman(&sender_public);
        let recv_key = Self::derive_chacha_key(shared_secret.as_bytes(), "recv", 0)?;

        Ok(Self {
            send_key: LayerBKey::new([0u8; 32]), // Placeholder
            recv_key: Some(LayerBKey::new(recv_key)),
            local_ephemeral,
            local_ephemeral_pub,
            remote_public: sender_public,
            session_direction: SessionDirection::ShuttleToReceiver,
            key_generation: 0,
        })
    }

    /// Encrypt payload with Layer B (ChaCha20-Poly1305)
    pub fn encrypt(&self, payload: &[u8], metadata: &LayerBMetadata) -> Result<LayerBEnvelope> {
        // Generate random nonce
        let mut nonce_b = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_b);

        // Prepare session info
        let sess_info = SessionInfo {
            eph_pub: self.local_ephemeral_pub.to_bytes(),
            peer_id_hint: self.get_peer_hint(),
        };

        // Prepare AAD
        let aad_info = LayerBAad {
            hop: metadata.hop.clone(),
            bucket_size: metadata.bucket_size,
            original_size: metadata.original_size,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        // Serialize AAD for authenticated encryption
        let aad_bytes = bincode::serialize(&(&sess_info, &aad_info))
            .map_err(|e| anyhow!("Failed to serialize B-layer AAD: {}", e))?;

        // Encrypt payload
        let ct = self.send_key.encrypt(payload, &nonce_b, &aad_bytes)?;

        Ok(LayerBEnvelope {
            v: 1,
            sess: sess_info,
            aad: aad_info,
            ct,
            nonce_b,
        })
    }

    /// Decrypt Layer B envelope
    pub fn decrypt(&self, envelope: &LayerBEnvelope) -> Result<(Vec<u8>, LayerBMetadata)> {
        // Verify version
        if envelope.v != 1 {
            return Err(anyhow!("Unsupported Layer B version: {}", envelope.v));
        }

        // Select appropriate key
        let key = match self.session_direction {
            SessionDirection::ClientToShuttle => &self.send_key,
            SessionDirection::ShuttleToReceiver => {
                self.recv_key.as_ref()
                    .ok_or_else(|| anyhow!("No receive key configured"))?
            }
        };

        // Reconstruct AAD
        let aad_bytes = bincode::serialize(&(&envelope.sess, &envelope.aad))
            .map_err(|e| anyhow!("Failed to serialize AAD for B-layer decryption: {}", e))?;

        // Decrypt payload
        let payload = key.decrypt(&envelope.ct, &envelope.nonce_b, &aad_bytes)?;

        // Extract metadata
        let metadata = LayerBMetadata {
            hop: envelope.aad.hop.clone(),
            bucket_size: envelope.aad.bucket_size,
            original_size: envelope.aad.original_size,
        };

        Ok((payload, metadata))
    }

    /// Rotate keys for new session
    pub fn rotate_keys(&mut self) -> Result<()> {
        self.key_generation += 1;

        // Generate new ephemeral for key derivation
        let ephemeral_for_derivation = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_pub = PublicKey::from(&ephemeral_for_derivation);

        // Derive new keys
        let shared_secret = ephemeral_for_derivation.diffie_hellman(&self.remote_public);

        // Generate another ephemeral for storage (since the previous one was consumed)
        self.local_ephemeral = EphemeralSecret::random_from_rng(OsRng);
        self.local_ephemeral_pub = ephemeral_pub;
        let new_send_key = Self::derive_chacha_key(
            shared_secret.as_bytes(),
            "send",
            self.key_generation,
        )?;

        self.send_key = LayerBKey::new(new_send_key);

        // If we have a receive key, rotate it too
        if self.recv_key.is_some() {
            let new_recv_key = Self::derive_chacha_key(
                shared_secret.as_bytes(),
                "recv",
                self.key_generation,
            )?;
            self.recv_key = Some(LayerBKey::new(new_recv_key));
        }

        log::info!("Layer B keys rotated to generation {}", self.key_generation);
        Ok(())
    }

    /// Get ephemeral public key for current session
    pub fn get_ephemeral_public(&self) -> [u8; 32] {
        self.local_ephemeral_pub.to_bytes()
    }

    /// Derive ChaCha20 key from X25519 shared secret using HKDF
    fn derive_chacha_key(
        shared_secret: &[u8],
        direction: &str,
        generation: u32,
    ) -> Result<[u8; 32]> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hk = Hkdf::<Sha256>::new(None, shared_secret);
        let mut key = [0u8; 32];

        let info = format!("layer-b-interrelay-{}-v1-gen-{}", direction, generation);
        hk.expand(info.as_bytes(), &mut key)
            .map_err(|e| anyhow!("HKDF expand failed: {}", e))?;

        Ok(key)
    }

    /// Get peer hint for session info
    fn get_peer_hint(&self) -> String {
        match self.session_direction {
            SessionDirection::ClientToShuttle => "shuttle".to_string(),
            SessionDirection::ShuttleToReceiver => "receiver".to_string(),
        }
    }

    /// Validate envelope size and timing constraints
    pub fn validate_envelope(&self, envelope: &LayerBEnvelope) -> Result<()> {
        const MAX_B_ENVELOPE_SIZE: usize = 1024 * 1024; // 1MB max
        const MAX_AGE_SECONDS: u64 = 300; // 5 minutes

        // Size validation
        let serialized_size = envelope.to_bytes()?.len();
        if serialized_size > MAX_B_ENVELOPE_SIZE {
            return Err(anyhow!(
                "Layer B envelope too large: {} bytes (max: {})",
                serialized_size,
                MAX_B_ENVELOPE_SIZE
            ));
        }

        // Timing validation
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now.saturating_sub(envelope.aad.timestamp) > MAX_AGE_SECONDS {
            return Err(anyhow!("Layer B envelope too old"));
        }

        // Future timestamp check (allow small clock skew)
        if envelope.aad.timestamp > now + 60 {
            return Err(anyhow!("Layer B envelope timestamp too far in future"));
        }

        // Validate hop direction
        match self.session_direction {
            SessionDirection::ClientToShuttle => {
                if envelope.aad.hop != "client→shuttle" {
                    return Err(anyhow!("Invalid hop direction for client→shuttle"));
                }
            }
            SessionDirection::ShuttleToReceiver => {
                if envelope.aad.hop != "shuttle→receiver" {
                    return Err(anyhow!("Invalid hop direction for shuttle→receiver"));
                }
            }
        }

        Ok(())
    }

    /// Create Layer B context from received ephemeral public key
    pub fn from_ephemeral_exchange(
        remote_eph_pub: &[u8; 32],
        local_static_priv: &[u8; 32],
        direction: SessionDirection,
    ) -> Result<Self> {
        let local_static = StaticSecret::from(*local_static_priv);
        let remote_public = PublicKey::from(*remote_eph_pub);

        // Generate new ephemeral for this session
        let local_ephemeral = EphemeralSecret::random_from_rng(OsRng);
        let local_ephemeral_pub = PublicKey::from(&local_ephemeral);

        // Derive shared secret
        let shared_secret = local_static.diffie_hellman(&remote_public);

        // Derive keys based on direction
        let (send_key, recv_key) = match direction {
            SessionDirection::ClientToShuttle => {
                let send = Self::derive_chacha_key(shared_secret.as_bytes(), "send", 0)?;
                (LayerBKey::new(send), None)
            }
            SessionDirection::ShuttleToReceiver => {
                let recv = Self::derive_chacha_key(shared_secret.as_bytes(), "recv", 0)?;
                (LayerBKey::new([0u8; 32]), Some(LayerBKey::new(recv)))
            }
        };

        Ok(Self {
            send_key,
            recv_key,
            local_ephemeral,
            local_ephemeral_pub,
            remote_public,
            session_direction: direction,
            key_generation: 0,
        })
    }
}

/// Utilities for Layer B key management
pub struct LayerBKeyManager;

impl LayerBKeyManager {
    /// Generate long-term static key for relay
    pub fn generate_relay_static_key() -> [u8; 32] {
        let static_secret = StaticSecret::random_from_rng(OsRng);
        PublicKey::from(&static_secret).to_bytes()
    }

    /// Perform ephemeral key exchange for new session
    pub fn ephemeral_exchange(
        local_static: &[u8; 32],
        remote_ephemeral: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32])> {
        let local_static = StaticSecret::from(*local_static);
        let local_ephemeral = EphemeralSecret::random_from_rng(OsRng);
        let local_ephemeral_pub = PublicKey::from(&local_ephemeral);

        let remote_public = PublicKey::from(*remote_ephemeral);
        let shared_secret = local_static.diffie_hellman(&remote_public);

        Ok((local_ephemeral_pub.to_bytes(), shared_secret.to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layer_b_roundtrip() {
        let shuttle_pub = [2u8; 32];
        let context = LayerBContext::new(&shuttle_pub).unwrap();

        let metadata = LayerBMetadata {
            hop: "client→shuttle".to_string(),
            bucket_size: 4096,
            original_size: 42,
        };

        let payload = b"Hello, Layer B!";

        // Encrypt
        let envelope = context.encrypt(payload, &metadata).unwrap();

        // Validate
        context.validate_envelope(&envelope).unwrap();

        // Decrypt (note: in real usage, receiving side would have corresponding key)
        let (decrypted, recovered_metadata) = context.decrypt(&envelope).unwrap();

        assert_eq!(decrypted, payload);
        assert_eq!(recovered_metadata.hop, metadata.hop);
        assert_eq!(recovered_metadata.bucket_size, metadata.bucket_size);
    }

    #[test]
    fn test_key_rotation() {
        let shuttle_pub = [2u8; 32];
        let mut context = LayerBContext::new(&shuttle_pub).unwrap();

        let old_generation = context.key_generation;
        context.rotate_keys().unwrap();
        assert_eq!(context.key_generation, old_generation + 1);
    }

    #[test]
    fn test_ephemeral_key_exchange() {
        let local_static = [3u8; 32];
        let remote_ephemeral = [4u8; 32];

        let (local_eph_pub, shared_secret) = LayerBKeyManager::ephemeral_exchange(
            &local_static,
            &remote_ephemeral,
        ).unwrap();

        assert_eq!(local_eph_pub.len(), 32);
        assert_eq!(shared_secret.len(), 32);
        assert_ne!(local_eph_pub, [0u8; 32]);
        assert_ne!(shared_secret, [0u8; 32]);
    }

    #[test]
    fn test_envelope_validation() {
        let shuttle_pub = [2u8; 32];
        let context = LayerBContext::new(&shuttle_pub).unwrap();

        let mut envelope = LayerBEnvelope {
            v: 1,
            sess: SessionInfo {
                eph_pub: [0u8; 32],
                peer_id_hint: "test".to_string(),
            },
            aad: LayerBAad {
                hop: "client→shuttle".to_string(),
                bucket_size: 4096,
                original_size: 100,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
            ct: vec![0u8; 100],
            nonce_b: [0u8; 12],
        };

        // Valid envelope should pass
        context.validate_envelope(&envelope).unwrap();

        // Old timestamp should fail
        envelope.aad.timestamp = 0;
        assert!(context.validate_envelope(&envelope).is_err());

        // Wrong hop direction should fail
        envelope.aad.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        envelope.aad.hop = "shuttle→receiver".to_string();
        assert!(context.validate_envelope(&envelope).is_err());
    }

    #[test]
    fn test_bidirectional_contexts() {
        let shuttle_pub = [5u8; 32];
        let receiver_static = [6u8; 32];

        // Client→shuttle context
        let client_ctx = LayerBContext::new(&shuttle_pub).unwrap();
        let client_eph_pub = client_ctx.get_ephemeral_public();

        // Shuttle→receiver context
        let receiver_ctx = LayerBContext::new_receive_context(
            &client_eph_pub,
            &receiver_static,
        ).unwrap();

        // Both contexts should be valid
        assert_eq!(client_ctx.session_direction as u8, SessionDirection::ClientToShuttle as u8);
        assert_eq!(receiver_ctx.session_direction as u8, SessionDirection::ShuttleToReceiver as u8);
    }
}