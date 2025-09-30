// Triple-encryption onion transport implementation
// Layer A (Signal) → Layer B (X25519+ChaCha20) → Layer C (AES-GCM)

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    layer_b_interrelay::{LayerBContext, LayerBEnvelope},
    layer_c_local::{LayerCContext, LayerCEnvelope},
    padding::{bucketize, add_padding, remove_padding, PaddingPolicy},
    signal_bridge::SignalEnvelope,
};

/// Complete onion frame ready for transport
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionFrame {
    pub c_envelope: LayerCEnvelope,
}

/// Session context for managing all three layers
#[derive(ZeroizeOnDrop)]
pub struct OnionSession {
    pub session_id: String,
    pub layer_c_ctx: LayerCContext,
    pub layer_b_ctx: LayerBContext,
    #[zeroize(skip)]
    pub padding_policy: PaddingPolicy,
}

/// Key rotation state
#[derive(Debug)]
pub struct KeyRotationState {
    pub layer_c_rotations: u32,
    pub layer_b_rotations: u32,
    pub last_rotation: std::time::Instant,
}

impl OnionSession {
    /// Create new session with fresh keys for all layers
    pub fn new(
        session_id: String,
        remote_relay_pub: &[u8; 32],
        shuttle_pub: &[u8; 32],
        padding_policy: PaddingPolicy,
    ) -> Result<Self> {
        let layer_c_ctx = LayerCContext::new(remote_relay_pub)?;
        let layer_b_ctx = LayerBContext::new(shuttle_pub)?;

        Ok(Self {
            session_id,
            layer_c_ctx,
            layer_b_ctx,
            padding_policy,
        })
    }

    /// Wrap Signal envelope with B and C layers
    pub fn wrap_a_b_c(&mut self, signal_envelope: &SignalEnvelope) -> Result<OnionFrame> {
        // Step 1: Serialize Signal envelope (A-layer)
        let a_bytes = signal_envelope.to_bytes()?;

        let original_size = a_bytes.len();

        // Step 2: Apply bucketized padding
        let (bucket_size, padded_a) = match self.padding_policy {
            PaddingPolicy::Enabled => {
                let bucket = bucketize(a_bytes.len());
                let padded = add_padding(&a_bytes, bucket)?;
                (bucket, padded)
            }
            PaddingPolicy::Disabled => (a_bytes.len(), a_bytes),
        };

        // Step 3: Wrap with B-layer (inter-relay)
        let b_envelope = self.layer_b_ctx.encrypt(
            &padded_a,
            &LayerBMetadata {
                hop: "client→shuttle".to_string(),
                bucket_size,
                original_size,
            },
        )?;

        // Step 4: Wrap with C-layer (local hop)
        let c_envelope = self.layer_c_ctx.encrypt(
            &b_envelope.to_bytes()?,
            &LayerCMetadata {
                session_id: self.session_id.clone(),
                dst_hint: "relay".to_string(),
                size_orig: original_size,
                bucket: bucket_size,
                t_bucket: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
            },
        )?;

        Ok(OnionFrame { c_envelope })
    }

    /// Peel C, B, and A layers to recover Signal envelope
    pub fn peel_c_b_a(&mut self, frame: &OnionFrame) -> Result<SignalEnvelope> {
        // Step 1: Peel C-layer (local hop)
        let (b_bytes, c_metadata) = self.layer_c_ctx.decrypt(&frame.c_envelope)?;

        // Step 2: Parse B-envelope
        let b_envelope = LayerBEnvelope::from_bytes(&b_bytes)?;

        // Step 3: Peel B-layer (inter-relay)
        let (padded_a, b_metadata) = self.layer_b_ctx.decrypt(&b_envelope)?;

        // Step 4: Verify metadata consistency
        if c_metadata.size_orig != b_metadata.original_size {
            return Err(anyhow!("Metadata size mismatch between layers"));
        }

        if c_metadata.bucket != b_metadata.bucket_size {
            return Err(anyhow!("Bucket size mismatch between layers"));
        }

        // Step 5: Remove padding
        let a_bytes = match self.padding_policy {
            PaddingPolicy::Enabled => remove_padding(&padded_a, c_metadata.size_orig)?,
            PaddingPolicy::Disabled => padded_a,
        };

        // Step 6: Parse Signal envelope
        SignalEnvelope::from_bytes(&a_bytes)
    }

    /// Rotate keys based on policy
    pub fn rotate_keys_if_needed(&mut self, state: &mut KeyRotationState) -> Result<bool> {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(state.last_rotation);

        // Rotate every 30 minutes or 1000 messages
        let should_rotate_time = elapsed.as_secs() > 30 * 60;
        let should_rotate_count = state.layer_c_rotations > 1000 || state.layer_b_rotations > 1000;

        if should_rotate_time || should_rotate_count {
            self.layer_c_ctx.rotate_keys()?;
            self.layer_b_ctx.rotate_keys()?;

            state.layer_c_rotations = 0;
            state.layer_b_rotations = 0;
            state.last_rotation = now;

            log::info!("Rotated onion transport keys for session {}", self.session_id);
            return Ok(true);
        }

        Ok(false)
    }

    /// Generate cover traffic dummy frame
    pub fn generate_cover_traffic(&mut self) -> Result<OnionFrame> {
        use rand::RngCore;

        // Create dummy signal envelope with random data
        let mut dummy_data = vec![0u8; rand::thread_rng().next_u32() as usize % 1024 + 256];
        rand::thread_rng().fill_bytes(&mut dummy_data);

        let dummy_signal = SignalEnvelope::dummy(dummy_data)?;
        self.wrap_a_b_c(&dummy_signal)
    }
}

/// Metadata for B-layer encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerBMetadata {
    pub hop: String,
    pub bucket_size: usize,
    pub original_size: usize,
}

/// Metadata for C-layer encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerCMetadata {
    pub session_id: String,
    pub dst_hint: String,
    pub size_orig: usize,
    pub bucket: usize,
    pub t_bucket: u64,
}

/// Manager for multiple onion sessions
pub struct OnionSessionManager {
    sessions: HashMap<String, OnionSession>,
    rotation_states: HashMap<String, KeyRotationState>,
}

impl OnionSessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            rotation_states: HashMap::new(),
        }
    }

    pub fn create_session(
        &mut self,
        session_id: String,
        remote_relay_pub: &[u8; 32],
        shuttle_pub: &[u8; 32],
        padding_policy: PaddingPolicy,
    ) -> Result<()> {
        let session = OnionSession::new(
            session_id.clone(),
            remote_relay_pub,
            shuttle_pub,
            padding_policy,
        )?;

        let rotation_state = KeyRotationState {
            layer_c_rotations: 0,
            layer_b_rotations: 0,
            last_rotation: std::time::Instant::now(),
        };

        self.sessions.insert(session_id.clone(), session);
        self.rotation_states.insert(session_id, rotation_state);

        Ok(())
    }

    pub fn send_message(
        &mut self,
        session_id: &str,
        signal_envelope: &SignalEnvelope,
    ) -> Result<OnionFrame> {
        let session = self.sessions.get_mut(session_id)
            .ok_or_else(|| anyhow!("Session not found: {}", session_id))?;

        let mut rotation_state = self.rotation_states.get_mut(session_id)
            .ok_or_else(|| anyhow!("Rotation state not found: {}", session_id))?;

        session.rotate_keys_if_needed(&mut rotation_state)?;

        let frame = session.wrap_a_b_c(signal_envelope)?;

        rotation_state.layer_c_rotations += 1;
        rotation_state.layer_b_rotations += 1;

        Ok(frame)
    }

    pub fn receive_message(
        &mut self,
        session_id: &str,
        frame: &OnionFrame,
    ) -> Result<SignalEnvelope> {
        let session = self.sessions.get_mut(session_id)
            .ok_or_else(|| anyhow!("Session not found: {}", session_id))?;

        session.peel_c_b_a(frame)
    }

    pub fn remove_session(&mut self, session_id: &str) {
        self.sessions.remove(session_id);
        self.rotation_states.remove(session_id);
    }

    pub fn generate_cover_traffic(&mut self, session_id: &str) -> Result<Option<OnionFrame>> {
        if let Some(session) = self.sessions.get_mut(session_id) {
            Ok(Some(session.generate_cover_traffic()?))
        } else {
            Ok(None)
        }
    }
}

/// Utility for constant-time operations
pub mod secure_utils {
    /// Constant-time comparison
    pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut result = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }

        result == 0
    }

    /// Secure random delay for timing attack mitigation
    pub fn jitter_delay() {
        use rand::Rng;
        let delay_ms = rand::thread_rng().gen_range(1..10);
        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
    }
}