// Triple-encryption onion transport implementation
// This module implements the full onion transport stack:
// Layer A (Signal) → Layer B (X25519+ChaCha20) → Layer C (AES-GCM)

pub mod onion;
pub mod layer_c_local;
pub mod layer_b_interrelay;
pub mod padding;
pub mod signal_bridge;

pub use onion::{OnionFrame, OnionSession, OnionSessionManager, LayerBMetadata, LayerCMetadata};
pub use layer_c_local::{LayerCContext, LayerCEnvelope, LayerCHandshake};
pub use layer_b_interrelay::{LayerBContext, LayerBEnvelope};
pub use padding::{PaddingPolicy, SecurePadding, CoverTrafficPadding, BucketStats};
pub use signal_bridge::SignalEnvelope;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;

/// Transport configuration for the onion system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    pub local_relay_url: String,
    pub shuttle_url: String,
    pub padding_enabled: bool,
    pub cover_traffic_enabled: bool,
    pub key_rotation_interval: u64, // seconds
    pub session_timeout: u64,       // seconds
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            local_relay_url: "ws://localhost:8080".to_string(),
            shuttle_url: "wss://shuttle.example.com".to_string(),
            padding_enabled: true,
            cover_traffic_enabled: true,
            key_rotation_interval: 30 * 60, // 30 minutes
            session_timeout: 24 * 60 * 60,  // 24 hours
        }
    }
}

/// Transport manager for handling all onion sessions
pub struct TransportManager {
    session_manager: Arc<RwLock<OnionSessionManager>>,
    config: TransportConfig,
    stats: Arc<Mutex<TransportStats>>,
}

/// Statistics for transport operations
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TransportStats {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub sessions_created: u64,
    pub key_rotations: u64,
    pub cover_traffic_sent: u64,
}

impl TransportManager {
    pub fn new(config: TransportConfig) -> Self {
        Self {
            session_manager: Arc::new(RwLock::new(OnionSessionManager::new())),
            config,
            stats: Arc::new(Mutex::new(TransportStats::default())),
        }
    }

    /// Create a new onion session
    pub async fn create_session(
        &self,
        session_id: String,
        remote_relay_pub: [u8; 32],
        shuttle_pub: [u8; 32],
    ) -> Result<()> {
        let mut manager = self.session_manager.write().await;
        let padding_policy = if self.config.padding_enabled {
            PaddingPolicy::Enabled
        } else {
            PaddingPolicy::Disabled
        };

        manager.create_session(session_id, &remote_relay_pub, &shuttle_pub, padding_policy)?;

        if let Ok(mut stats) = self.stats.lock() {
            stats.sessions_created += 1;
        }

        Ok(())
    }

    /// Send a message through the onion transport
    pub async fn send_message(
        &self,
        session_id: &str,
        signal_envelope: &SignalEnvelope,
    ) -> Result<OnionFrame> {
        let mut manager = self.session_manager.write().await;
        let frame = manager.send_message(session_id, signal_envelope)?;

        if let Ok(mut stats) = self.stats.lock() {
            stats.messages_sent += 1;
            stats.bytes_sent += frame.c_envelope.to_bytes()?.len() as u64;
        }

        Ok(frame)
    }

    /// Receive a message from the onion transport
    pub async fn receive_message(
        &self,
        session_id: &str,
        frame: &OnionFrame,
    ) -> Result<SignalEnvelope> {
        let mut manager = self.session_manager.write().await;
        let envelope = manager.receive_message(session_id, frame)?;

        if let Ok(mut stats) = self.stats.lock() {
            stats.messages_received += 1;
            stats.bytes_received += frame.c_envelope.to_bytes()?.len() as u64;
        }

        Ok(envelope)
    }

    /// Generate cover traffic for a session
    pub async fn generate_cover_traffic(&self, session_id: &str) -> Result<Option<OnionFrame>> {
        let mut manager = self.session_manager.write().await;
        let frame = manager.generate_cover_traffic(session_id)?;

        if frame.is_some() {
            if let Ok(mut stats) = self.stats.lock() {
                stats.cover_traffic_sent += 1;
            }
        }

        Ok(frame)
    }

    /// Remove a session
    pub async fn remove_session(&self, session_id: &str) {
        let mut manager = self.session_manager.write().await;
        manager.remove_session(session_id);
    }

    /// Get current transport statistics
    pub fn get_stats(&self) -> TransportStats {
        match self.stats.lock() {
            Ok(stats) => stats.clone(),
            Err(_) => TransportStats::default(),
        }
    }

    /// Update transport configuration
    pub fn update_config(&mut self, config: TransportConfig) {
        self.config = config;
    }

    /// Get current configuration
    pub fn get_config(&self) -> &TransportConfig {
        &self.config
    }
}

/// Wire format utilities for serialization
pub mod wire {
    use super::*;
    use anyhow::{anyhow, Result};

    /// Wire format version
    pub const WIRE_VERSION: u8 = 1;

    /// Maximum frame size (2MB)
    pub const MAX_FRAME_SIZE: usize = 2 * 1024 * 1024;

    /// Serialize onion frame for wire transmission
    pub fn serialize_frame(frame: &OnionFrame) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();

        // Add version header
        buffer.push(WIRE_VERSION);

        // Serialize frame
        let frame_bytes = bincode::serialize(frame)
            .map_err(|e| anyhow!("Failed to serialize frame: {}", e))?;

        if frame_bytes.len() > MAX_FRAME_SIZE {
            return Err(anyhow!("Frame too large: {} bytes", frame_bytes.len()));
        }

        // Add length prefix (big-endian u32)
        let len = frame_bytes.len() as u32;
        buffer.extend_from_slice(&len.to_be_bytes());

        // Add frame data
        buffer.extend_from_slice(&frame_bytes);

        Ok(buffer)
    }

    /// Deserialize onion frame from wire format
    pub fn deserialize_frame(data: &[u8]) -> Result<OnionFrame> {
        if data.len() < 5 {
            return Err(anyhow!("Invalid frame: too short"));
        }

        // Check version
        if data[0] != WIRE_VERSION {
            return Err(anyhow!("Unsupported wire version: {}", data[0]));
        }

        // Parse length
        let len_bytes: [u8; 4] = data[1..5].try_into()
            .map_err(|_| anyhow!("Invalid length field"))?;
        let len = u32::from_be_bytes(len_bytes) as usize;

        if len > MAX_FRAME_SIZE {
            return Err(anyhow!("Frame too large: {} bytes", len));
        }

        if data.len() < 5 + len {
            return Err(anyhow!("Incomplete frame"));
        }

        // Deserialize frame
        let frame_data = &data[5..5 + len];
        bincode::deserialize(frame_data)
            .map_err(|e| anyhow!("Failed to deserialize frame: {}", e))
    }

    /// Create heartbeat frame for connection keep-alive
    pub fn create_heartbeat() -> Vec<u8> {
        vec![WIRE_VERSION, 0, 0, 0, 0] // Empty frame
    }

    /// Check if frame is a heartbeat
    pub fn is_heartbeat(data: &[u8]) -> bool {
        data.len() == 5 && data[0] == WIRE_VERSION && &data[1..] == [0, 0, 0, 0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_transport_manager() {
        let config = TransportConfig::default();
        let manager = TransportManager::new(config);

        let session_id = "test-session".to_string();
        let remote_pub = [1u8; 32];
        let shuttle_pub = [2u8; 32];

        // Create session
        manager.create_session(session_id.clone(), remote_pub, shuttle_pub)
            .await.unwrap();

        // Check stats
        let stats = manager.get_stats();
        assert_eq!(stats.sessions_created, 1);
    }

    #[test]
    fn test_wire_format() {
        use wire::*;

        // Test heartbeat
        let heartbeat = create_heartbeat();
        assert!(is_heartbeat(&heartbeat));

        // Test frame serialization would require actual frame
        // This validates the wire format structure
        assert_eq!(heartbeat.len(), 5);
        assert_eq!(heartbeat[0], WIRE_VERSION);
    }

    #[test]
    fn test_config_defaults() {
        let config = TransportConfig::default();
        assert!(config.padding_enabled);
        assert!(config.cover_traffic_enabled);
        assert_eq!(config.key_rotation_interval, 30 * 60);
    }
}