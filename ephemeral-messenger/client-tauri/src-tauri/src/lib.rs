// Secure Messaging & Document Suite - Library Root (Stub Implementation)
// Re-exports all public modules for testing and CLI usage

mod stubs;

// Use simplified stub implementations
pub use crypto_stub as crypto;
pub use stubs::*;

pub mod crypto_stub;
pub mod tor_integration;
// pub mod settings_store;  // Temporarily disabled due to compilation errors
pub mod signal_placeholder;
// pub mod login_commands;  // Temporarily disabled due to compilation errors

// Re-export main types for external usage
pub use crypto_stub::{CryptoManager, Identity, EncryptedMessage, MessageMetadata};
pub use stubs::{SecureDocFormat, SecureDocManifest, DocumentPolicy};
pub use stubs::security::{SecurityChecker, PreSendCheckResults, PreOpenCheckResults};
pub use tor_integration::{TorManager, OnionService, TorStatus};
pub use stubs::document::{DocumentEditor, DocumentMetadata};
pub use stubs::{SessionManager, CipherAlgorithm, CipherCode, CipherPayload, SessionInfo};
pub use signal_placeholder::{SignalSession, SignalStore, PreKey};

// Version information
pub const VERSION: &str = "1.0.0";
pub const BUILD_TYPE: &str = if cfg!(debug_assertions) { "debug" } else { "release" };

// Initialize logging for library usage
pub fn init_logging() {
    println!("Logging initialized (stub implementation)");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_info() {
        assert_eq!(VERSION, "1.0.0");
        assert!(!BUILD_TYPE.is_empty());
    }
}