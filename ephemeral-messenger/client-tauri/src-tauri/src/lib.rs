// Secure Messaging & Document Suite - Library Root
// Re-exports all public modules for testing and CLI usage

pub mod crypto;
pub mod security;
pub mod tor_integration;
pub mod document;
pub mod memory;
pub mod hardware_token;
pub mod securedoc;
pub mod session;
pub mod login_commands;
pub mod settings_store;
pub mod keydetect;
pub mod signal_placeholder;

// Re-export main types for external usage
pub use crypto::{CryptoManager, Identity, EncryptedMessage};
pub use securedoc::{SecureDocFormat, SecureDocManifest, DocumentPolicy};
pub use security::{SecurityChecker, PreSendCheckResults, PreOpenCheckResults};
pub use tor_integration::{TorManager, OnionService, TorStatus};
pub use document::{DocumentEditor, DocumentMetadata};
pub use session::{SessionManager, CipherAlgorithm, CipherCode, CipherPayload, SessionInfo};
pub use signal_placeholder::{SignalSession, SignalStore, PreKey};

// Version information
pub const VERSION: &str = "1.0.0";
pub const BUILD_TYPE: &str = if cfg!(debug_assertions) { "debug" } else { "release" };

// Initialize logging for library usage
pub fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter("secure_messaging=info")
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .init();
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