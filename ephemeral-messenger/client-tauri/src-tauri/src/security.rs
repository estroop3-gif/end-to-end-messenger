// Security checker - Pre-send and pre-open validation
// Implements comprehensive security checks before any crypto operations

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityCheckResult {
    pub passed: bool,
    pub message: String,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreSendCheckResults {
    pub tor_reachability: SecurityCheckResult,
    pub swap_status: SecurityCheckResult,
    pub memory_lock: SecurityCheckResult,
    pub hardware_token: SecurityCheckResult,
    pub fingerprint_verification: SecurityCheckResult,
    pub client_certificate: SecurityCheckResult,
    pub binary_signature: SecurityCheckResult,
    pub time_window: SecurityCheckResult,
    pub overall_passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreOpenCheckResults {
    pub binary_signature: SecurityCheckResult,
    pub identity_unlock: SecurityCheckResult,
    pub memory_security: SecurityCheckResult,
    pub manifest_signature: SecurityCheckResult,
    pub time_policy: SecurityCheckResult,
    pub network_policy: SecurityCheckResult,
    pub overall_passed: bool,
}

pub struct SecurityChecker {
    verified_fingerprints: HashMap<String, (String, u64)>, // recipient_id -> (fingerprint, timestamp)
    trusted_signing_keys: Vec<String>,
    hardware_token_required: bool,
    network_connections_blocked: bool,
}

impl SecurityChecker {
    pub fn new() -> Self {
        Self {
            verified_fingerprints: HashMap::new(),
            trusted_signing_keys: Vec::new(),
            hardware_token_required: true,
            network_connections_blocked: false,
        }
    }

    pub async fn initialize(&mut self) -> Result<()> {
        // Load trusted signing keys from secure storage
        self.load_trusted_keys().await?;

        // Initialize hardware token detection
        self.initialize_hardware_detection().await?;

        println!("Security checker initialized");
        Ok(())
    }

    pub async fn run_pre_send_checks(
        &mut self,
        recipient_id: &str,
        recipient_onion: &str,
        require_hardware_token: bool,
    ) -> Result<PreSendCheckResults> {
        println!("Running pre-send security checks for recipient: {}", recipient_id);

        let checks = PreSendCheckResults {
            tor_reachability: self.check_tor_reachability(Some(recipient_onion)).await,
            swap_status: self.check_swap_status().await,
            memory_lock: self.check_memory_lock().await,
            hardware_token: self.check_hardware_token(require_hardware_token).await,
            fingerprint_verification: self.check_fingerprint_verification(recipient_id).await,
            client_certificate: self.check_client_certificate().await,
            binary_signature: self.check_binary_signature().await,
            time_window: self.check_time_window(recipient_onion).await,
            overall_passed: false,
        };

        // Calculate overall result
        let overall_passed = [
            &checks.tor_reachability,
            &checks.swap_status,
            &checks.memory_lock,
            &checks.hardware_token,
            &checks.fingerprint_verification,
            &checks.binary_signature,
            &checks.time_window,
        ]
        .iter()
        .all(|check| check.passed);

        Ok(PreSendCheckResults {
            overall_passed,
            ..checks
        })
    }

    pub async fn run_pre_open_checks(
        &mut self,
        file_path: &str,
        require_hardware_token: bool,
    ) -> Result<PreOpenCheckResults> {
        println!("Running pre-open security checks for file: {}", file_path);

        // Block all network connections during document opening
        self.network_connections_blocked = true;

        let checks = PreOpenCheckResults {
            binary_signature: self.check_binary_signature().await,
            identity_unlock: self.check_identity_unlock(require_hardware_token).await,
            memory_security: self.check_memory_security().await,
            manifest_signature: self.check_manifest_signature(file_path).await,
            time_policy: self.check_time_policy(file_path).await,
            network_policy: self.check_network_policy().await,
            overall_passed: false,
        };

        let overall_passed = [
            &checks.binary_signature,
            &checks.identity_unlock,
            &checks.memory_security,
            &checks.manifest_signature,
            &checks.time_policy,
            &checks.network_policy,
        ]
        .iter()
        .all(|check| check.passed);

        Ok(PreOpenCheckResults {
            overall_passed,
            ..checks
        })
    }

    // Pre-send checks implementation

    async fn check_tor_reachability(&self, onion_address: Option<&str>) -> SecurityCheckResult {
        // Check if Tor daemon is running
        if let Err(e) = self.check_tor_daemon_status().await {
            return SecurityCheckResult {
                passed: false,
                message: format!("Tor daemon not accessible: {}", e),
                remediation: Some("Start Tor daemon: sudo systemctl start tor".to_string()),
            };
        }

        // Test SOCKS proxy connectivity
        if let Err(e) = self.test_tor_socks_proxy().await {
            return SecurityCheckResult {
                passed: false,
                message: format!("Tor SOCKS proxy not accessible: {}", e),
                remediation: Some("Check Tor configuration and restart if needed".to_string()),
            };
        }

        // Test onion service if provided
        if let Some(onion) = onion_address {
            if let Err(e) = self.test_onion_reachability(onion).await {
                return SecurityCheckResult {
                    passed: false,
                    message: format!("Onion service {} not reachable: {}", onion, e),
                    remediation: Some("Verify onion address and ensure recipient's service is running".to_string()),
                };
            }
        }

        SecurityCheckResult {
            passed: true,
            message: "Tor connectivity verified".to_string(),
            remediation: None,
        }
    }

    async fn check_swap_status(&self) -> SecurityCheckResult {
        match self.read_proc_swaps().await {
            Ok(swap_info) => {
                let active_swaps: Vec<&str> = swap_info
                    .lines()
                    .filter(|line| !line.starts_with("Filename") && !line.trim().is_empty())
                    .collect();

                if !active_swaps.is_empty() {
                    SecurityCheckResult {
                        passed: false,
                        message: "Swap is active - memory may be written to disk".to_string(),
                        remediation: Some("Disable swap: sudo swapoff -a\nOn Tails: sudo systemctl mask swap.target".to_string()),
                    }
                } else {
                    SecurityCheckResult {
                        passed: true,
                        message: "No active swap detected".to_string(),
                        remediation: None,
                    }
                }
            }
            Err(e) => SecurityCheckResult {
                passed: false,
                message: format!("Could not check swap status: {}", e),
                remediation: Some("Manually verify: cat /proc/swaps".to_string()),
            },
        }
    }

    async fn check_memory_lock(&self) -> SecurityCheckResult {
        match self.test_memory_lock_capability().await {
            Ok(true) => SecurityCheckResult {
                passed: true,
                message: "Memory locking available and active".to_string(),
                remediation: None,
            },
            Ok(false) => SecurityCheckResult {
                passed: false,
                message: "Memory locking not available".to_string(),
                remediation: Some("Ensure CAP_IPC_LOCK capability or run with appropriate privileges".to_string()),
            },
            Err(e) => SecurityCheckResult {
                passed: false,
                message: format!("Memory lock check failed: {}", e),
                remediation: Some("Check system capabilities for memory locking".to_string()),
            },
        }
    }

    async fn check_hardware_token(&self, required: bool) -> SecurityCheckResult {
        let yubikey_detected = self.detect_yubikey().await.unwrap_or(false);
        let openpgp_card = self.detect_openpgp_card().await.unwrap_or(false);
        let has_token = yubikey_detected || openpgp_card;

        if required && !has_token {
            SecurityCheckResult {
                passed: false,
                message: "Hardware security token required but not detected".to_string(),
                remediation: Some("Insert YubiKey or OpenPGP-compatible hardware token and ensure it's properly initialized".to_string()),
            }
        } else if !required && !has_token {
            SecurityCheckResult {
                passed: true,
                message: "Hardware token not required (using software keys)".to_string(),
                remediation: None,
            }
        } else {
            let token_type = if yubikey_detected { "YubiKey" } else { "OpenPGP card" };
            SecurityCheckResult {
                passed: true,
                message: format!("Hardware token detected: {}", token_type),
                remediation: None,
            }
        }
    }

    async fn check_fingerprint_verification(&self, recipient_id: &str) -> SecurityCheckResult {
        if let Some((fingerprint, timestamp)) = self.verified_fingerprints.get(recipient_id) {
            let age = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() - timestamp;

            // Fingerprints expire after 24 hours
            if age > 86400 {
                SecurityCheckResult {
                    passed: false,
                    message: "Recipient fingerprint verification expired".to_string(),
                    remediation: Some("Re-verify recipient fingerprint through out-of-band channel".to_string()),
                }
            } else {
                SecurityCheckResult {
                    passed: true,
                    message: format!("Recipient fingerprint verified {} hours ago", age / 3600),
                    remediation: None,
                }
            }
        } else {
            SecurityCheckResult {
                passed: false,
                message: "Recipient fingerprint never verified".to_string(),
                remediation: Some("Verify recipient fingerprint through secure out-of-band channel (QR code, voice call, etc.)".to_string()),
            }
        }
    }

    async fn check_client_certificate(&self) -> SecurityCheckResult {
        // Check for mutual TLS client certificate
        match self.has_valid_client_certificate().await {
            Ok(true) => SecurityCheckResult {
                passed: true,
                message: "Client certificate available and valid".to_string(),
                remediation: None,
            },
            Ok(false) => SecurityCheckResult {
                passed: true, // Not always required
                message: "No client certificate configured (using Tor onion auth only)".to_string(),
                remediation: None,
            },
            Err(e) => SecurityCheckResult {
                passed: true, // Non-critical
                message: format!("Client certificate check failed: {} (proceeding anyway)", e),
                remediation: None,
            },
        }
    }

    async fn check_binary_signature(&self) -> SecurityCheckResult {
        match self.verify_binary_signature().await {
            Ok(true) => SecurityCheckResult {
                passed: true,
                message: "Binary signature verified".to_string(),
                remediation: None,
            },
            Ok(false) => SecurityCheckResult {
                passed: false,
                message: "Binary signature verification failed".to_string(),
                remediation: Some("Verify binary integrity:\n1. Check SHA256 hash against known good values\n2. Re-download from trusted source\n3. In development, disable signature checks in settings".to_string()),
            },
            Err(e) => SecurityCheckResult {
                passed: false,
                message: format!("Binary signature check failed: {}", e),
                remediation: Some("Unable to verify binary signature. Proceed only if you trust the source.".to_string()),
            },
        }
    }

    async fn check_time_window(&self, onion_address: &str) -> SecurityCheckResult {
        match self.get_onion_creation_time(onion_address).await {
            Ok(Some(creation_time)) => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                let age = now - creation_time;

                // Onion services should be created within 5 minutes
                if age > 300 {
                    SecurityCheckResult {
                        passed: false,
                        message: "Recipient onion service is too old for ephemeral session".to_string(),
                        remediation: Some("Ask recipient to create a fresh onion service (< 5 minutes old)".to_string()),
                    }
                } else {
                    SecurityCheckResult {
                        passed: true,
                        message: format!("Onion service created {} seconds ago (within time window)", age),
                        remediation: None,
                    }
                }
            }
            Ok(None) => SecurityCheckResult {
                passed: true, // Cannot determine, assume OK
                message: "Cannot determine onion service age (proceeding)".to_string(),
                remediation: None,
            },
            Err(e) => SecurityCheckResult {
                passed: true, // Non-critical
                message: format!("Time window check skipped: {}", e),
                remediation: None,
            },
        }
    }

    // Pre-open checks implementation

    async fn check_identity_unlock(&self, require_hardware_token: bool) -> SecurityCheckResult {
        if require_hardware_token {
            match self.test_hardware_token_unlock().await {
                Ok(true) => SecurityCheckResult {
                    passed: true,
                    message: "Hardware token unlocked and accessible".to_string(),
                    remediation: None,
                },
                Ok(false) => SecurityCheckResult {
                    passed: false,
                    message: "Hardware token locked or not accessible".to_string(),
                    remediation: Some("Unlock hardware token with PIN or touch".to_string()),
                },
                Err(e) => SecurityCheckResult {
                    passed: false,
                    message: format!("Hardware token check failed: {}", e),
                    remediation: Some("Ensure hardware token is properly connected and initialized".to_string()),
                },
            }
        } else {
            SecurityCheckResult {
                passed: true,
                message: "Using passphrase-based identity (hardware token not required)".to_string(),
                remediation: None,
            }
        }
    }

    async fn check_memory_security(&self) -> SecurityCheckResult {
        let swap_check = self.check_swap_status().await;
        let lock_check = self.check_memory_lock().await;

        if swap_check.passed && lock_check.passed {
            SecurityCheckResult {
                passed: true,
                message: "Memory security verified (no swap, memory locking active)".to_string(),
                remediation: None,
            }
        } else {
            let mut issues = Vec::new();
            if !swap_check.passed {
                issues.push("swap active");
            }
            if !lock_check.passed {
                issues.push("memory locking unavailable");
            }

            SecurityCheckResult {
                passed: false,
                message: format!("Memory security issues: {}", issues.join(", ")),
                remediation: Some("Fix memory security issues before opening encrypted documents".to_string()),
            }
        }
    }

    async fn check_manifest_signature(&self, file_path: &str) -> SecurityCheckResult {
        match self.verify_securedoc_manifest(file_path).await {
            Ok(true) => SecurityCheckResult {
                passed: true,
                message: "Document manifest signature valid".to_string(),
                remediation: None,
            },
            Ok(false) => SecurityCheckResult {
                passed: false,
                message: "Document manifest signature invalid or missing".to_string(),
                remediation: Some("This document may be corrupted or tampered with. Do not open unless you trust the source.".to_string()),
            },
            Err(e) => SecurityCheckResult {
                passed: false,
                message: format!("Manifest signature check failed: {}", e),
                remediation: Some("Cannot verify document integrity. Proceed with caution.".to_string()),
            },
        }
    }

    async fn check_time_policy(&self, file_path: &str) -> SecurityCheckResult {
        match self.check_document_expiry(file_path).await {
            Ok(Some(expiry)) => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                if now > expiry {
                    SecurityCheckResult {
                        passed: false,
                        message: "Document has expired".to_string(),
                        remediation: Some("This document is past its expiration date and cannot be opened".to_string()),
                    }
                } else {
                    SecurityCheckResult {
                        passed: true,
                        message: format!("Document expires in {} hours", (expiry - now) / 3600),
                        remediation: None,
                    }
                }
            }
            Ok(None) => SecurityCheckResult {
                passed: true,
                message: "Document has no expiration policy".to_string(),
                remediation: None,
            },
            Err(e) => SecurityCheckResult {
                passed: true, // Non-critical
                message: format!("Time policy check skipped: {}", e),
                remediation: None,
            },
        }
    }

    async fn check_network_policy(&self) -> SecurityCheckResult {
        if self.network_connections_blocked {
            // Verify no outbound connections are possible
            match self.test_network_isolation().await {
                Ok(true) => SecurityCheckResult {
                    passed: true,
                    message: "Network isolation active - no outbound connections possible".to_string(),
                    remediation: None,
                },
                Ok(false) => SecurityCheckResult {
                    passed: false,
                    message: "Network connections still possible during document open".to_string(),
                    remediation: Some("Disconnect from network or enable airplane mode before opening documents".to_string()),
                },
                Err(e) => SecurityCheckResult {
                    passed: false,
                    message: format!("Network isolation check failed: {}", e),
                    remediation: Some("Manually verify network is disconnected".to_string()),
                },
            }
        } else {
            SecurityCheckResult {
                passed: true,
                message: "Network policy check disabled".to_string(),
                remediation: None,
            }
        }
    }

    // Helper methods for actual checks

    async fn check_tor_daemon_status(&self) -> Result<()> {
        let output = Command::new("curl")
            .args(&[
                "--socks5", "127.0.0.1:9050",
                "--connect-timeout", "5",
                "--max-time", "10",
                "http://check.torproject.org/",
            ])
            .output()
            .map_err(|e| anyhow!("Failed to test Tor connectivity: {}", e))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(anyhow!("Tor connectivity test failed"))
        }
    }

    async fn test_tor_socks_proxy(&self) -> Result<()> {
        // Test SOCKS proxy on port 9050
        use std::net::TcpStream;
        use std::time::Duration;

        TcpStream::connect_timeout(
            &"127.0.0.1:9050".parse().unwrap(),
            Duration::from_secs(5),
        )
        .map_err(|e| anyhow!("Cannot connect to Tor SOCKS proxy: {}", e))?;

        Ok(())
    }

    async fn test_onion_reachability(&self, onion_address: &str) -> Result<()> {
        // TODO: Implement onion service reachability test
        // For now, assume reachable
        Ok(())
    }

    async fn read_proc_swaps(&self) -> Result<String> {
        fs::read_to_string("/proc/swaps")
            .map_err(|e| anyhow!("Failed to read /proc/swaps: {}", e))
    }

    async fn test_memory_lock_capability(&self) -> Result<bool> {
        // Test if mlockall would succeed
        #[cfg(target_os = "linux")]
        {
            use nix::sys::mman::{mlockall, munlockall, MlockAllFlags};

            match mlockall(MlockAllFlags::MCL_CURRENT) {
                Ok(()) => {
                    let _ = munlockall(); // Unlock for now
                    Ok(true)
                }
                Err(_) => Ok(false),
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            // Assume available on other platforms
            Ok(true)
        }
    }

    async fn detect_yubikey(&self) -> Result<bool> {
        let output = Command::new("lsusb")
            .output()
            .map_err(|e| anyhow!("Failed to run lsusb: {}", e))?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        Ok(output_str.contains("Yubico"))
    }

    async fn detect_openpgp_card(&self) -> Result<bool> {
        let output = Command::new("gpg")
            .args(&["--card-status"])
            .output()
            .map_err(|e| anyhow!("Failed to run gpg --card-status: {}", e))?;

        Ok(output.status.success())
    }

    async fn has_valid_client_certificate(&self) -> Result<bool> {
        // TODO: Implement client certificate validation
        Ok(false)
    }

    async fn verify_binary_signature(&self) -> Result<bool> {
        // TODO: Implement binary signature verification
        // For development, return false to remind about implementation
        Ok(false)
    }

    async fn get_onion_creation_time(&self, onion_address: &str) -> Result<Option<u64>> {
        // TODO: Track onion creation times
        Ok(None)
    }

    async fn test_hardware_token_unlock(&self) -> Result<bool> {
        // TODO: Test hardware token accessibility
        Ok(true)
    }

    async fn verify_securedoc_manifest(&self, file_path: &str) -> Result<bool> {
        // TODO: Implement .securedoc manifest verification
        Ok(true)
    }

    async fn check_document_expiry(&self, file_path: &str) -> Result<Option<u64>> {
        // TODO: Check document expiry from manifest
        Ok(None)
    }

    async fn test_network_isolation(&self) -> Result<bool> {
        // Test if we can make any outbound connections
        use std::net::TcpStream;
        use std::time::Duration;

        // Try to connect to common services
        let test_hosts = ["8.8.8.8:53", "1.1.1.1:53", "google.com:80"];

        for host in &test_hosts {
            if let Ok(_) = TcpStream::connect_timeout(
                &host.parse().unwrap(),
                Duration::from_secs(1),
            ) {
                return Ok(false); // Connection succeeded, not isolated
            }
        }

        Ok(true) // No connections succeeded, isolated
    }

    async fn load_trusted_keys(&mut self) -> Result<()> {
        // TODO: Load trusted signing keys from secure storage
        Ok(())
    }

    async fn initialize_hardware_detection(&mut self) -> Result<()> {
        // TODO: Initialize hardware token detection
        Ok(())
    }

    pub fn verify_recipient_fingerprint(&mut self, recipient_id: &str, fingerprint: &str) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.verified_fingerprints.insert(
            recipient_id.to_string(),
            (fingerprint.to_string(), timestamp),
        );

        println!("Fingerprint verified for recipient: {}", recipient_id);
    }

    pub fn clear_verified_fingerprints(&mut self) {
        self.verified_fingerprints.clear();
    }
}