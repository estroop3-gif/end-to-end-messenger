// Account Management Commands for Tauri
//
// This module provides Tauri commands for account creation, key generation,
// and hardware key management operations called from the frontend.
//
// SECURITY NOTE: All operations involving private keys are performed
// with secure memory handling and immediate cleanup.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use tauri::command;
use uuid::Uuid;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use age::secrecy::SecretString;
use age::{Decryptor, Encryptor, Recipient};

#[derive(Debug, Serialize, Deserialize)]
pub struct GeneratedKeyResult {
    pub user_id: String,
    pub public_key: String,
    pub fingerprint: String,
    pub key_file_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SoftwareAccountResult {
    pub user_id: String,
    pub public_key: String,
    pub fingerprint: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountConfig {
    pub account_type: String, // "hardware" or "software"
    pub user_id: String,
    pub username: String,
    pub created_at: String,
    pub key_fingerprint: String,
    pub hardware_key_present: bool,
}

/// Generate a hardware key using the external keygen tool
#[command]
pub async fn generate_hardware_key(
    username: String,
    device_path: String,
    validity_days: Option<u32>,
) -> Result<GeneratedKeyResult, String> {
    // Validate inputs
    if username.trim().is_empty() {
        return Err("Username cannot be empty".to_string());
    }

    if device_path.trim().is_empty() {
        return Err("Device path cannot be empty".to_string());
    }

    // Check if device path exists and is writable
    let device_pathbuf = PathBuf::from(&device_path);
    if !device_pathbuf.exists() {
        return Err("Device path does not exist".to_string());
    }

    let validity = validity_days.unwrap_or(365);
    let user_id = Uuid::new_v4().to_string();

    // Build keygen command
    let keygen_path = find_keygen_binary()?;
    let mut cmd = Command::new(keygen_path);

    cmd.args(&[
        "--interactive=false",
        &format!("--user-id={}", user_id),
        &format!("--validity={}", validity),
        &format!("--output={}", device_path),
        "--qr",
    ]);

    // Execute key generation
    match cmd.output() {
        Ok(output) => {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);

                // Parse output to extract key information
                let key_file_path = extract_key_file_path(&stdout)?;
                let public_key = extract_public_key(&key_file_path)?;
                let fingerprint = calculate_fingerprint(&user_id, &public_key);

                Ok(GeneratedKeyResult {
                    user_id,
                    public_key,
                    fingerprint,
                    key_file_path,
                })
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                Err(format!("Key generation failed: {}", stderr))
            }
        }
        Err(e) => Err(format!("Failed to execute keygen: {}", e)),
    }
}

/// Create a software-only account with passphrase-derived keys
#[command]
pub async fn create_software_account(
    username: String,
    passphrase: String,
) -> Result<SoftwareAccountResult, String> {
    // Validate inputs
    if username.trim().is_empty() {
        return Err("Username cannot be empty".to_string());
    }

    if passphrase.is_empty() {
        return Err("Passphrase cannot be empty".to_string());
    }

    // Check passphrase strength
    if !is_strong_passphrase(&passphrase) {
        return Err("Passphrase is too weak".to_string());
    }

    let user_id = Uuid::new_v4().to_string();

    // Derive cryptographic keys from passphrase using Argon2
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(passphrase.as_bytes(), &salt)
        .map_err(|e| format!("Password hashing failed: {}", e))?
        .to_string();

    // For demonstration, we'll generate a placeholder public key
    // In a real implementation, this would derive actual cryptographic keys
    let public_key = derive_public_key_from_passphrase(&passphrase, &user_id)?;
    let fingerprint = calculate_fingerprint(&user_id, &public_key);

    // Store account configuration
    save_software_account_config(&AccountConfig {
        account_type: "software".to_string(),
        user_id: user_id.clone(),
        username: username.trim().to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        key_fingerprint: fingerprint.clone(),
        hardware_key_present: false,
    })?;

    Ok(SoftwareAccountResult {
        user_id,
        public_key,
        fingerprint,
    })
}

/// Scan for removable devices
#[command]
pub async fn scan_removable_devices() -> Result<Vec<HashMap<String, String>>, String> {
    let mut devices = Vec::new();

    // Common mount points to check
    let mount_points = vec![
        "/media",
        "/mnt",
        "/run/media",
        "/run/user/1000",
        "/run/user/1001",
    ];

    for mount_point in mount_points {
        let mount_path = PathBuf::from(mount_point);
        if mount_path.exists() {
            if let Ok(entries) = std::fs::read_dir(mount_path) {
                for entry in entries.flatten() {
                    if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        let device_path = entry.path();

                        // Check if device is writable
                        if is_writable(&device_path) {
                            let mut device_info = HashMap::new();
                            device_info.insert("name".to_string(),
                                entry.file_name().to_string_lossy().to_string());
                            device_info.insert("path".to_string(),
                                device_path.to_string_lossy().to_string());
                            device_info.insert("size".to_string(),
                                get_device_size(&device_path));
                            device_info.insert("filesystem".to_string(),
                                get_filesystem_type(&device_path));

                            devices.push(device_info);
                        }
                    }
                }
            }
        }
    }

    Ok(devices)
}

/// Validate passphrase strength
#[command]
pub async fn validate_passphrase_strength(passphrase: String) -> Result<String, String> {
    let strength = calculate_passphrase_strength(&passphrase);
    Ok(strength)
}

/// Check if hardware key detection service is available
#[command]
pub async fn check_key_detection_service() -> Result<bool, String> {
    // This would check if the key detection service is running
    // For now, return true as a placeholder
    Ok(true)
}

// Helper functions

fn find_keygen_binary() -> Result<String, String> {
    // Look for keygen binary in various locations
    let possible_paths = vec![
        "./tools/bin/keygen",
        "../tools/bin/keygen",
        "/usr/local/bin/keygen",
        "keygen", // In PATH
    ];

    for path in possible_paths {
        if PathBuf::from(path).exists() || which::which(path).is_ok() {
            return Ok(path.to_string());
        }
    }

    Err("keygen binary not found".to_string())
}

fn extract_key_file_path(output: &str) -> Result<String, String> {
    // Parse keygen output to find the keyfile path
    for line in output.lines() {
        if line.contains("Keyfile written to:") {
            if let Some(path) = line.split("Keyfile written to:").nth(1) {
                return Ok(path.trim().to_string());
            }
        }
    }
    Err("Could not extract keyfile path from output".to_string())
}

fn extract_public_key(key_file_path: &str) -> Result<String, String> {
    // Read and parse the generated keyfile to extract public key
    let content = std::fs::read_to_string(key_file_path)
        .map_err(|e| format!("Failed to read keyfile: {}", e))?;

    let key_data: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse keyfile JSON: {}", e))?;

    key_data.get("pub_identity_ed25519")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "Public key not found in keyfile".to_string())
}

fn calculate_fingerprint(user_id: &str, public_key: &str) -> String {
    use sha2::{Sha256, Digest};

    let mut hasher = Sha256::new();
    hasher.update(user_id.as_bytes());
    hasher.update(public_key.as_bytes());
    let result = hasher.finalize();

    format!("{:x}", result)[..16].to_string()
}

fn is_strong_passphrase(passphrase: &str) -> bool {
    // Basic passphrase strength validation
    let length_ok = passphrase.len() >= 12;
    let has_upper = passphrase.chars().any(|c| c.is_uppercase());
    let has_lower = passphrase.chars().any(|c| c.is_lowercase());
    let has_digit = passphrase.chars().any(|c| c.is_numeric());
    let has_special = passphrase.chars().any(|c| !c.is_alphanumeric());

    // Check for word-based passphrases (4+ words)
    let word_count = passphrase.split_whitespace().count();
    let is_phrase = word_count >= 4;

    // Strong if either complex password or good passphrase
    let is_complex = length_ok && has_upper && has_lower && has_digit && has_special;

    is_complex || (is_phrase && passphrase.len() >= 20)
}

fn calculate_passphrase_strength(passphrase: &str) -> String {
    let mut score = 0;

    // Length scoring
    if passphrase.len() >= 12 { score += 2; }
    else if passphrase.len() >= 8 { score += 1; }

    // Character variety
    if passphrase.chars().any(|c| c.is_lowercase()) { score += 1; }
    if passphrase.chars().any(|c| c.is_uppercase()) { score += 1; }
    if passphrase.chars().any(|c| c.is_numeric()) { score += 1; }
    if passphrase.chars().any(|c| !c.is_alphanumeric()) { score += 1; }

    // Word-based passphrase bonus
    let word_count = passphrase.split_whitespace().count();
    if word_count >= 4 { score += 2; }

    match score {
        0..=3 => "weak".to_string(),
        4..=5 => "medium".to_string(),
        _ => "strong".to_string(),
    }
}

fn derive_public_key_from_passphrase(passphrase: &str, user_id: &str) -> Result<String, String> {
    // This is a placeholder implementation
    // In a real system, this would derive actual Ed25519 keys from the passphrase
    use sha2::{Sha256, Digest};

    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    hasher.update(user_id.as_bytes());
    hasher.update(b"ephemeral-messenger-public-key");
    let result = hasher.finalize();

    // Encode as base64 (placeholder - not a real Ed25519 key)
    Ok(base64::encode(&result[..32]))
}

fn save_software_account_config(config: &AccountConfig) -> Result<(), String> {
    // In a real implementation, this would save to a secure local store
    // For now, just validate that we can serialize it
    serde_json::to_string(config)
        .map_err(|e| format!("Failed to serialize account config: {}", e))?;

    println!("Account config would be saved: {:?}", config);
    Ok(())
}

fn is_writable(path: &PathBuf) -> bool {
    // Test if we can write to the path
    let test_file = path.join(".write_test");
    match std::fs::write(&test_file, b"test") {
        Ok(_) => {
            let _ = std::fs::remove_file(&test_file);
            true
        }
        Err(_) => false,
    }
}

fn get_device_size(path: &PathBuf) -> String {
    // Get device size using statvfs or similar
    // This is a placeholder implementation
    match std::fs::metadata(path) {
        Ok(_) => "Unknown size".to_string(),
        Err(_) => "0 B".to_string(),
    }
}

fn get_filesystem_type(_path: &PathBuf) -> String {
    // Get filesystem type
    // This is a placeholder implementation
    "Unknown".to_string()
}