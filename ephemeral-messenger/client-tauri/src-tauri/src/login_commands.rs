use tauri::{command, AppHandle, State};
use std::sync::Mutex;
use anyhow::Result;
use serde::{Serialize, Deserialize};

use crate::settings_store::{SettingsStore, Settings, AccessMode};
use crate::keydetect::HardwareKeyDetector;

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HardKeyStatus {
    pub present: bool,
    pub fingerprint: Option<String>,
    pub device_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SettingsResponse {
    pub version: u32,
    pub access_mode: String,
    pub has_credential: bool,
    pub updated_at: i64,
}

pub struct LoginState {
    pub settings_store: Mutex<SettingsStore>,
    pub key_detector: Mutex<HardwareKeyDetector>,
    pub authenticated: Mutex<bool>,
}

impl LoginState {
    pub fn new(data_dir: std::path::PathBuf) -> Result<Self> {
        Ok(LoginState {
            settings_store: Mutex::new(SettingsStore::new(data_dir)?),
            key_detector: Mutex::new(HardwareKeyDetector::new()?),
            authenticated: Mutex::new(false),
        })
    }
}

#[command]
pub async fn set_local_passphrase_cmd(
    passphrase: String,
    state: State<'_, LoginState>,
) -> Result<LoginResponse, String> {
    if passphrase.is_empty() {
        return Ok(LoginResponse {
            ok: false,
            error: Some("Passphrase cannot be empty".to_string()),
        });
    }

    let store = state.settings_store.lock().map_err(|e| e.to_string())?;

    match store.set_local_passphrase(&passphrase) {
        Ok(()) => {
            // Mark as authenticated since we just set up the passphrase
            *state.authenticated.lock().map_err(|e| e.to_string())? = true;
            Ok(LoginResponse {
                ok: true,
                error: None,
            })
        }
        Err(e) => Ok(LoginResponse {
            ok: false,
            error: Some(e.to_string()),
        }),
    }
}

#[command]
pub async fn verify_local_passphrase_cmd(
    passphrase: String,
    state: State<'_, LoginState>,
) -> Result<LoginResponse, String> {
    if passphrase.is_empty() {
        return Ok(LoginResponse {
            ok: false,
            error: Some("Passphrase cannot be empty".to_string()),
        });
    }

    let store = state.settings_store.lock().map_err(|e| e.to_string())?;

    match store.verify_local_passphrase(&passphrase) {
        Ok(true) => {
            // Mark as authenticated
            *state.authenticated.lock().map_err(|e| e.to_string())? = true;
            Ok(LoginResponse {
                ok: true,
                error: None,
            })
        }
        Ok(false) => Ok(LoginResponse {
            ok: false,
            error: Some("Invalid passphrase".to_string()),
        }),
        Err(e) => Ok(LoginResponse {
            ok: false,
            error: Some(format!("Authentication error: {}", e)),
        }),
    }
}

#[command]
pub async fn set_hardkey_mode_cmd(
    state: State<'_, LoginState>,
) -> Result<LoginResponse, String> {
    // First check if a hardware key is present
    let key_detector = state.key_detector.lock().map_err(|e| e.to_string())?;
    let keys = key_detector.scan_for_keys().map_err(|e| e.to_string())?;

    if keys.is_empty() {
        return Ok(LoginResponse {
            ok: false,
            error: Some("No hardware key detected. Please insert a valid hardware key.".to_string()),
        });
    }

    // Validate the first detected key
    let key_path = &keys[0].device_path;
    match key_detector.validate_key(key_path) {
        Ok(true) => {
            // Mark as authenticated and switch mode
            *state.authenticated.lock().map_err(|e| e.to_string())? = true;

            let store = state.settings_store.lock().map_err(|e| e.to_string())?;
            match store.set_hardkey_mode() {
                Ok(()) => Ok(LoginResponse {
                    ok: true,
                    error: None,
                }),
                Err(e) => Ok(LoginResponse {
                    ok: false,
                    error: Some(e.to_string()),
                }),
            }
        }
        Ok(false) => Ok(LoginResponse {
            ok: false,
            error: Some("Hardware key validation failed".to_string()),
        }),
        Err(e) => Ok(LoginResponse {
            ok: false,
            error: Some(format!("Key validation error: {}", e)),
        }),
    }
}

#[command]
pub async fn check_hardkey_cmd(
    state: State<'_, LoginState>,
) -> Result<HardKeyStatus, String> {
    let key_detector = state.key_detector.lock().map_err(|e| e.to_string())?;

    match key_detector.scan_for_keys() {
        Ok(keys) => {
            if keys.is_empty() {
                Ok(HardKeyStatus {
                    present: false,
                    fingerprint: None,
                    device_path: None,
                })
            } else {
                let key = &keys[0];
                // Validate the key
                match key_detector.validate_key(&key.device_path) {
                    Ok(true) => Ok(HardKeyStatus {
                        present: true,
                        fingerprint: Some(key.device_id.clone()),
                        device_path: Some(key.device_path.clone()),
                    }),
                    Ok(false) => Ok(HardKeyStatus {
                        present: false,
                        fingerprint: None,
                        device_path: None,
                    }),
                    Err(_) => Ok(HardKeyStatus {
                        present: false,
                        fingerprint: None,
                        device_path: None,
                    }),
                }
            }
        }
        Err(_) => Ok(HardKeyStatus {
            present: false,
            fingerprint: None,
            device_path: None,
        }),
    }
}

#[command]
pub async fn settings_load_cmd(
    state: State<'_, LoginState>,
) -> Result<SettingsResponse, String> {
    let store = state.settings_store.lock().map_err(|e| e.to_string())?;

    match store.load_settings() {
        Ok(settings) => {
            let access_mode_str = match settings.access_mode {
                AccessMode::Hardkey => "hardkey".to_string(),
                AccessMode::LocalPassphrase => "local_passphrase".to_string(),
            };

            Ok(SettingsResponse {
                version: settings.version,
                access_mode: access_mode_str,
                has_credential: settings.credential.is_some(),
                updated_at: settings.updated_at,
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

#[command]
pub async fn logout_cmd(
    state: State<'_, LoginState>,
) -> Result<LoginResponse, String> {
    *state.authenticated.lock().map_err(|e| e.to_string())? = false;

    Ok(LoginResponse {
        ok: true,
        error: None,
    })
}

#[command]
pub async fn is_authenticated_cmd(
    state: State<'_, LoginState>,
) -> Result<bool, String> {
    Ok(*state.authenticated.lock().map_err(|e| e.to_string())?)
}

#[command]
pub async fn clear_local_credential_cmd(
    state: State<'_, LoginState>,
) -> Result<LoginResponse, String> {
    // Clear authentication status
    *state.authenticated.lock().map_err(|e| e.to_string())? = false;

    let store = state.settings_store.lock().map_err(|e| e.to_string())?;

    match store.clear_local_credential() {
        Ok(()) => Ok(LoginResponse {
            ok: true,
            error: None,
        }),
        Err(e) => Ok(LoginResponse {
            ok: false,
            error: Some(e.to_string()),
        }),
    }
}

// Utility function to check if user is authenticated for protected commands
pub fn require_authentication(state: &State<LoginState>) -> Result<(), String> {
    let authenticated = *state.authenticated.lock().map_err(|e| e.to_string())?;
    if !authenticated {
        Err("Authentication required".to_string())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tauri::test::{mock_app, MockRuntime};

    #[tokio::test]
    async fn test_passphrase_flow() {
        let temp_dir = TempDir::new().unwrap();
        let state = LoginState::new(temp_dir.path().to_path_buf()).unwrap();

        // Initially not authenticated
        let auth_status = is_authenticated_cmd(State::from(&state)).await.unwrap();
        assert!(!auth_status);

        // Set a passphrase
        let passphrase = "test_passphrase_123";
        let result = set_local_passphrase_cmd(passphrase.to_string(), State::from(&state)).await.unwrap();
        assert!(result.ok);

        // Should now be authenticated
        let auth_status = is_authenticated_cmd(State::from(&state)).await.unwrap();
        assert!(auth_status);

        // Logout
        let logout_result = logout_cmd(State::from(&state)).await.unwrap();
        assert!(logout_result.ok);

        // Should not be authenticated
        let auth_status = is_authenticated_cmd(State::from(&state)).await.unwrap();
        assert!(!auth_status);

        // Verify passphrase
        let verify_result = verify_local_passphrase_cmd(passphrase.to_string(), State::from(&state)).await.unwrap();
        assert!(verify_result.ok);

        // Should be authenticated again
        let auth_status = is_authenticated_cmd(State::from(&state)).await.unwrap();
        assert!(auth_status);
    }

    #[tokio::test]
    async fn test_invalid_passphrase() {
        let temp_dir = TempDir::new().unwrap();
        let state = LoginState::new(temp_dir.path().to_path_buf()).unwrap();

        // Set a passphrase first
        let passphrase = "valid_passphrase_123";
        let result = set_local_passphrase_cmd(passphrase.to_string(), State::from(&state)).await.unwrap();
        assert!(result.ok);

        // Logout
        logout_cmd(State::from(&state)).await.unwrap();

        // Try wrong passphrase
        let verify_result = verify_local_passphrase_cmd("wrong_passphrase".to_string(), State::from(&state)).await.unwrap();
        assert!(!verify_result.ok);
        assert!(verify_result.error.is_some());

        // Should not be authenticated
        let auth_status = is_authenticated_cmd(State::from(&state)).await.unwrap();
        assert!(!auth_status);
    }

    #[tokio::test]
    async fn test_settings_load() {
        let temp_dir = TempDir::new().unwrap();
        let state = LoginState::new(temp_dir.path().to_path_buf()).unwrap();

        // Load default settings
        let settings = settings_load_cmd(State::from(&state)).await.unwrap();
        assert_eq!(settings.access_mode, "hardkey");
        assert!(!settings.has_credential);

        // Set passphrase
        let passphrase = "test_passphrase_123";
        set_local_passphrase_cmd(passphrase.to_string(), State::from(&state)).await.unwrap();

        // Load settings again
        let settings = settings_load_cmd(State::from(&state)).await.unwrap();
        assert_eq!(settings.access_mode, "local_passphrase");
        assert!(settings.has_credential);
    }

    #[tokio::test]
    async fn test_empty_passphrase() {
        let temp_dir = TempDir::new().unwrap();
        let state = LoginState::new(temp_dir.path().to_path_buf()).unwrap();

        // Try empty passphrase
        let result = set_local_passphrase_cmd("".to_string(), State::from(&state)).await.unwrap();
        assert!(!result.ok);
        assert!(result.error.unwrap().contains("cannot be empty"));

        // Try verifying empty passphrase
        let verify_result = verify_local_passphrase_cmd("".to_string(), State::from(&state)).await.unwrap();
        assert!(!verify_result.ok);
        assert!(verify_result.error.unwrap().contains("cannot be empty"));
    }
}