// JESUS IS KING - Secure Messaging Application
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::State;
use std::sync::Mutex;
use anyhow::Result;

mod crypto_stub;
mod tor_integration;
mod signal_placeholder;
mod stubs;
mod settings_store;
mod wipe_manager;

use crypto_stub::CryptoManager;
use tor_integration::TorManager;
use settings_store::{SettingsStore, DeadManSwitchSettings};
use wipe_manager::{WipeManager, DmsPolicy};

// Application state with DMS support
struct AppState {
    crypto_manager: Mutex<CryptoManager>,
    tor_manager: Mutex<Option<TorManager>>,
    settings_store: Mutex<Option<SettingsStore>>,
    wipe_manager: Mutex<Option<WipeManager>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            crypto_manager: Mutex::new(CryptoManager::default()),
            tor_manager: Mutex::new(None),
            settings_store: Mutex::new(None),
            wipe_manager: Mutex::new(None),
        }
    }
}

// Simplified login state
#[derive(Default)]
struct LoginState {
    authenticated: Mutex<bool>,
}

impl LoginState {
    fn new() -> Self {
        Self::default()
    }
}

// Simplified Tauri commands
#[tauri::command]
async fn is_authenticated_cmd(state: State<'_, LoginState>) -> Result<bool, String> {
    let authenticated = state.authenticated.lock().unwrap();
    Ok(*authenticated)
}

#[tauri::command]
async fn set_local_passphrase_cmd(passphrase: String, state: State<'_, LoginState>) -> Result<(), String> {
    let mut authenticated = state.authenticated.lock().unwrap();
    *authenticated = !passphrase.is_empty();
    Ok(())
}

#[tauri::command]
async fn logout_cmd(state: State<'_, LoginState>) -> Result<(), String> {
    let mut authenticated = state.authenticated.lock().unwrap();
    *authenticated = false;
    Ok(())
}

#[tauri::command]
async fn get_current_identity(app_state: State<'_, AppState>) -> Result<crypto_stub::Identity, String> {
    let identity = {
        let mut crypto_manager = app_state.crypto_manager.lock().unwrap();
        crypto_manager.generate_identity(false, Some("test".to_string()))
    };
    identity.map_err(|e| e.to_string())
}

#[tauri::command]
async fn initialize_crypto(app_state: State<'_, AppState>) -> Result<(), String> {
    let result = {
        let mut crypto_manager = app_state.crypto_manager.lock().unwrap();
        crypto_manager.initialize()
    };
    result.map_err(|e| e.to_string())
}

// Dead-Man Switch Tauri commands
#[tauri::command]
async fn initialize_dms(app_state: State<'_, AppState>) -> Result<(), String> {
    use std::path::PathBuf;

    let data_dir = PathBuf::from("./data"); // Use simple path for now

    let settings_store = SettingsStore::new(data_dir.clone())
        .map_err(|e| format!("Failed to create settings store: {}", e))?;

    let wipe_manager = WipeManager::new(settings_store.clone(), data_dir);

    {
        let mut settings_guard = app_state.settings_store.lock().unwrap();
        *settings_guard = Some(settings_store);
    }

    {
        let mut wipe_guard = app_state.wipe_manager.lock().unwrap();
        *wipe_guard = Some(wipe_manager);
    }

    Ok(())
}

#[tauri::command]
async fn get_dms_settings(app_state: State<'_, AppState>) -> Result<DeadManSwitchSettings, String> {
    let settings_guard = app_state.settings_store.lock().unwrap();
    let settings_store = settings_guard.as_ref()
        .ok_or("Settings store not initialized")?;

    settings_store.get_dms_settings()
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn update_dms_settings(
    dms_settings: DeadManSwitchSettings,
    app_state: State<'_, AppState>
) -> Result<(), String> {
    let settings_guard = app_state.settings_store.lock().unwrap();
    let settings_store = settings_guard.as_ref()
        .ok_or("Settings store not initialized")?;

    settings_store.update_dms_settings(dms_settings)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn verify_dms_policy(
    policy_json: String,
    signature_b64: String,
    admin_pubkey_b64: String,
    app_state: State<'_, AppState>
) -> Result<DmsPolicy, String> {
    let wipe_guard = app_state.wipe_manager.lock().unwrap();
    let wipe_manager = wipe_guard.as_ref()
        .ok_or("Wipe manager not initialized")?;

    wipe_manager.verify_dms_policy(
        policy_json.as_bytes(),
        &signature_b64,
        &admin_pubkey_b64
    ).map_err(|e| e.to_string())
}

#[tauri::command]
async fn configure_dms(
    policy: DmsPolicy,
    signature: String,
    app_state: State<'_, AppState>
) -> Result<(), String> {
    let wipe_guard = app_state.wipe_manager.lock().unwrap();
    let wipe_manager = wipe_guard.as_ref()
        .ok_or("Wipe manager not initialized")?;

    wipe_manager.configure_dms(policy, signature)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn check_dms_status(app_state: State<'_, AppState>) -> Result<bool, String> {
    let wipe_guard = app_state.wipe_manager.lock().unwrap();
    let wipe_manager = wipe_guard.as_ref()
        .ok_or("Wipe manager not initialized")?;

    wipe_manager.check_dms_status()
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn perform_dms_checkin(app_state: State<'_, AppState>) -> Result<(), String> {
    let wipe_guard = app_state.wipe_manager.lock().unwrap();
    let wipe_manager = wipe_guard.as_ref()
        .ok_or("Wipe manager not initialized")?;

    wipe_manager.perform_checkin()
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn trigger_emergency_wipe(
    reason: String,
    app_state: State<'_, AppState>
) -> Result<(), String> {
    let wipe_guard = app_state.wipe_manager.lock().unwrap();
    let wipe_manager = wipe_guard.as_ref()
        .ok_or("Wipe manager not initialized")?;

    wipe_manager.trigger_emergency_wipe(&reason)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn disable_dms(
    admin_signature: String,
    app_state: State<'_, AppState>
) -> Result<(), String> {
    let wipe_guard = app_state.wipe_manager.lock().unwrap();
    let wipe_manager = wipe_guard.as_ref()
        .ok_or("Wipe manager not initialized")?;

    wipe_manager.disable_dms(&admin_signature)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_machine_identifier(app_state: State<'_, AppState>) -> Result<String, String> {
    let wipe_guard = app_state.wipe_manager.lock().unwrap();
    let wipe_manager = wipe_guard.as_ref()
        .ok_or("Wipe manager not initialized")?;

    wipe_manager.get_machine_identifier()
        .map_err(|e| e.to_string())
}

fn main() {
    println!("Starting Ephemeral Messenger v1.0.0 (Stub Implementation)");
    println!("✝️ Jesus is King - Secure Communication for His Glory");

    tauri::Builder::default()
        .manage(AppState::default())
        .manage(LoginState::new())
        .invoke_handler(tauri::generate_handler![
            is_authenticated_cmd,
            set_local_passphrase_cmd,
            logout_cmd,
            get_current_identity,
            initialize_crypto,
            initialize_dms,
            get_dms_settings,
            update_dms_settings,
            verify_dms_policy,
            configure_dms,
            check_dms_status,
            perform_dms_checkin,
            trigger_emergency_wipe,
            disable_dms,
            get_machine_identifier,
        ])
        .setup(|app| {
            println!("Application initialized successfully (stub implementation)");
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}