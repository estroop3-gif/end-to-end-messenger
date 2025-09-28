// Secure Messaging & Session Cipher Suite
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::{AppHandle, Manager, State};
use std::sync::Mutex;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

mod session;
mod session_commands;
mod login_commands;
mod settings_store;
mod keydetect;

use session::SessionManager;
use login_commands::LoginState;

// Application state
#[derive(Default)]
struct AppState {
    session_manager: Mutex<SessionManager>,
}

fn main() {
    println!("Starting Secure Messaging & Session Cipher Suite v1.0.0");

    tauri::Builder::default()
        .manage(AppState::default())
        .manage(LoginState::new())
        .invoke_handler(tauri::generate_handler![
            // Session cipher commands
            session_commands::generate_cipher_code,
            session_commands::start_cipher_session,
            session_commands::join_cipher_session,
            session_commands::encrypt_session_message,
            session_commands::decrypt_session_message,
            session_commands::end_cipher_session,
            session_commands::get_session_info,
            session_commands::list_active_sessions,
            session_commands::validate_cipher_code_input,
            // Login and authentication commands
            login_commands::set_local_passphrase_cmd,
            login_commands::verify_local_passphrase_cmd,
            login_commands::set_hardkey_mode_cmd,
            login_commands::check_hardkey_cmd,
            login_commands::settings_load_cmd,
            login_commands::logout_cmd,
            login_commands::is_authenticated_cmd,
            login_commands::clear_local_credential_cmd
        ])
        .run(tauri::generate_context!())
        .expect("Error while running tauri application");
}