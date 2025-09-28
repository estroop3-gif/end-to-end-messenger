use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use anyhow::{Result, Context};
use serde::{Serialize, Deserialize};
use tauri::{State, command};

use crate::settings_store::{SecureSettings, Settings, AccessMode};
use crate::access_modes::{AccessModeManager, HazardWarning, PasswordStrength, AuthenticatedSession};
use crate::admin_approvals::{AdminApprovalManager, ApprovalRequest, ApprovalChallenge, AdminAction, ActionDetails, RiskLevel, AuditEntry};
use crate::fullwipe_prep::{FullWipePreparation, WipePlan, TargetDevice, WipeMethod, DeviceInfo, USBCreationRequest};

// Application state
pub struct AppState {
    pub access_manager: Arc<AccessModeManager>,
    pub admin_manager: Arc<AdminApprovalManager>,
    pub fullwipe_prep: Arc<FullWipePreparation>,
    pub current_settings: Arc<Mutex<Option<Settings>>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SettingsResponse {
    pub success: bool,
    pub settings: Option<Settings>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub success: bool,
    pub session: Option<AuthenticatedSession>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApprovalResponse {
    pub success: bool,
    pub challenge: Option<ApprovalChallenge>,
    pub audit_entry: Option<AuditEntry>,
    pub error: Option<String>,
}

// Settings commands
#[command]
pub async fn settings_load(
    access_mode: String,
    passphrase: Option<String>,
    state: State<'_, AppState>,
) -> Result<SettingsResponse, String> {
    let settings_result = match access_mode.as_str() {
        "hardware_key" => {
            state.access_manager.authenticate_with_hardware_key()
                .and_then(|_| {
                    // Load settings with hardware key
                    // This would integrate with the secure settings loading
                    Ok(Settings::default()) // Placeholder
                })
        }
        "local_only" => {
            if let Some(phrase) = passphrase {
                state.access_manager.authenticate_with_passphrase(&phrase)
                    .and_then(|_| {
                        // Load settings with passphrase
                        Ok(Settings::default()) // Placeholder
                    })
            } else {
                Err(anyhow::anyhow!("Passphrase required for local-only access"))
            }
        }
        _ => Err(anyhow::anyhow!("Invalid access mode")),
    };

    match settings_result {
        Ok(settings) => {
            *state.current_settings.lock().unwrap() = Some(settings.clone());
            Ok(SettingsResponse {
                success: true,
                settings: Some(settings),
                error: None,
            })
        }
        Err(e) => Ok(SettingsResponse {
            success: false,
            settings: None,
            error: Some(e.to_string()),
        }),
    }
}

#[command]
pub async fn settings_save(
    settings: Settings,
    state: State<'_, AppState>,
) -> Result<SettingsResponse, String> {
    // Verify user is authenticated
    if !state.access_manager.is_authenticated() {
        return Ok(SettingsResponse {
            success: false,
            settings: None,
            error: Some("Not authenticated".to_string()),
        });
    }

    // Save settings (this would use the SecureSettings instance)
    *state.current_settings.lock().unwrap() = Some(settings.clone());

    Ok(SettingsResponse {
        success: true,
        settings: Some(settings),
        error: None,
    })
}

// Access mode commands
#[command]
pub async fn authenticate_hardware_key(
    state: State<'_, AppState>,
) -> Result<AuthResponse, String> {
    match state.access_manager.authenticate_with_hardware_key() {
        Ok(session) => Ok(AuthResponse {
            success: true,
            session: Some(session),
            error: None,
        }),
        Err(e) => Ok(AuthResponse {
            success: false,
            session: None,
            error: Some(e.to_string()),
        }),
    }
}

#[command]
pub async fn authenticate_passphrase(
    passphrase: String,
    state: State<'_, AppState>,
) -> Result<AuthResponse, String> {
    match state.access_manager.authenticate_with_passphrase(&passphrase) {
        Ok(session) => Ok(AuthResponse {
            success: true,
            session: Some(session),
            error: None,
        }),
        Err(e) => Ok(AuthResponse {
            success: false,
            session: None,
            error: Some(e.to_string()),
        }),
    }
}

#[command]
pub async fn check_hardware_key_requirement(
    state: State<'_, AppState>,
) -> Result<bool, String> {
    state.access_manager.check_hardware_key_requirement()
        .map_err(|e| e.to_string())
}

#[command]
pub async fn get_local_access_warning(
    state: State<'_, AppState>,
) -> Result<HazardWarning, String> {
    Ok(state.access_manager.get_local_access_warning())
}

#[command]
pub async fn validate_passphrase_strength(
    passphrase: String,
    state: State<'_, AppState>,
) -> Result<PasswordStrength, String> {
    state.access_manager.validate_passphrase_strength(&passphrase)
        .map_err(|e| e.to_string())
}

#[command]
pub async fn enable_local_access(
    passphrase: String,
    confirmation: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    match state.access_manager.enable_local_access(&passphrase, &confirmation) {
        Ok(()) => Ok(true),
        Err(e) => Err(e.to_string()),
    }
}

#[command]
pub async fn disable_local_access(
    state: State<'_, AppState>,
) -> Result<bool, String> {
    match state.access_manager.disable_local_access() {
        Ok(()) => Ok(true),
        Err(e) => Err(e.to_string()),
    }
}

#[command]
pub async fn lock_session(
    state: State<'_, AppState>,
) -> Result<bool, String> {
    state.access_manager.lock();
    Ok(true)
}

// Admin approval commands
#[command]
pub async fn request_admin_approval(
    action: String,
    description: String,
    justification: String,
    state: State<'_, AppState>,
) -> Result<ApprovalResponse, String> {
    let admin_action = match action.as_str() {
        "enable_local_access" => AdminAction::EnableLocalOnlyAccess,
        "enable_full_wipe" => AdminAction::EnableFullDriveWipe,
        "create_wipe_usb" => AdminAction::CreateWipeUSB,
        "lock_settings" => AdminAction::LockSettings,
        _ => return Ok(ApprovalResponse {
            success: false,
            challenge: None,
            audit_entry: None,
            error: Some("Invalid admin action".to_string()),
        }),
    };

    let request = ApprovalRequest {
        action: admin_action.clone(),
        details: ActionDetails {
            description,
            previous_value: None,
            new_value: None,
            additional_context: std::collections::HashMap::new(),
        },
        justification,
        risk_level: state.admin_manager.get_risk_level(&admin_action),
        required_confirmations: 1,
    };

    match state.admin_manager.request_approval(request) {
        Ok(challenge) => Ok(ApprovalResponse {
            success: true,
            challenge: Some(challenge),
            audit_entry: None,
            error: None,
        }),
        Err(e) => Ok(ApprovalResponse {
            success: false,
            challenge: None,
            audit_entry: None,
            error: Some(e.to_string()),
        }),
    }
}

#[command]
pub async fn grant_admin_approval_hardware(
    action: String,
    description: String,
    justification: String,
    confirmation_phrase: String,
    expected_phrase: String,
    state: State<'_, AppState>,
) -> Result<ApprovalResponse, String> {
    let admin_action = match action.as_str() {
        "enable_local_access" => AdminAction::EnableLocalOnlyAccess,
        "enable_full_wipe" => AdminAction::EnableFullDriveWipe,
        "create_wipe_usb" => AdminAction::CreateWipeUSB,
        "lock_settings" => AdminAction::LockSettings,
        _ => return Ok(ApprovalResponse {
            success: false,
            challenge: None,
            audit_entry: None,
            error: Some("Invalid admin action".to_string()),
        }),
    };

    let request = ApprovalRequest {
        action: admin_action.clone(),
        details: ActionDetails {
            description,
            previous_value: None,
            new_value: None,
            additional_context: std::collections::HashMap::new(),
        },
        justification,
        risk_level: state.admin_manager.get_risk_level(&admin_action),
        required_confirmations: 1,
    };

    match state.admin_manager.grant_approval_with_hardware_key(request, &confirmation_phrase, &expected_phrase) {
        Ok(audit_entry) => Ok(ApprovalResponse {
            success: true,
            challenge: None,
            audit_entry: Some(audit_entry),
            error: None,
        }),
        Err(e) => Ok(ApprovalResponse {
            success: false,
            challenge: None,
            audit_entry: None,
            error: Some(e.to_string()),
        }),
    }
}

#[command]
pub async fn grant_admin_approval_passphrase(
    action: String,
    description: String,
    justification: String,
    admin_passphrase: String,
    confirmation_phrase: String,
    expected_phrase: String,
    state: State<'_, AppState>,
) -> Result<ApprovalResponse, String> {
    let admin_action = match action.as_str() {
        "enable_local_access" => AdminAction::EnableLocalOnlyAccess,
        "enable_full_wipe" => AdminAction::EnableFullDriveWipe,
        "create_wipe_usb" => AdminAction::CreateWipeUSB,
        "lock_settings" => AdminAction::LockSettings,
        _ => return Ok(ApprovalResponse {
            success: false,
            challenge: None,
            audit_entry: None,
            error: Some("Invalid admin action".to_string()),
        }),
    };

    let request = ApprovalRequest {
        action: admin_action.clone(),
        details: ActionDetails {
            description,
            previous_value: None,
            new_value: None,
            additional_context: std::collections::HashMap::new(),
        },
        justification,
        risk_level: state.admin_manager.get_risk_level(&admin_action),
        required_confirmations: 1,
    };

    match state.admin_manager.grant_approval_with_passphrase(request, &admin_passphrase, &confirmation_phrase, &expected_phrase) {
        Ok(audit_entry) => Ok(ApprovalResponse {
            success: true,
            challenge: None,
            audit_entry: Some(audit_entry),
            error: None,
        }),
        Err(e) => Ok(ApprovalResponse {
            success: false,
            challenge: None,
            audit_entry: None,
            error: Some(e.to_string()),
        }),
    }
}

#[command]
pub async fn get_audit_log(
    state: State<'_, AppState>,
) -> Result<Vec<AuditEntry>, String> {
    Ok(state.admin_manager.get_audit_log())
}

// Full wipe commands
#[command]
pub async fn list_storage_devices(
    state: State<'_, AppState>,
) -> Result<Vec<DeviceInfo>, String> {
    state.fullwipe_prep.list_storage_devices()
        .map_err(|e| e.to_string())
}

#[command]
pub async fn create_wipe_plan(
    device_path: String,
    device_id: String,
    serial_number: Option<String>,
    model: Option<String>,
    size_bytes: u64,
    wipe_method: String,
    state: State<'_, AppState>,
) -> Result<WipePlan, String> {
    let target_device = TargetDevice {
        device_path,
        device_id,
        serial_number,
        model,
        size_bytes,
        verified_twice: true,
    };

    let method = match wipe_method.as_str() {
        "secure_erase" => WipeMethod::SecureErase,
        "multi_pass_random" => WipeMethod::MultiPassRandom,
        "single_pass_zero" => WipeMethod::SinglePassZero,
        "blk_discard" => WipeMethod::BlkDiscard,
        "hybrid" => WipeMethod::Hybrid,
        _ => return Err("Invalid wipe method".to_string()),
    };

    state.fullwipe_prep.create_wipe_plan(target_device, method)
        .map_err(|e| e.to_string())
}

#[command]
pub async fn create_wipe_usb(
    usb_device_path: String,
    wipe_plan: WipePlan,
    include_verification_tools: bool,
    make_bootable: bool,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let request = USBCreationRequest {
        usb_device_path,
        wipe_plan,
        include_verification_tools,
        make_bootable,
    };

    match state.fullwipe_prep.create_wipe_usb(request) {
        Ok(()) => Ok(true),
        Err(e) => Err(e.to_string()),
    }
}

#[command]
pub async fn validate_wipe_target(
    device_path: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    match state.fullwipe_prep.validate_wipe_target(&device_path) {
        Ok(()) => Ok(true),
        Err(e) => Err(e.to_string()),
    }
}

// Utility commands
#[command]
pub async fn get_current_session(
    state: State<'_, AppState>,
) -> Result<Option<AuthenticatedSession>, String> {
    Ok(state.access_manager.get_current_session())
}

#[command]
pub async fn is_authenticated(
    state: State<'_, AppState>,
) -> Result<bool, String> {
    Ok(state.access_manager.is_authenticated())
}

#[command]
pub async fn update_activity(
    state: State<'_, AppState>,
) -> Result<bool, String> {
    state.access_manager.update_activity()
        .map(|_| true)
        .map_err(|e| e.to_string())
}