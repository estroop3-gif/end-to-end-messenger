use tauri::{command, State};
use serde::{Serialize, Deserialize};
use anyhow::Result;

use crate::session::{SessionManager, SessionInfo, SessionOptions, CipherCode, CipherAlgorithm, Argon2Params, PassphraseMode};

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionResponse {
    pub success: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CipherCodeRequest {
    pub def_id: String,
    pub label: String,
    pub algorithm: String, // "caesar", "vigenere", "otp", "aead"
    pub algorithm_params: serde_json::Value,
    pub ttl_minutes: Option<u64>,
    pub recipient_pubkey: Option<String>,
    pub embed_secret: bool,
    pub confirm_danger: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CipherCodeResponse {
    pub cipher_code: CipherCode,
    pub short_code: String,
    pub qr_code_png: Vec<u8>, // Base64 encoded PNG
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionStartRequest {
    pub session_id: Option<String>,
    pub cipher_code: Option<CipherCode>,
    pub cipher_code_string: Option<String>, // Base58 encoded
    pub participants: Vec<String>,
    pub options: Option<SessionOptions>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionJoinRequest {
    pub session_id: String,
    pub cipher_code: Option<CipherCode>,
    pub cipher_code_string: Option<String>,
    pub passphrase: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionMessageRequest {
    pub session_id: String,
    pub plaintext: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionMessageResponse {
    pub session_ciphertext: Vec<u8>, // Base64 will be applied by serde
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionDecryptRequest {
    pub session_id: String,
    pub session_ciphertext: Vec<u8>,
}

/// Generate a cipher code from cipher definition
#[command]
pub async fn generate_cipher_code(
    request: CipherCodeRequest,
    session_manager: State<'_, SessionManager>,
) -> Result<SessionResponse, String> {
    // Validate dangerous embedding
    if request.embed_secret && request.confirm_danger != Some(true) {
        return Ok(SessionResponse {
            success: false,
            data: None,
            error: Some("Must confirm danger when embedding secrets in cipher code".to_string()),
        });
    }

    // Parse algorithm
    let algorithm = match request.algorithm.as_str() {
        "caesar" => {
            let shift = request.algorithm_params.get("shift")
                .and_then(|v| v.as_i64())
                .ok_or("Missing or invalid shift parameter for Caesar cipher")?;
            CipherAlgorithm::Caesar { shift: shift as i32 }
        },
        "vigenere" => {
            CipherAlgorithm::Vigenere {
                keyword_encrypted: Vec::new() // Will be filled by session manager
            }
        },
        "otp" => {
            let pad_id = request.algorithm_params.get("pad_id")
                .and_then(|v| v.as_str())
                .ok_or("Missing pad_id for OTP cipher")?;
            let offset = request.algorithm_params.get("offset")
                .and_then(|v| v.as_u64())
                .ok_or("Missing offset for OTP cipher")?;
            let length = request.algorithm_params.get("length")
                .and_then(|v| v.as_u64())
                .ok_or("Missing length for OTP cipher")?;

            CipherAlgorithm::OTP {
                pad_id: pad_id.to_string(),
                offset,
                length,
                pad_hmac: Vec::new(), // Will be calculated
            }
        },
        "aead" => {
            let memory_cost = request.algorithm_params.get("memory_cost")
                .and_then(|v| v.as_u64())
                .unwrap_or(65536) as u32;
            let time_cost = request.algorithm_params.get("time_cost")
                .and_then(|v| v.as_u64())
                .unwrap_or(3) as u32;
            let parallelism = request.algorithm_params.get("parallelism")
                .and_then(|v| v.as_u64())
                .unwrap_or(1) as u32;

            CipherAlgorithm::AEAD {
                kdf_salt: vec![0u8; 32], // Will be generated
                argon2_params: Argon2Params {
                    memory_cost,
                    time_cost,
                    parallelism,
                },
                passphrase_mode: PassphraseMode::RequireInput, // Will be determined
            }
        },
        _ => return Ok(SessionResponse {
            success: false,
            data: None,
            error: Some(format!("Unsupported algorithm: {}", request.algorithm)),
        }),
    };

    // Convert recipient pubkey
    let recipient_pubkey = request.recipient_pubkey
        .as_ref()
        .map(|s| base64::decode(s))
        .transpose()
        .map_err(|e| format!("Invalid recipient public key: {}", e))?;

    match session_manager.generate_cipher_code(
        &request.def_id,
        &request.label,
        algorithm,
        request.ttl_minutes,
        recipient_pubkey.as_deref(),
        request.embed_secret,
    ) {
        Ok((cipher_code, short_code, qr_bytes)) => {
            let response = CipherCodeResponse {
                cipher_code,
                short_code,
                qr_code_png: qr_bytes,
            };
            Ok(SessionResponse {
                success: true,
                data: Some(serde_json::to_value(response).unwrap()),
                error: None,
            })
        },
        Err(e) => Ok(SessionResponse {
            success: false,
            data: None,
            error: Some(e.to_string()),
        }),
    }
}

/// Start a new cipher session
#[command]
pub async fn start_cipher_session(
    request: SessionStartRequest,
    session_manager: State<'_, SessionManager>,
) -> Result<SessionResponse, String> {
    // Parse cipher code if provided as string
    let cipher_code = if let Some(code) = request.cipher_code {
        code
    } else if let Some(code_string) = request.cipher_code_string {
        parse_cipher_code_string(&code_string)
            .map_err(|e| format!("Failed to parse cipher code: {}", e))?
    } else {
        return Ok(SessionResponse {
            success: false,
            data: None,
            error: Some("Either cipher_code or cipher_code_string must be provided".to_string()),
        });
    };

    let ttl_minutes = request.options.as_ref()
        .and_then(|opts| opts.ttl_minutes);

    match session_manager.start_session(
        request.session_id,
        cipher_code,
        request.participants,
        ttl_minutes,
    ) {
        Ok(session_id) => Ok(SessionResponse {
            success: true,
            data: Some(serde_json::json!({ "session_id": session_id })),
            error: None,
        }),
        Err(e) => Ok(SessionResponse {
            success: false,
            data: None,
            error: Some(e.to_string()),
        }),
    }
}

/// Join an existing cipher session
#[command]
pub async fn join_cipher_session(
    request: SessionJoinRequest,
    session_manager: State<'_, SessionManager>,
) -> Result<SessionResponse, String> {
    // Parse cipher code if provided as string
    let cipher_code = if let Some(code) = request.cipher_code {
        code
    } else if let Some(code_string) = request.cipher_code_string {
        parse_cipher_code_string(&code_string)
            .map_err(|e| format!("Failed to parse cipher code: {}", e))?
    } else {
        return Ok(SessionResponse {
            success: false,
            data: None,
            error: Some("Either cipher_code or cipher_code_string must be provided".to_string()),
        });
    };

    match session_manager.join_session(
        &request.session_id,
        cipher_code,
        request.passphrase.as_deref(),
    ) {
        Ok(()) => Ok(SessionResponse {
            success: true,
            data: Some(serde_json::json!({ "joined": true })),
            error: None,
        }),
        Err(e) => Ok(SessionResponse {
            success: false,
            data: None,
            error: Some(e.to_string()),
        }),
    }
}

/// Encrypt a message using session cipher
#[command]
pub async fn encrypt_session_message(
    request: SessionMessageRequest,
    session_manager: State<'_, SessionManager>,
) -> Result<SessionResponse, String> {
    match session_manager.encrypt_session_message(&request.session_id, &request.plaintext) {
        Ok(ciphertext) => {
            let response = SessionMessageResponse {
                session_ciphertext: ciphertext,
            };
            Ok(SessionResponse {
                success: true,
                data: Some(serde_json::to_value(response).unwrap()),
                error: None,
            })
        },
        Err(e) => Ok(SessionResponse {
            success: false,
            data: None,
            error: Some(e.to_string()),
        }),
    }
}

/// Decrypt a session message
#[command]
pub async fn decrypt_session_message(
    request: SessionDecryptRequest,
    session_manager: State<'_, SessionManager>,
) -> Result<SessionResponse, String> {
    match session_manager.decrypt_session_message(&request.session_id, &request.session_ciphertext) {
        Ok(plaintext) => Ok(SessionResponse {
            success: true,
            data: Some(serde_json::json!({ "plaintext": plaintext })),
            error: None,
        }),
        Err(e) => Ok(SessionResponse {
            success: false,
            data: None,
            error: Some(e.to_string()),
        }),
    }
}

/// End a cipher session
#[command]
pub async fn end_cipher_session(
    session_id: String,
    re_envelope: bool,
    session_manager: State<'_, SessionManager>,
) -> Result<SessionResponse, String> {
    match session_manager.end_session(&session_id, re_envelope) {
        Ok(()) => Ok(SessionResponse {
            success: true,
            data: Some(serde_json::json!({ "ended": true })),
            error: None,
        }),
        Err(e) => Ok(SessionResponse {
            success: false,
            data: None,
            error: Some(e.to_string()),
        }),
    }
}

/// Get session information
#[command]
pub async fn get_session_info(
    session_id: String,
    session_manager: State<'_, SessionManager>,
) -> Result<SessionResponse, String> {
    match session_manager.get_session_info(&session_id) {
        Ok(Some(info)) => Ok(SessionResponse {
            success: true,
            data: Some(serde_json::to_value(info).unwrap()),
            error: None,
        }),
        Ok(None) => Ok(SessionResponse {
            success: false,
            data: None,
            error: Some("Session not found".to_string()),
        }),
        Err(e) => Ok(SessionResponse {
            success: false,
            data: None,
            error: Some(e.to_string()),
        }),
    }
}

/// List active sessions
#[command]
pub async fn list_active_sessions(
    session_manager: State<'_, SessionManager>,
) -> Result<SessionResponse, String> {
    // TODO: Implement list_active_sessions in SessionManager
    Ok(SessionResponse {
        success: true,
        data: Some(serde_json::json!({ "sessions": [] })),
        error: None,
    })
}

/// Parse a cipher code from base58 string
fn parse_cipher_code_string(code_string: &str) -> Result<CipherCode> {
    let compressed_data = bs58::decode(code_string)
        .into_vec()
        .map_err(|e| anyhow::anyhow!("Invalid base58 encoding: {}", e))?;

    // TODO: Implement decompression
    let json_data = compressed_data; // Placeholder

    let cipher_code: CipherCode = serde_json::from_slice(&json_data)
        .map_err(|e| anyhow::anyhow!("Invalid cipher code format: {}", e))?;

    Ok(cipher_code)
}

/// Validate cipher code input (UI helper)
#[command]
pub async fn validate_cipher_code_input(
    code_input: String,
) -> Result<SessionResponse, String> {
    match parse_cipher_code_string(&code_input) {
        Ok(cipher_code) => Ok(SessionResponse {
            success: true,
            data: Some(serde_json::json!({
                "valid": true,
                "label": cipher_code.label,
                "algorithm": format!("{:?}", cipher_code.algorithm).split('{').next().unwrap(),
                "expires_at": cipher_code.expires_at
            })),
            error: None,
        }),
        Err(e) => Ok(SessionResponse {
            success: false,
            data: Some(serde_json::json!({ "valid": false })),
            error: Some(e.to_string()),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_code_request_parsing() {
        let request = CipherCodeRequest {
            def_id: "test".to_string(),
            label: "Test Caesar".to_string(),
            algorithm: "caesar".to_string(),
            algorithm_params: serde_json::json!({ "shift": 3 }),
            ttl_minutes: Some(60),
            recipient_pubkey: None,
            embed_secret: false,
            confirm_danger: None,
        };

        assert_eq!(request.algorithm, "caesar");
        assert_eq!(request.algorithm_params.get("shift").unwrap().as_i64().unwrap(), 3);
    }

    #[test]
    fn test_session_start_request() {
        let request = SessionStartRequest {
            session_id: Some("test-session".to_string()),
            cipher_code: None,
            cipher_code_string: Some("test_code".to_string()),
            participants: vec!["user1".to_string(), "user2".to_string()],
            options: Some(SessionOptions::default()),
        };

        assert_eq!(request.participants.len(), 2);
    }
}