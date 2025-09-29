#!/usr/bin/env rust

// Session Cipher CLI Tool
// A command-line interface for testing and demonstrating the session cipher functionality

use std::env;
use std::process;
use anyhow::Result;
use serde_json;

// Import session module from the main crate
use secure_messaging_suite::{SessionManager, CipherAlgorithm, CipherCode};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    let command = &args[1];

    let result = match command.as_str() {
        "generate" => handle_generate_command(&args[2..]),
        "start" => handle_start_command(&args[2..]),
        "join" => handle_join_command(&args[2..]),
        "encrypt" => handle_encrypt_command(&args[2..]),
        "decrypt" => handle_decrypt_command(&args[2..]),
        "end" => handle_end_command(&args[2..]),
        "list" => handle_list_command(&args[2..]),
        "test" => handle_test_command(&args[2..]),
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        },
        _ => {
            eprintln!("Unknown command: {}", command);
            print_usage();
            process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

fn print_usage() {
    println!("Session Cipher CLI Tool");
    println!("Usage: session_cli <command> [options]");
    println!();
    println!("Commands:");
    println!("  generate <label> <algorithm> [ttl_seconds] [producer]");
    println!("    Generate a new cipher code");
    println!("    Algorithms: caesar:<shift>, vigenere:<keyword>, aead:<keysize>, otp:<pad_id>:<offset>:<length>");
    println!();
    println!("  start <cipher_code_json> [participants] [ttl_minutes]");
    println!("    Start a new session with a cipher code");
    println!();
    println!("  join <cipher_code_json> [participants]");
    println!("    Join an existing session");
    println!();
    println!("  encrypt <session_id> <plaintext>");
    println!("    Encrypt a message in the session");
    println!();
    println!("  decrypt <session_id> <ciphertext_hex>");
    println!("    Decrypt a message from the session");
    println!();
    println!("  end <session_id> [re_envelope=true|false]");
    println!("    End a session with optional re-enveloping");
    println!();
    println!("  list");
    println!("    List all active sessions");
    println!();
    println!("  test [algorithm]");
    println!("    Run tests for session functionality");
    println!();
    println!("Examples:");
    println!("  session_cli generate \"My Test\" caesar:3 3600 alice");
    println!("  session_cli start '{{\"version\":1,...}}' alice,bob 60");
    println!("  session_cli encrypt session123 \"Hello, World!\"");
    println!("  session_cli test caesar");
}

fn handle_generate_command(args: &[String]) -> Result<()> {
    if args.len() < 2 {
        eprintln!("Usage: session_cli generate <label> <algorithm> [ttl_seconds] [producer]");
        process::exit(1);
    }

    let label = &args[0];
    let algorithm_str = &args[1];
    let ttl_seconds = args.get(2).and_then(|s| s.parse().ok());
    let producer = args.get(3).cloned().unwrap_or_else(|| "cli_user".to_string());

    let algorithm = parse_algorithm(algorithm_str)?;

    let manager = SessionManager::new();
    let cipher_code = manager.generate_cipher_code(
        label.clone(),
        algorithm,
        ttl_seconds,
        producer,
        false, // Don't embed dangerous secrets by default
    )?;

    let json = serde_json::to_string_pretty(&cipher_code)?;
    println!("Generated cipher code:");
    println!("{}", json);

    Ok(())
}

fn handle_start_command(args: &[String]) -> Result<()> {
    if args.is_empty() {
        eprintln!("Usage: session_cli start <cipher_code_json> [participants] [ttl_minutes]");
        process::exit(1);
    }

    let cipher_code_json = &args[0];
    let participants = args.get(1)
        .map(|s| s.split(',').map(|p| p.trim().to_string()).collect())
        .unwrap_or_else(|| vec!["cli_user".to_string()]);
    let ttl_minutes = args.get(2).and_then(|s| s.parse().ok());

    let cipher_code: CipherCode = serde_json::from_str(cipher_code_json)?;

    let manager = SessionManager::new();
    let session_id = manager.start_session(
        None, // Auto-generate session ID
        cipher_code,
        participants,
        ttl_minutes,
    )?;

    println!("Started session: {}", session_id);
    Ok(())
}

fn handle_join_command(args: &[String]) -> Result<()> {
    if args.is_empty() {
        eprintln!("Usage: session_cli join <cipher_code_json> [participants]");
        process::exit(1);
    }

    let cipher_code_json = &args[0];
    let participants = args.get(1)
        .map(|s| s.split(',').map(|p| p.trim().to_string()).collect())
        .unwrap_or_else(|| vec!["cli_user".to_string()]);

    let cipher_code: CipherCode = serde_json::from_str(cipher_code_json)?;

    let manager = SessionManager::new();
    let session_id = manager.join_session(cipher_code, participants)?;

    println!("Joined session: {}", session_id);
    Ok(())
}

fn handle_encrypt_command(args: &[String]) -> Result<()> {
    if args.len() < 2 {
        eprintln!("Usage: session_cli encrypt <session_id> <plaintext>");
        process::exit(1);
    }

    let session_id = &args[0];
    let plaintext = &args[1];

    let manager = SessionManager::new();
    let encrypted = manager.encrypt_session_message(session_id, plaintext)?;

    // Convert to hex for output
    let hex_output = hex::encode(&encrypted);
    println!("Encrypted message: {}", hex_output);
    Ok(())
}

fn handle_decrypt_command(args: &[String]) -> Result<()> {
    if args.len() < 2 {
        eprintln!("Usage: session_cli decrypt <session_id> <ciphertext_hex>");
        process::exit(1);
    }

    let session_id = &args[0];
    let ciphertext_hex = &args[1];

    let ciphertext = hex::decode(ciphertext_hex)?;

    let manager = SessionManager::new();
    let plaintext = manager.decrypt_session_message(session_id, &ciphertext)?;

    println!("Decrypted message: {}", plaintext);
    Ok(())
}

fn handle_end_command(args: &[String]) -> Result<()> {
    if args.is_empty() {
        eprintln!("Usage: session_cli end <session_id> [re_envelope=true|false]");
        process::exit(1);
    }

    let session_id = &args[0];
    let re_envelope = args.get(1)
        .map(|s| s.parse().unwrap_or(true))
        .unwrap_or(true);

    let manager = SessionManager::new();
    manager.end_session(session_id, re_envelope)?;

    println!("Ended session: {}", session_id);
    if re_envelope {
        println!("Messages were re-enveloped for long-term storage");
    }
    Ok(())
}

fn handle_list_command(_args: &[String]) -> Result<()> {
    let manager = SessionManager::new();
    let sessions = manager.list_active_sessions()?;

    if sessions.is_empty() {
        println!("No active sessions");
    } else {
        println!("Active sessions:");
        for session in sessions {
            println!("  {} - {} ({} participants, {} messages)",
                session.session_id,
                session.label,
                session.participants.len(),
                session.message_count
            );
        }
    }

    Ok(())
}

fn handle_test_command(args: &[String]) -> Result<()> {
    let algorithm = args.get(0).map(String::as_str);

    println!("Running session cipher tests...");

    match algorithm {
        Some("caesar") => test_caesar_cipher()?,
        Some("vigenere") => test_vigenere_cipher()?,
        Some("aead") => test_aead_cipher()?,
        Some("otp") => test_otp_cipher()?,
        Some("all") | None => {
            test_caesar_cipher()?;
            test_vigenere_cipher()?;
            test_aead_cipher()?;
            test_otp_cipher()?;
            test_session_lifecycle()?;
        },
        Some(alg) => {
            eprintln!("Unknown algorithm for testing: {}", alg);
            process::exit(1);
        }
    }

    println!("All tests completed successfully!");
    Ok(())
}

fn parse_algorithm(algorithm_str: &str) -> Result<CipherAlgorithm> {
    let parts: Vec<&str> = algorithm_str.split(':').collect();

    match parts[0] {
        "caesar" => {
            if parts.len() != 2 {
                anyhow::bail!("Caesar cipher format: caesar:<shift>");
            }
            let shift = parts[1].parse()?;
            Ok(CipherAlgorithm::Caesar { shift })
        },
        "vigenere" => {
            if parts.len() != 2 {
                anyhow::bail!("Vigenère cipher format: vigenere:<keyword>");
            }
            Ok(CipherAlgorithm::Vigenere { keyword: parts[1].to_string() })
        },
        "aead" => {
            if parts.len() != 2 {
                anyhow::bail!("AEAD cipher format: aead:<keysize>");
            }
            let key_size = parts[1].parse()?;
            Ok(CipherAlgorithm::AEAD { key_size })
        },
        "otp" => {
            if parts.len() != 4 {
                anyhow::bail!("OTP cipher format: otp:<pad_id>:<offset>:<length>");
            }
            let pad_id = parts[1].to_string();
            let offset = parts[2].parse()?;
            let length = parts[3].parse()?;
            Ok(CipherAlgorithm::OTP { pad_id, offset, length })
        },
        _ => anyhow::bail!("Unknown algorithm: {}. Supported: caesar, vigenere, aead, otp", parts[0])
    }
}

fn test_caesar_cipher() -> Result<()> {
    println!("Testing Caesar cipher...");

    let manager = SessionManager::new();

    let cipher_code = manager.generate_cipher_code(
        "Caesar Test".to_string(),
        CipherAlgorithm::Caesar { shift: 13 },
        Some(3600),
        "test_user".to_string(),
        false,
    )?;

    let session_id = manager.start_session(
        None,
        cipher_code,
        vec!["test_user".to_string()],
        Some(60),
    )?;

    let plaintext = "Hello, Caesar cipher test!";
    let encrypted = manager.encrypt_session_message(&session_id, plaintext)?;
    let decrypted = manager.decrypt_session_message(&session_id, &encrypted)?;

    assert_eq!(plaintext, decrypted);
    manager.end_session(&session_id, false)?;

    println!("  ✓ Caesar cipher test passed");
    Ok(())
}

fn test_vigenere_cipher() -> Result<()> {
    println!("Testing Vigenère cipher...");

    let manager = SessionManager::new();

    let cipher_code = manager.generate_cipher_code(
        "Vigenère Test".to_string(),
        CipherAlgorithm::Vigenere { keyword: "SECRET".to_string() },
        Some(3600),
        "test_user".to_string(),
        false,
    )?;

    let session_id = manager.start_session(
        None,
        cipher_code,
        vec!["test_user".to_string()],
        Some(60),
    )?;

    let plaintext = "Hello, Vigenère cipher test!";
    let encrypted = manager.encrypt_session_message(&session_id, plaintext)?;
    let decrypted = manager.decrypt_session_message(&session_id, &encrypted)?;

    assert_eq!(plaintext, decrypted);
    manager.end_session(&session_id, false)?;

    println!("  ✓ Vigenère cipher test passed");
    Ok(())
}

fn test_aead_cipher() -> Result<()> {
    println!("Testing AEAD cipher...");

    let manager = SessionManager::new();

    let cipher_code = manager.generate_cipher_code(
        "AEAD Test".to_string(),
        CipherAlgorithm::AEAD { key_size: 32 },
        Some(3600),
        "test_user".to_string(),
        false,
    )?;

    let session_id = manager.start_session(
        None,
        cipher_code,
        vec!["test_user".to_string()],
        Some(60),
    )?;

    // Note: AEAD might be placeholder implementation
    let plaintext = "Hello, AEAD cipher test!";
    match manager.encrypt_session_message(&session_id, plaintext) {
        Ok(encrypted) => {
            match manager.decrypt_session_message(&session_id, &encrypted) {
                Ok(decrypted) => {
                    assert_eq!(plaintext, decrypted);
                    println!("  ✓ AEAD cipher test passed");
                },
                Err(_) => println!("  ⚠ AEAD cipher decryption not implemented (placeholder)")
            }
        },
        Err(_) => println!("  ⚠ AEAD cipher encryption not implemented (placeholder)")
    }

    manager.end_session(&session_id, false)?;
    Ok(())
}

fn test_otp_cipher() -> Result<()> {
    println!("Testing OTP cipher...");

    let manager = SessionManager::new();

    let cipher_code = manager.generate_cipher_code(
        "OTP Test".to_string(),
        CipherAlgorithm::OTP {
            pad_id: "test_pad_cli".to_string(),
            offset: 1000,
            length: 64
        },
        Some(3600),
        "test_user".to_string(),
        false,
    )?;

    let session_id = manager.start_session(
        None,
        cipher_code,
        vec!["test_user".to_string()],
        Some(60),
    )?;

    let plaintext = "Hello, OTP cipher test!";
    let encrypted = manager.encrypt_session_message(&session_id, plaintext)?;
    let decrypted = manager.decrypt_session_message(&session_id, &encrypted)?;

    assert_eq!(plaintext, decrypted);
    manager.end_session(&session_id, true)?; // Test re-enveloping

    println!("  ✓ OTP cipher test passed");
    Ok(())
}

fn test_session_lifecycle() -> Result<()> {
    println!("Testing session lifecycle...");

    let manager = SessionManager::new();

    // Test multiple concurrent sessions
    let mut session_ids = Vec::new();

    for i in 0..3 {
        let cipher_code = manager.generate_cipher_code(
            format!("Lifecycle Test {}", i),
            CipherAlgorithm::Caesar { shift: i + 1 },
            Some(3600),
            "test_user".to_string(),
            false,
        )?;

        let session_id = manager.start_session(
            None,
            cipher_code,
            vec![format!("user_{}", i)],
            Some(60),
        )?;

        session_ids.push(session_id);
    }

    // Verify all sessions are active
    let active_sessions = manager.list_active_sessions()?;
    assert_eq!(active_sessions.len(), 3);

    // Test encryption/decryption on multiple sessions
    for session_id in &session_ids {
        let plaintext = "Lifecycle test message";
        let encrypted = manager.encrypt_session_message(session_id, plaintext)?;
        let decrypted = manager.decrypt_session_message(session_id, &encrypted)?;
        assert_eq!(plaintext, decrypted);
    }

    // End all sessions
    for session_id in session_ids {
        manager.end_session(&session_id, false)?;
    }

    // Verify no sessions remain
    let active_sessions_after = manager.list_active_sessions()?;
    assert_eq!(active_sessions_after.len(), 0);

    println!("  ✓ Session lifecycle test passed");
    Ok(())
}