// Command-line demo for Phase 1: Core crypto and .securedoc format
// Tests encryption, document creation, and .securedoc file format

use anyhow::Result;
use clap::{Arg, Command};
use std::fs;
use std::path::Path;

// Import our library
use secure_messaging_suite::{
    CryptoManager, SecureDocFormat, VERSION,
    init_logging
};

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();

    let matches = Command::new("Secure Messaging Demo")
        .version(VERSION)
        .about("Demo tool for secure messaging and document encryption")
        .subcommand(
            Command::new("encrypt")
                .about("Encrypt a message or document")
                .arg(Arg::new("input")
                    .short('i')
                    .long("input")
                    .value_name("FILE")
                    .help("Input file or '-' for stdin")
                    .required(true))
                .arg(Arg::new("output")
                    .short('o')
                    .long("output")
                    .value_name("FILE")
                    .help("Output .securedoc file")
                    .required(true))
                .arg(Arg::new("title")
                    .short('t')
                    .long("title")
                    .value_name("TITLE")
                    .help("Document title")
                    .default_value("Untitled Document"))
                .arg(Arg::new("recipients")
                    .short('r')
                    .long("recipients")
                    .value_name("LIST")
                    .help("Comma-separated list of recipient IDs")
                    .default_value("self"))
        )
        .subcommand(
            Command::new("decrypt")
                .about("Decrypt a .securedoc file")
                .arg(Arg::new("input")
                    .short('i')
                    .long("input")
                    .value_name("FILE")
                    .help("Input .securedoc file")
                    .required(true))
                .arg(Arg::new("output")
                    .short('o')
                    .long("output")
                    .value_name("FILE")
                    .help("Output plaintext file or '-' for stdout")
                    .default_value("-"))
        )
        .subcommand(
            Command::new("generate-identity")
                .about("Generate a new identity")
                .arg(Arg::new("output")
                    .short('o')
                    .long("output")
                    .value_name("FILE")
                    .help("Output file for identity")
                    .default_value("identity.json"))
        )
        .subcommand(
            Command::new("test-roundtrip")
                .about("Test encrypt/decrypt roundtrip")
                .arg(Arg::new("message")
                    .short('m')
                    .long("message")
                    .value_name("TEXT")
                    .help("Test message")
                    .default_value("Hello, secure world! 🔒"))
        )
        .get_matches();

    match matches.subcommand() {
        Some(("encrypt", sub_matches)) => {
            cmd_encrypt(sub_matches).await?;
        }
        Some(("decrypt", sub_matches)) => {
            cmd_decrypt(sub_matches).await?;
        }
        Some(("generate-identity", sub_matches)) => {
            cmd_generate_identity(sub_matches).await?;
        }
        Some(("test-roundtrip", sub_matches)) => {
            cmd_test_roundtrip(sub_matches).await?;
        }
        _ => {
            println!("Use --help to see available commands");
        }
    }

    Ok(())
}

async fn cmd_encrypt(matches: &clap::ArgMatches) -> Result<()> {
    let input = matches.get_one::<String>("input").unwrap();
    let output = matches.get_one::<String>("output").unwrap();
    let title = matches.get_one::<String>("title").unwrap();
    let recipients_str = matches.get_one::<String>("recipients").unwrap();

    println!("🔒 Encrypting document...");
    println!("  Input: {}", input);
    println!("  Output: {}", output);
    println!("  Title: {}", title);

    // Read input
    let content = if input == "-" {
        use std::io::Read;
        let mut buffer = String::new();
        std::io::stdin().read_to_string(&mut buffer)?;
        buffer
    } else {
        fs::read_to_string(input)?
    };

    // Parse recipients
    let recipients: Vec<String> = recipients_str
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();

    println!("  Recipients: {:?}", recipients);
    println!("  Content length: {} bytes", content.len());

    // Initialize crypto manager
    let mut crypto_manager = CryptoManager::new(false); // No hardware token for demo
    crypto_manager.initialize().await?;

    // Generate identity if needed
    println!("  Generating identity...");
    let identity = crypto_manager.generate_identity(false, Some("demo_passphrase".to_string())).await?;
    println!("  Identity fingerprint: {}", identity.fingerprint);

    // Create SecureDoc format
    let securedoc_format = SecureDocFormat::new();

    // Generate keys for demo (normally from crypto manager)
    let age_identity = age::x25519::Identity::generate();
    let (_, signing_key) = sodiumoxide::crypto::sign::gen_keypair();

    // Create encrypted document
    let securedoc_data = securedoc_format.create_document(
        &content,
        &recipients,
        title,
        &identity.fingerprint,
        &signing_key,
        &age_identity,
    ).await?;

    // Apply size padding
    let padded_data = SecureDocFormat::apply_size_padding(&securedoc_data, 4096);

    // Write to file
    fs::write(output, &padded_data)?;

    println!("✅ Document encrypted successfully!");
    println!("  Output file: {}", output);
    println!("  Final size: {} bytes (padded)", padded_data.len());

    Ok(())
}

async fn cmd_decrypt(matches: &clap::ArgMatches) -> Result<()> {
    let input = matches.get_one::<String>("input").unwrap();
    let output = matches.get_one::<String>("output").unwrap();

    println!("🔓 Decrypting document...");
    println!("  Input: {}", input);
    println!("  Output: {}", output);

    // Read encrypted file
    let securedoc_data = fs::read(input)?;
    println!("  File size: {} bytes", securedoc_data.len());

    // Create SecureDoc format
    let securedoc_format = SecureDocFormat::new();

    // Generate identity for demo (in real usage, would load existing)
    let age_identity = age::x25519::Identity::generate();

    // Decrypt document
    let (content, manifest) = securedoc_format.open_document(
        &securedoc_data,
        "self", // recipient ID
        &age_identity,
        false, // Skip signature verification for demo
    ).await?;

    println!("  Title: {}", manifest.title);
    println!("  Author: {}", manifest.author_fingerprint);
    println!("  Created: {}", manifest.created_at);
    println!("  Content length: {} bytes", content.len());

    // Write output
    if output == "-" {
        println!("\n--- DECRYPTED CONTENT ---");
        println!("{}", content);
        println!("--- END CONTENT ---");
    } else {
        fs::write(output, &content)?;
        println!("✅ Document decrypted successfully!");
        println!("  Output file: {}", output);
    }

    Ok(())
}

async fn cmd_generate_identity(matches: &clap::ArgMatches) -> Result<()> {
    let output = matches.get_one::<String>("output").unwrap();

    println!("🆔 Generating new identity...");

    // Initialize crypto manager
    let mut crypto_manager = CryptoManager::new(false);
    crypto_manager.initialize().await?;

    // Generate identity
    let identity = crypto_manager.generate_identity(false, Some("demo_passphrase".to_string())).await?;

    println!("✅ Identity generated!");
    println!("  Fingerprint: {}", identity.fingerprint);
    println!("  Created: {}", identity.created_at);

    // Save to file
    let identity_json = serde_json::to_string_pretty(&identity)?;
    fs::write(output, identity_json)?;

    println!("  Saved to: {}", output);

    Ok(())
}

async fn cmd_test_roundtrip(matches: &clap::ArgMatches) -> Result<()> {
    let message = matches.get_one::<String>("message").unwrap();

    println!("🔄 Testing encrypt/decrypt roundtrip...");
    println!("  Original message: \"{}\"", message);

    // Initialize crypto manager
    let mut crypto_manager = CryptoManager::new(false);
    crypto_manager.initialize().await?;

    // Generate identity
    println!("  Generating identity...");
    let identity = crypto_manager.generate_identity(false, Some("test_passphrase".to_string())).await?;
    println!("  Identity: {}", identity.fingerprint);

    // Test message encryption
    println!("  Testing message encryption...");
    let encrypted_msg = crypto_manager.encrypt_message(message, &identity.public_identity).await?;
    println!("  Encrypted size: {} bytes", encrypted_msg.layer_c.len());

    // Test message decryption
    println!("  Testing message decryption...");
    let decrypted_msg = crypto_manager.decrypt_message(&encrypted_msg).await?;
    println!("  Decrypted message: \"{}\"", decrypted_msg);

    // Verify roundtrip
    if message == &decrypted_msg {
        println!("✅ Message roundtrip successful!");
    } else {
        println!("❌ Message roundtrip failed!");
        println!("    Expected: \"{}\"", message);
        println!("    Got:      \"{}\"", decrypted_msg);
        return Err(anyhow::anyhow!("Roundtrip verification failed"));
    }

    // Test document encryption
    println!("  Testing document encryption...");
    let securedoc_format = SecureDocFormat::new();
    let age_identity = age::x25519::Identity::generate();
    let (_, signing_key) = sodiumoxide::crypto::sign::gen_keypair();

    let securedoc_data = securedoc_format.create_document(
        message,
        &["test_user".to_string()],
        "Test Document",
        &identity.fingerprint,
        &signing_key,
        &age_identity,
    ).await?;

    println!("  Document size: {} bytes", securedoc_data.len());

    // Test document decryption
    println!("  Testing document decryption...");
    let (decrypted_content, manifest) = securedoc_format.open_document(
        &securedoc_data,
        "test_user",
        &age_identity,
        false, // Skip signature verification
    ).await?;

    println!("  Decrypted document: \"{}\"", decrypted_content);
    println!("  Document title: {}", manifest.title);

    // Verify document roundtrip
    if message == &decrypted_content {
        println!("✅ Document roundtrip successful!");
    } else {
        println!("❌ Document roundtrip failed!");
        return Err(anyhow::anyhow!("Document roundtrip verification failed"));
    }

    println!("🎉 All tests passed! Core crypto system is working.");

    Ok(())
}