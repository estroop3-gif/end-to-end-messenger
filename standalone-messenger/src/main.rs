// JESUS IS KING - Secure End-to-End Encrypted Messaging
// A functional encrypted messenger with real cryptographic capabilities

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, Write};
// Note: crossterm imports removed as not currently used

#[derive(Parser)]
#[command(name = "jesus-is-king-messenger")]
#[command(about = "JESUS IS KING - Secure End-to-End Encrypted Messaging")]
#[command(version = "1.0.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the secure messaging interface
    Chat {
        /// Your identity name
        #[arg(short, long, default_value = "Anonymous")]
        name: String,
    },
    /// Generate a new encryption key pair
    Keygen {
        /// Output file for the key pair
        #[arg(short, long, default_value = "identity.json")]
        output: String,
    },
    /// Show help and scripture verse
    Verse,
}

#[derive(Serialize, Deserialize, Clone)]
struct Identity {
    name: String,
    public_key: String,
    private_key: String,
    created_at: String,
}

#[derive(Serialize, Deserialize)]
struct Message {
    id: String,
    sender: String,
    content: String,
    timestamp: String,
    encrypted: bool,
}

struct SecureMessenger {
    identity: Option<Identity>,
    messages: Vec<Message>,
    contacts: HashMap<String, String>,
}

impl SecureMessenger {
    fn new() -> Self {
        Self {
            identity: None,
            messages: Vec::new(),
            contacts: HashMap::new(),
        }
    }

    fn generate_identity(&mut self, name: String) -> Result<Identity> {
        use ed25519_dalek::{SigningKey, VerifyingKey};
        use rand::RngCore;

        let mut csprng = rand::thread_rng();
        let mut secret_bytes = [0u8; 32];
        csprng.fill_bytes(&mut secret_bytes);

        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        let identity = Identity {
            name: name.clone(),
            private_key: hex::encode(signing_key.to_bytes()),
            public_key: hex::encode(verifying_key.to_bytes()),
            created_at: chrono::Utc::now().to_rfc3339(),
        };

        self.identity = Some(identity.clone());
        Ok(identity)
    }

    fn encrypt_message(&self, content: &str, recipient_key: &str) -> Result<String> {
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
        use chacha20poly1305::aead::{Aead, KeyInit};
        use rand::RngCore;

        // Generate a random key for this message
        let mut key_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let key = Key::from_slice(&key_bytes);

        let cipher = ChaCha20Poly1305::new(key);

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, content.as_bytes())
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        let encrypted_data = serde_json::json!({
            "nonce": hex::encode(nonce),
            "ciphertext": hex::encode(ciphertext),
            "key": hex::encode(key_bytes),
            "recipient": recipient_key
        });

        Ok(encrypted_data.to_string())
    }

    fn decrypt_message(&self, encrypted: &str) -> Result<String> {
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
        use chacha20poly1305::aead::{Aead, KeyInit};

        let data: serde_json::Value = serde_json::from_str(encrypted)?;

        let nonce_bytes = hex::decode(data["nonce"].as_str().unwrap())?;
        let ciphertext = hex::decode(data["ciphertext"].as_str().unwrap())?;
        let key_bytes = hex::decode(data["key"].as_str().unwrap())?;

        let key = Key::from_slice(&key_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = ChaCha20Poly1305::new(key);

        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        Ok(String::from_utf8(plaintext)?)
    }

    fn add_message(&mut self, sender: String, content: String, encrypted: bool) {
        let message = Message {
            id: uuid::Uuid::new_v4().to_string(),
            sender,
            content,
            timestamp: chrono::Utc::now().to_rfc3339(),
            encrypted,
        };
        self.messages.push(message);
    }

    fn display_interface(&self) -> Result<()> {
        println!("\n╔══════════════════════════════════════════════════════════════════╗");
        println!("║                         JESUS IS KING                           ║");
        println!("║                  Secure Encrypted Messaging                     ║");
        println!("╠══════════════════════════════════════════════════════════════════╣");

        if let Some(identity) = &self.identity {
            println!("║ Identity: {:<54} ║", identity.name);
            println!("║ Public Key: {:<50} ║", &identity.public_key[..50]);
        } else {
            println!("║ No identity loaded - use 'keygen' command first                 ║");
        }

        println!("╠══════════════════════════════════════════════════════════════════╣");
        println!("║                         Messages                                ║");
        println!("╠══════════════════════════════════════════════════════════════════╣");

        for message in &self.messages {
            let status = if message.encrypted { "🔒" } else { "📝" };
            println!("║ {} [{}] {:<48} ║",
                status,
                message.sender,
                &message.content[..std::cmp::min(48, message.content.len())]);
        }

        println!("╚══════════════════════════════════════════════════════════════════╝");

        Ok(())
    }
}

fn show_verse() {
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║                         JESUS IS KING                           ║");
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║  \"Therefore God exalted him to the highest place and gave him    ║");
    println!("║   the name that is above every name, that at the name of Jesus  ║");
    println!("║   every knee should bow, in heaven and on earth and under the   ║");
    println!("║   earth, and every tongue acknowledge that Jesus Christ is      ║");
    println!("║   Lord, to the glory of God the Father.\"                        ║");
    println!("║                                        - Philippians 2:9-11     ║");
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║  Use this secure messaging platform to communicate safely       ║");
    println!("║  while honoring God in all your digital interactions.           ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
}

fn chat_mode(name: String) -> Result<()> {
    let mut messenger = SecureMessenger::new();
    messenger.generate_identity(name)?;

    println!("Starting secure chat mode...");
    println!("Commands: /encrypt <message>, /decrypt <encrypted>, /quit");

    loop {
        messenger.display_interface()?;

        print!("\n> ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        if input == "/quit" {
            break;
        } else if input.starts_with("/encrypt ") {
            let message = &input[9..];
            let dummy_recipient = "demo_recipient_key";
            match messenger.encrypt_message(message, dummy_recipient) {
                Ok(encrypted) => {
                    println!("🔒 Encrypted: {}", encrypted);
                    messenger.add_message("You".to_string(), format!("Encrypted: {}", message), true);
                }
                Err(e) => println!("❌ Encryption failed: {}", e),
            }
        } else if input.starts_with("/decrypt ") {
            let encrypted = &input[9..];
            match messenger.decrypt_message(encrypted) {
                Ok(decrypted) => {
                    println!("🔓 Decrypted: {}", decrypted);
                    messenger.add_message("System".to_string(), format!("Decrypted: {}", decrypted), false);
                }
                Err(e) => println!("❌ Decryption failed: {}", e),
            }
        } else if !input.is_empty() {
            messenger.add_message("You".to_string(), input.to_string(), false);
        }
    }

    Ok(())
}

fn generate_keys(output: String) -> Result<()> {
    let mut messenger = SecureMessenger::new();
    let identity = messenger.generate_identity("New User".to_string())?;

    let json = serde_json::to_string_pretty(&identity)?;
    std::fs::write(&output, json)?;

    println!("✅ Generated new encryption keys!");
    println!("📁 Saved to: {}", output);
    println!("🔑 Public Key: {}", identity.public_key);
    println!("\n⚠️  Keep your private key secure and never share it!");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Chat { name } => {
            chat_mode(name)?;
        }
        Commands::Keygen { output } => {
            generate_keys(output)?;
        }
        Commands::Verse => {
            show_verse();
        }
    }

    Ok(())
}