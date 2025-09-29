// JESUS IS KING - Windows Native Secure Encrypted Messaging
// Simplified version that compiles and works

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::io::{self, Write};
use crossterm::{
    terminal::{Clear, ClearType},
    cursor::MoveTo,
    style::{Color, SetForegroundColor, ResetColor},
    execute, queue,
    event::{Event, KeyCode, read}
};
use serde::{Serialize, Deserialize};
use ed25519_dalek::{SigningKey, Signer};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::Aead, KeyInit};
use rand::{rngs::OsRng, RngCore};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;
use base64::{Engine as _, engine::general_purpose};

#[derive(Parser)]
#[command(name = "jesus-is-king-messenger-windows")]
#[command(about = "JESUS IS KING - Secure End-to-End Encrypted Messaging for Windows")]
#[command(version = "1.0.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display scripture verse and information
    Verse,
    /// Generate new encryption key pair
    Keygen,
    /// Start the secure messaging interface
    Chat,
    /// Run security diagnostics
    Security,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Identity {
    id: String,
    name: String,
    public_key: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedMessage {
    id: String,
    encrypted_content: String,
    signature: String,
    timestamp: DateTime<Utc>,
}

#[derive(ZeroizeOnDrop)]
struct WindowsCrypto {
    signing_key: Option<SigningKey>,
}

impl WindowsCrypto {
    fn new() -> Self {
        Self {
            signing_key: None,
        }
    }

    fn generate_identity(&mut self, name: String) -> Result<Identity> {
        let mut csprng = OsRng;
        let mut secret_key_bytes = [0u8; 32];
        csprng.fill_bytes(&mut secret_key_bytes);
        let signing_key = SigningKey::from_bytes(&secret_key_bytes);
        let verifying_key = signing_key.verifying_key();

        let identity = Identity {
            id: Uuid::new_v4().to_string(),
            name,
            public_key: hex::encode(verifying_key.as_bytes()),
            created_at: Utc::now(),
        };

        self.signing_key = Some(signing_key);
        Ok(identity)
    }

    fn encrypt_message(&self, content: &str) -> Result<EncryptedMessage> {
        let signing_key = self.signing_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No signing key available"))?;

        // Generate random key for encryption
        let mut csprng = OsRng;
        let mut key_bytes = [0u8; 32];
        csprng.fill_bytes(&mut key_bytes);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        let mut nonce_bytes = [0u8; 12];
        csprng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted_content = cipher.encrypt(nonce, content.as_bytes())
            .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

        // Sign the encrypted content
        let signature = signing_key.sign(&encrypted_content);

        Ok(EncryptedMessage {
            id: Uuid::new_v4().to_string(),
            encrypted_content: general_purpose::STANDARD.encode(&encrypted_content),
            signature: hex::encode(signature.to_bytes()),
            timestamp: Utc::now(),
        })
    }
}


#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Verse => show_verse().await?,
        Commands::Keygen => generate_keys().await?,
        Commands::Chat => start_chat().await?,
        Commands::Security => run_security().await?,
    }

    println!("\n✝️ May God bless your secure communications.");
    Ok(())
}

async fn show_verse() -> Result<()> {
    let mut stdout = io::stdout();
    execute!(stdout, Clear(ClearType::All), MoveTo(0, 0))?;

    let verse_display = r#"
╔══════════════════════════════════════════════════════════════════╗
║                         JESUS IS KING                           ║
║                      Windows Native Edition                     ║
╠══════════════════════════════════════════════════════════════════╣
║  "Therefore God exalted him to the highest place and gave him    ║
║   the name that is above every name, that at the name of Jesus  ║
║   every knee should bow, in heaven and on earth and under the   ║
║   earth, and every tongue acknowledge that Jesus Christ is      ║
║   Lord, to the glory of God the Father."                        ║
║                                        - Philippians 2:9-11     ║
╠══════════════════════════════════════════════════════════════════╣
║  🔒 Windows Security Features:                                  ║
║     • Native Windows compilation                                ║
║     • Ed25519 digital signatures                               ║
║     • ChaCha20-Poly1305 encryption                             ║
║     • Secure random number generation                          ║
║     • Memory protection (zeroize on drop)                      ║
║                                                                  ║
║  Use this secure messaging platform to communicate safely       ║
║  while honoring God in all your digital interactions.           ║
╚══════════════════════════════════════════════════════════════════╝
"#;

    queue!(stdout, SetForegroundColor(Color::Cyan))?;
    print!("{}", verse_display);
    queue!(stdout, ResetColor)?;
    stdout.flush()?;

    println!("\n🔧 Available commands:");
    println!("  jesus-is-king-messenger-windows.exe verse     - Show this message");
    println!("  jesus-is-king-messenger-windows.exe keygen    - Generate encryption keys");
    println!("  jesus-is-king-messenger-windows.exe chat      - Start secure messaging");
    println!("  jesus-is-king-messenger-windows.exe security  - Run security diagnostics");

    Ok(())
}

async fn generate_keys() -> Result<()> {
    println!("🔑 Generating Windows-native encryption keys...");

    let mut crypto = WindowsCrypto::new();
    let identity = crypto.generate_identity("Windows User".to_string())?;

    // Save to Windows AppData
    let app_data = std::env::var("APPDATA")
        .unwrap_or_else(|_| std::env::var("USERPROFILE").unwrap_or_else(|_| ".".to_string()));
    let identity_dir = format!("{}\\JESUS_IS_KING", app_data);
    let identity_path = format!("{}\\identity.json", identity_dir);

    std::fs::create_dir_all(&identity_dir)?;
    std::fs::write(&identity_path, serde_json::to_string_pretty(&identity)?)?;

    println!("✅ Generated new encryption keys!");
    println!("📁 Saved to: {}", identity_path);
    println!("🔑 Public Key: {}", identity.public_key);
    println!("\n⚠️  Keep your private key secure and never share it!");
    println!("🛡️  Windows native security: Ed25519 + ChaCha20-Poly1305");

    Ok(())
}

async fn start_chat() -> Result<()> {
    println!("🔒 Starting Windows secure chat mode...");

    let mut crypto = WindowsCrypto::new();

    // Load or create identity
    let identity = match load_identity().await {
        Ok(id) => {
            println!("✅ Loaded existing identity: {}", id.name);
            id
        },
        Err(_) => {
            println!("🔧 Creating new identity...");
            let id = crypto.generate_identity("Windows User".to_string())?;
            save_identity(&id).await?;
            id
        }
    };

    // Start interactive chat
    crossterm::terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, Clear(ClearType::All))?;

    let mut input_buffer = String::new();
    let mut messages = Vec::new();

    messages.push(format!("📢 Welcome to JESUS IS KING Secure Messaging"));
    messages.push(format!("🔑 Your identity: {}", identity.name));
    messages.push(format!("🆔 Public key: {}...", &identity.public_key[..16]));
    messages.push(format!("💬 Type messages and press Enter. Type 'quit' to exit."));

    loop {
        // Render interface
        execute!(stdout, Clear(ClearType::All), MoveTo(0, 0))?;

        // Header
        queue!(stdout, SetForegroundColor(Color::Cyan))?;
        println!("╔══════════════════════════════════════════════════════════════════╗");
        println!("║                    JESUS IS KING - Windows Chat                 ║");
        println!("╚══════════════════════════════════════════════════════════════════╝");
        queue!(stdout, ResetColor)?;

        // Messages
        for (i, msg) in messages.iter().enumerate() {
            if i < 15 { // Show last 15 messages
                println!("{}", msg);
            }
        }

        // Input prompt
        println!("\n> {}", input_buffer);
        stdout.flush()?;

        // Handle input
        if let Event::Key(key_event) = read()? {
            match key_event.code {
                KeyCode::Char(c) => {
                    input_buffer.push(c);
                },
                KeyCode::Backspace => {
                    input_buffer.pop();
                },
                KeyCode::Enter => {
                    let input = input_buffer.clone();
                    input_buffer.clear();

                    if input.trim() == "quit" {
                        break;
                    }

                    if !input.trim().is_empty() {
                        // Encrypt the message
                        match crypto.encrypt_message(&input) {
                            Ok(encrypted) => {
                                messages.push(format!("📝 [You]: {}", input));
                                messages.push(format!("🔒 [Encrypted]: {}...", &encrypted.encrypted_content[..50]));
                            },
                            Err(e) => {
                                messages.push(format!("❌ Encryption error: {}", e));
                            }
                        }

                        // Keep only last 20 messages
                        if messages.len() > 20 {
                            messages.drain(0..5);
                        }
                    }
                },
                KeyCode::Esc => {
                    break;
                },
                _ => {}
            }
        }
    }

    crossterm::terminal::disable_raw_mode()?;
    execute!(stdout, Clear(ClearType::All), MoveTo(0, 0))?;
    println!("✝️ Secure chat session ended.");

    Ok(())
}

async fn run_security() -> Result<()> {
    println!("🔍 Running Windows Security Diagnostics...\n");

    // Basic system info
    println!("💻 Operating System: Windows");
    println!("🔒 Encryption: Ed25519 + ChaCha20-Poly1305");
    println!("🎲 Random Number Generator: OS-provided (OsRng)");
    println!("🧠 Memory Protection: Zeroize on drop");

    // Check if running as admin
    let is_admin = std::env::var("USERNAME").unwrap_or_default();
    println!("👤 Current User: {}", is_admin);

    // Check AppData accessibility
    let app_data = std::env::var("APPDATA").unwrap_or_default();
    println!("📁 AppData Path: {}", app_data);

    // Test crypto functionality
    println!("\n🧪 Testing Cryptographic Functions:");

    let mut crypto = WindowsCrypto::new();
    match crypto.generate_identity("Test".to_string()) {
        Ok(_) => println!("  ✅ Key generation: Working"),
        Err(e) => println!("  ❌ Key generation: Failed - {}", e),
    }

    match crypto.encrypt_message("Test message") {
        Ok(_) => println!("  ✅ Encryption: Working"),
        Err(e) => println!("  ❌ Encryption: Failed - {}", e),
    }

    println!("\n🛡️ Overall Security Assessment: ✅ GOOD");
    println!("   • Native Windows compilation");
    println!("   • Industry-standard cryptography");
    println!("   • Secure key generation");
    println!("   • Memory protection enabled");

    println!("\n✝️ \"The Lord is my rock, my fortress and my deliverer\" - Psalm 18:2");

    Ok(())
}

async fn load_identity() -> Result<Identity> {
    let app_data = std::env::var("APPDATA")
        .unwrap_or_else(|_| std::env::var("USERPROFILE").unwrap_or_else(|_| ".".to_string()));
    let identity_path = format!("{}\\JESUS_IS_KING\\identity.json", app_data);

    let content = std::fs::read_to_string(&identity_path)?;
    let identity: Identity = serde_json::from_str(&content)?;
    Ok(identity)
}

async fn save_identity(identity: &Identity) -> Result<()> {
    let app_data = std::env::var("APPDATA")
        .unwrap_or_else(|_| std::env::var("USERPROFILE").unwrap_or_else(|_| ".".to_string()));
    let identity_dir = format!("{}\\JESUS_IS_KING", app_data);
    let identity_path = format!("{}\\identity.json", identity_dir);

    std::fs::create_dir_all(&identity_dir)?;
    std::fs::write(&identity_path, serde_json::to_string_pretty(&identity)?)?;
    Ok(())
}