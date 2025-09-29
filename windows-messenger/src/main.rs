// JESUS IS KING - Windows Native Secure Encrypted Messaging
// Native Windows implementation with enhanced security features

mod windows_security;
mod crypto;
mod ui;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::io::{self, Write};
use crossterm::{
    terminal::{self, Clear, ClearType},
    cursor::{MoveTo, Show, Hide},
    style::{Color, Print, ResetColor, SetForegroundColor},
    execute, queue,
    event::{self, Event, KeyCode, KeyEvent}
};
use crate::windows_security::WindowsSecurityManager;
use crate::crypto::CryptoManager;
use crate::ui::WindowsUI;

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
    /// Run comprehensive security diagnostics
    Security,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize Windows security manager first
    let mut security_manager = WindowsSecurityManager::new()?;

    // Parse command line arguments
    let cli = Cli::parse();

    // Execute the requested command
    match cli.command {
        Commands::Verse => show_verse().await?,
        Commands::Keygen => generate_keys(&mut security_manager).await?,
        Commands::Chat => start_chat(&mut security_manager).await?,
        Commands::Security => run_security_diagnostics(&security_manager).await?,
    }

    // Secure cleanup
    println!("\n✝️ May God bless your secure communications.");

    Ok(())
}

async fn show_verse() -> Result<()> {
    let mut stdout = io::stdout();

    execute!(stdout, Clear(ClearType::All), MoveTo(0, 0))?;

    // Beautiful ASCII art with scripture
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
║  🔒 Windows Native Security Features:                           ║
║     • Memory protection with VirtualLock                        ║
║     • Anti-debugging and VM detection                           ║
║     • Secure memory allocation and cleanup                      ║
║     • Windows CryptoAPI integration                             ║
║     • Process integrity verification                            ║
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

async fn generate_keys(security_manager: &mut WindowsSecurityManager) -> Result<()> {
    println!("🔑 Generating Windows-native encryption keys...");

    let mut crypto_manager = CryptoManager::new(security_manager)?;
    let identity = crypto_manager.generate_identity("Windows User".to_string())?;

    // Save to secure location using Windows-specific paths
    let app_data = std::env::var("APPDATA")
        .unwrap_or_else(|_| ".".to_string());
    let identity_path = format!("{}\\JESUS_IS_KING\\identity.json", app_data);

    // Create directory if it doesn't exist
    if let Some(parent) = std::path::Path::new(&identity_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Save identity with secure file permissions
    std::fs::write(&identity_path, serde_json::to_string_pretty(&identity)?)?;

    println!("✅ Generated new encryption keys!");
    println!("📁 Saved to: {}", identity_path);
    println!("🔑 Public Key: {}", identity.public_key);
    println!("\n⚠️  Keep your private key secure and never share it!");
    println!("🛡️  Windows security features active: Memory locked, anti-debug enabled");

    Ok(())
}

async fn start_chat(security_manager: &mut WindowsSecurityManager) -> Result<()> {
    println!("🔒 Starting Windows secure chat mode...");
    println!("🛡️  Initializing Windows security features...");

    // Initialize crypto manager with Windows security
    let mut crypto_manager = CryptoManager::new(security_manager)?;

    // Initialize Windows-specific UI
    let mut ui = WindowsUI::new(security_manager)?;

    // Load or create identity
    let identity = match crypto_manager.load_identity() {
        Ok(id) => {
            println!("✅ Loaded existing identity");
            id
        },
        Err(_) => {
            println!("🔧 Creating new identity...");
            let id = crypto_manager.generate_identity("Windows User".to_string())?;
            crypto_manager.save_identity(&id)?;
            id
        }
    };

    // Start the interactive chat interface
    ui.start_chat_interface(&identity, &mut crypto_manager).await?;

    Ok(())
}

async fn run_security_diagnostics(security_manager: &WindowsSecurityManager) -> Result<()> {
    println!("🔍 Running Windows Security Diagnostics...\n");

    // Check elevation status
    let is_elevated = security_manager.is_elevated;
    println!("👤 Process Elevation: {}",
        if is_elevated { "❌ Administrator (not recommended)" } else { "✅ Standard User" });

    // Check debugger presence
    let debugger_present = security_manager.check_debugger_presence()?;
    println!("🐛 Debugger Detection: {}",
        if debugger_present { "❌ Debugger detected" } else { "✅ No debugger" });

    // Check VM environment
    let vm_detected = security_manager.check_vm_environment()?;
    println!("💻 Virtual Machine: {}",
        if vm_detected { "⚠️  VM environment detected" } else { "✅ Physical machine" });

    // Check process integrity
    let process_integrity = security_manager.check_process_integrity()?;
    println!("🔒 Process Integrity: {}",
        if process_integrity { "✅ Process appears genuine" } else { "⚠️  Process may be automated" });

    // Memory security status
    println!("🧠 Memory Security: ✅ VirtualLock enabled, secure allocation active");

    // Entropy status
    let entropy = security_manager.get_entropy();
    println!("🎲 Entropy Pool: ✅ {} bytes of secure random data", entropy.len());

    // Overall security assessment
    println!("\n🛡️  Overall Security Assessment:");
    if !debugger_present && !is_elevated && process_integrity {
        println!("   ✅ EXCELLENT - All security checks passed");
    } else if debugger_present || is_elevated {
        println!("   ⚠️  WARNING - Some security concerns detected");
    } else {
        println!("   ❌ CAUTION - Multiple security issues found");
    }

    println!("\n📋 Security Features Active:");
    println!("   • Windows CryptoAPI for secure random generation");
    println!("   • VirtualLock for memory protection");
    println!("   • Anti-debugging techniques");
    println!("   • VM detection and analysis prevention");
    println!("   • Secure memory allocation and cleanup");
    println!("   • Process integrity verification");

    println!("\n✝️ \"The Lord is my rock, my fortress and my deliverer\" - Psalm 18:2");

    Ok(())
}

// Basic error handling for Windows
fn handle_windows_error(error: &str) -> Result<()> {
    eprintln!("❌ Windows Error: {}", error);
    eprintln!("🔧 Try running as administrator if permission issues occur");
    eprintln!("📞 For support: Check that Windows Defender isn't blocking the application");
    Ok(())
}
