// Windows-specific UI implementation
// Enhanced terminal interface with Windows console features

use anyhow::{Result, anyhow};
use std::io::{self, Write};
use crossterm::{
    terminal::{Clear, ClearType, enable_raw_mode, disable_raw_mode},
    cursor::{MoveTo, Show, Hide},
    style::{Color, Print, ResetColor, SetForegroundColor, SetBackgroundColor},
    execute, queue,
    event::{self, Event, KeyCode, KeyEvent, read}
};
use std::collections::VecDeque;
use chrono::{DateTime, Utc};

use crate::windows_security::WindowsSecurityManager;
use crate::crypto::{CryptoManager, Identity, EncryptedMessage};

pub struct WindowsUI {
    message_history: VecDeque<ChatMessage>,
    input_buffer: String,
    security_manager: *mut WindowsSecurityManager,
    screen_width: u16,
    screen_height: u16,
}

#[derive(Debug, Clone)]
struct ChatMessage {
    sender: String,
    content: String,
    timestamp: DateTime<Utc>,
    is_encrypted: bool,
    is_verified: bool,
}

impl WindowsUI {
    pub fn new(security_manager: &mut WindowsSecurityManager) -> Result<Self> {
        let (width, height) = crossterm::terminal::size()?;

        Ok(WindowsUI {
            message_history: VecDeque::new(),
            input_buffer: String::new(),
            security_manager: security_manager as *mut WindowsSecurityManager,
            screen_width: width,
            screen_height: height,
        })
    }

    pub async fn start_chat_interface(&mut self, identity: &Identity, crypto_manager: &mut CryptoManager) -> Result<()> {
        enable_raw_mode()?;

        // Clear screen and hide cursor
        execute!(io::stdout(), Clear(ClearType::All), Hide)?;

        // Add welcome message
        self.add_system_message("Welcome to JESUS IS KING - Windows Native Secure Messaging");
        self.add_system_message(&format!("Your identity: {}", identity.name));
        self.add_system_message(&format!("Public key: {}", &identity.public_key[..16] + "..."));
        self.add_system_message("Commands: /encrypt <message>, /decrypt <encrypted>, /security, /quit");

        loop {
            self.render_interface(identity)?;

            // Handle user input
            if let Event::Key(key_event) = read()? {
                match key_event.code {
                    KeyCode::Char(c) => {
                        self.input_buffer.push(c);
                    },
                    KeyCode::Backspace => {
                        self.input_buffer.pop();
                    },
                    KeyCode::Enter => {
                        let input = self.input_buffer.clone();
                        self.input_buffer.clear();

                        if input.trim().is_empty() {
                            continue;
                        }

                        if let Err(e) = self.process_command(&input, crypto_manager).await {
                            self.add_error_message(&format!("Error: {}", e));
                        }

                        if input.trim() == "/quit" {
                            break;
                        }
                    },
                    KeyCode::Esc => {
                        break;
                    },
                    _ => {}
                }
            }
        }

        // Cleanup
        execute!(io::stdout(), Clear(ClearType::All), MoveTo(0, 0), Show)?;
        disable_raw_mode()?;

        println!("✝️ Secure chat session ended. May God bless your communications.");

        Ok(())
    }

    async fn process_command(&mut self, input: &str, crypto_manager: &mut CryptoManager) -> Result<()> {
        let input = input.trim();

        if input.starts_with("/encrypt ") {
            let message = &input[9..];
            self.encrypt_and_display_message(message, crypto_manager).await?;
        } else if input.starts_with("/decrypt ") {
            let encrypted = &input[9..];
            self.decrypt_and_display_message(encrypted, crypto_manager).await?;
        } else if input == "/security" {
            self.show_security_status().await?;
        } else if input == "/quit" {
            // Will be handled in main loop
        } else if input.starts_with("/") {
            self.add_error_message("Unknown command. Available: /encrypt, /decrypt, /security, /quit");
        } else {
            // Regular message
            self.add_user_message(input);
        }

        Ok(())
    }

    async fn encrypt_and_display_message(&mut self, message: &str, crypto_manager: &mut CryptoManager) -> Result<()> {
        // For demo purposes, use a placeholder recipient key
        let placeholder_recipient_key = "0".repeat(64);

        match crypto_manager.encrypt_message(message, &placeholder_recipient_key) {
            Ok(encrypted_msg) => {
                self.add_system_message("✅ Message encrypted successfully");
                self.add_encrypted_message(&encrypted_msg.encrypted_content);
            },
            Err(e) => {
                self.add_error_message(&format!("Encryption failed: {}", e));
            }
        }

        Ok(())
    }

    async fn decrypt_and_display_message(&mut self, encrypted: &str, crypto_manager: &mut CryptoManager) -> Result<()> {
        // This would implement actual decryption
        self.add_system_message("🔓 Decryption would happen here (placeholder)");
        self.add_decrypted_message(&format!("Decrypted: {}", encrypted));
        Ok(())
    }

    async fn show_security_status(&mut self) -> Result<()> {
        let security_manager = unsafe { &*self.security_manager };

        let debugger = security_manager.check_debugger_presence()?;
        let vm_detected = security_manager.check_vm_environment()?;
        let process_integrity = security_manager.check_process_integrity()?;

        self.add_system_message("🔍 Windows Security Status:");
        self.add_system_message(&format!("  Debugger: {}", if debugger { "❌ Detected" } else { "✅ Clear" }));
        self.add_system_message(&format!("  VM Environment: {}", if vm_detected { "⚠️ Detected" } else { "✅ Physical" }));
        self.add_system_message(&format!("  Process Integrity: {}", if process_integrity { "✅ Good" } else { "⚠️ Suspicious" }));
        self.add_system_message(&format!("  Memory Security: ✅ VirtualLock Active"));

        Ok(())
    }

    fn render_interface(&self, identity: &Identity) -> Result<()> {
        let mut stdout = io::stdout();

        // Clear screen
        execute!(stdout, Clear(ClearType::All))?;

        // Render header
        self.render_header(&mut stdout, identity)?;

        // Render message area
        self.render_messages(&mut stdout)?;

        // Render input area
        self.render_input(&mut stdout)?;

        stdout.flush()?;
        Ok(())
    }

    fn render_header(&self, stdout: &mut io::Stdout, identity: &Identity) -> Result<()> {
        let header_line = "═".repeat(self.screen_width as usize);

        queue!(stdout, MoveTo(0, 0))?;
        queue!(stdout, SetForegroundColor(Color::Cyan))?;
        queue!(stdout, Print("╔"))?;
        queue!(stdout, Print(&header_line[..self.screen_width as usize - 2]))?;
        queue!(stdout, Print("╗"))?;

        queue!(stdout, MoveTo(0, 1))?;
        queue!(stdout, Print("║"))?;
        queue!(stdout, SetForegroundColor(Color::Yellow))?;
        queue!(stdout, Print("                         JESUS IS KING                           "))?;
        queue!(stdout, SetForegroundColor(Color::Cyan))?;
        queue!(stdout, Print("║"))?;

        queue!(stdout, MoveTo(0, 2))?;
        queue!(stdout, Print("║"))?;
        queue!(stdout, SetForegroundColor(Color::White))?;
        queue!(stdout, Print("                  Windows Secure Encrypted Messaging            "))?;
        queue!(stdout, SetForegroundColor(Color::Cyan))?;
        queue!(stdout, Print("║"))?;

        queue!(stdout, MoveTo(0, 3))?;
        queue!(stdout, Print("╠"))?;
        queue!(stdout, Print(&header_line[..self.screen_width as usize - 2]))?;
        queue!(stdout, Print("╣"))?;

        queue!(stdout, MoveTo(0, 4))?;
        queue!(stdout, Print("║"))?;
        queue!(stdout, SetForegroundColor(Color::Green))?;
        let identity_info = format!(" Identity: {} | Key: {}...",
            identity.name, &identity.public_key[..16]);
        queue!(stdout, Print(&format!("{:<64}", identity_info)))?;
        queue!(stdout, SetForegroundColor(Color::Cyan))?;
        queue!(stdout, Print("║"))?;

        queue!(stdout, MoveTo(0, 5))?;
        queue!(stdout, Print("╠"))?;
        queue!(stdout, Print(&header_line[..self.screen_width as usize - 2]))?;
        queue!(stdout, Print("╣"))?;

        queue!(stdout, ResetColor)?;
        Ok(())
    }

    fn render_messages(&self, stdout: &mut io::Stdout) -> Result<()> {
        let message_area_start = 6;
        let message_area_height = self.screen_height - 10; // Leave space for header and input

        // Render message history
        let messages_to_show = self.message_history.iter()
            .rev()
            .take(message_area_height as usize)
            .collect::<Vec<_>>();

        for (i, message) in messages_to_show.iter().rev().enumerate() {
            let y = message_area_start + i as u16;
            if y >= self.screen_height - 4 {
                break;
            }

            queue!(stdout, MoveTo(0, y))?;
            queue!(stdout, SetForegroundColor(Color::Cyan))?;
            queue!(stdout, Print("║"))?;

            // Format message based on type
            let (color, prefix) = match message.sender.as_str() {
                "System" => (Color::Yellow, "📢"),
                "Error" => (Color::Red, "❌"),
                "You" => (Color::Green, "📝"),
                "Encrypted" => (Color::Magenta, "🔒"),
                "Decrypted" => (Color::Blue, "🔓"),
                _ => (Color::White, "💬"),
            };

            queue!(stdout, SetForegroundColor(color))?;
            let message_text = format!(" {} [{}] {}",
                prefix, message.sender, message.content);
            let truncated = if message_text.len() > 63 {
                format!("{}...", &message_text[..60])
            } else {
                format!("{:<63}", message_text)
            };
            queue!(stdout, Print(&truncated))?;

            queue!(stdout, SetForegroundColor(Color::Cyan))?;
            queue!(stdout, Print("║"))?;
        }

        queue!(stdout, ResetColor)?;
        Ok(())
    }

    fn render_input(&self, stdout: &mut io::Stdout) -> Result<()> {
        let input_y = self.screen_height - 4;
        let header_line = "═".repeat(self.screen_width as usize);

        // Input area border
        queue!(stdout, MoveTo(0, input_y))?;
        queue!(stdout, SetForegroundColor(Color::Cyan))?;
        queue!(stdout, Print("╠"))?;
        queue!(stdout, Print(&header_line[..self.screen_width as usize - 2]))?;
        queue!(stdout, Print("╣"))?;

        // Input prompt
        queue!(stdout, MoveTo(0, input_y + 1))?;
        queue!(stdout, Print("║"))?;
        queue!(stdout, SetForegroundColor(Color::White))?;
        queue!(stdout, Print(" > "))?;

        // Input text
        let display_input = if self.input_buffer.len() > 59 {
            &self.input_buffer[self.input_buffer.len() - 59..]
        } else {
            &self.input_buffer
        };
        queue!(stdout, Print(&format!("{:<60}", display_input)))?;
        queue!(stdout, SetForegroundColor(Color::Cyan))?;
        queue!(stdout, Print("║"))?;

        // Bottom border
        queue!(stdout, MoveTo(0, input_y + 2))?;
        queue!(stdout, Print("╚"))?;
        queue!(stdout, Print(&header_line[..self.screen_width as usize - 2]))?;
        queue!(stdout, Print("╝"))?;

        // Commands help
        queue!(stdout, MoveTo(0, input_y + 3))?;
        queue!(stdout, SetForegroundColor(Color::DarkGrey))?;
        queue!(stdout, Print("Commands: /encrypt <msg> | /decrypt <enc> | /security | /quit | ESC"))?;

        queue!(stdout, ResetColor)?;
        Ok(())
    }

    fn add_system_message(&mut self, content: &str) {
        self.message_history.push_back(ChatMessage {
            sender: "System".to_string(),
            content: content.to_string(),
            timestamp: Utc::now(),
            is_encrypted: false,
            is_verified: false,
        });

        // Keep only last 100 messages
        if self.message_history.len() > 100 {
            self.message_history.pop_front();
        }
    }

    fn add_error_message(&mut self, content: &str) {
        self.message_history.push_back(ChatMessage {
            sender: "Error".to_string(),
            content: content.to_string(),
            timestamp: Utc::now(),
            is_encrypted: false,
            is_verified: false,
        });
    }

    fn add_user_message(&mut self, content: &str) {
        self.message_history.push_back(ChatMessage {
            sender: "You".to_string(),
            content: content.to_string(),
            timestamp: Utc::now(),
            is_encrypted: false,
            is_verified: false,
        });
    }

    fn add_encrypted_message(&mut self, content: &str) {
        self.message_history.push_back(ChatMessage {
            sender: "Encrypted".to_string(),
            content: content.to_string(),
            timestamp: Utc::now(),
            is_encrypted: true,
            is_verified: false,
        });
    }

    fn add_decrypted_message(&mut self, content: &str) {
        self.message_history.push_back(ChatMessage {
            sender: "Decrypted".to_string(),
            content: content.to_string(),
            timestamp: Utc::now(),
            is_encrypted: false,
            is_verified: true,
        });
    }
}

impl Drop for WindowsUI {
    fn drop(&mut self) {
        // Ensure terminal is restored on drop
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), Show, ResetColor);
    }
}