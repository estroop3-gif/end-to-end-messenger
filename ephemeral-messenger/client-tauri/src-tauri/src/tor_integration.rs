// Tor integration - Onion service creation and management
// Direct integration with Tor control port

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::TcpStream;
use std::io::{BufReader, BufRead, Write};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionService {
    pub address: String,
    pub private_key: String,
    pub local_port: u16,
    pub onion_port: u16,
    pub client_auth_key: Option<String>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorStatus {
    pub connected: bool,
    pub version: String,
    pub control_port: u16,
    pub socks_port: u16,
    pub circuit_count: u32,
}

pub struct TorManager {
    control_host: String,
    control_port: u16,
    control_password: Option<String>,
    active_onions: HashMap<String, OnionService>,
    authenticated: bool,
}

impl TorManager {
    pub fn new() -> Self {
        Self {
            control_host: "127.0.0.1".to_string(),
            control_port: 9051,
            control_password: None,
            active_onions: HashMap::new(),
            authenticated: false,
        }
    }

    pub async fn initialize(&mut self) -> Result<()> {
        // Test connection to Tor control port
        self.test_control_connection().await?;

        // Authenticate with Tor
        self.authenticate().await?;

        println!("Tor manager initialized and authenticated");
        Ok(())
    }

    /// Test connection to Tor control port
    async fn test_control_connection(&self) -> Result<()> {
        let address = format!("{}:{}", self.control_host, self.control_port);

        timeout(Duration::from_secs(5), async {
            TcpStream::connect(&address)
                .map_err(|e| anyhow!("Cannot connect to Tor control port {}: {}", address, e))
        })
        .await
        .map_err(|_| anyhow!("Timeout connecting to Tor control port"))?
        .map(|_| ())
    }

    /// Authenticate with Tor control port
    async fn authenticate(&mut self) -> Result<()> {
        let mut stream = TcpStream::connect(format!("{}:{}", self.control_host, self.control_port))?;

        // Send authentication command
        let auth_command = if let Some(ref password) = self.control_password {
            format!("AUTHENTICATE \"{}\"\r\n", password)
        } else {
            "AUTHENTICATE\r\n".to_string()
        };

        stream.write_all(auth_command.as_bytes())?;

        // Read response
        let mut reader = BufReader::new(&stream);
        let mut response = String::new();
        reader.read_line(&mut response)?;

        if response.starts_with("250") {
            self.authenticated = true;
            Ok(())
        } else {
            Err(anyhow!("Tor authentication failed: {}", response.trim()))
        }
    }

    /// Create ephemeral onion service
    pub async fn create_ephemeral_onion(
        &mut self,
        local_port: u16,
        onion_port: u16,
        client_auth_key: Option<String>,
    ) -> Result<OnionService> {
        if !self.authenticated {
            return Err(anyhow!("Not authenticated with Tor"));
        }

        let mut stream = TcpStream::connect(format!("{}:{}", self.control_host, self.control_port))?;

        // Build ADD_ONION command
        let mut command = format!(
            "ADD_ONION NEW:ED25519-V3 Port={},127.0.0.1:{} Flags=Detach",
            onion_port, local_port
        );

        if let Some(ref auth_key) = client_auth_key {
            command.push_str(&format!(" ClientAuth={}", auth_key));
        }

        command.push_str("\r\n");

        // Send command
        stream.write_all(command.as_bytes())?;

        // Read response
        let mut reader = BufReader::new(&stream);
        let mut lines = Vec::new();

        loop {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            let trimmed = line.trim();

            if trimmed.starts_with("250 OK") {
                break;
            } else if trimmed.starts_with("250-") || trimmed.starts_with("250 ") {
                lines.push(trimmed.to_string());
            } else if trimmed.starts_with("5") {
                return Err(anyhow!("Tor command failed: {}", trimmed));
            }
        }

        // Parse response to get onion address and private key
        let mut onion_address = None;
        let mut private_key = None;

        for line in &lines {
            if line.starts_with("250-ServiceID=") {
                onion_address = Some(line.strip_prefix("250-ServiceID=").unwrap().to_string());
            } else if line.starts_with("250-PrivateKey=") {
                private_key = Some(line.strip_prefix("250-PrivateKey=").unwrap().to_string());
            }
        }

        let address = onion_address
            .ok_or_else(|| anyhow!("No ServiceID in response"))?;
        let private_key = private_key
            .ok_or_else(|| anyhow!("No PrivateKey in response"))?;

        let full_address = format!("{}.onion", address);

        let onion_service = OnionService {
            address: full_address.clone(),
            private_key,
            local_port,
            onion_port,
            client_auth_key,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.active_onions.insert(address, onion_service.clone());

        println!("Created ephemeral onion service: {}", full_address);
        Ok(onion_service)
    }

    /// Delete ephemeral onion service
    pub async fn delete_onion_service(&mut self, onion_address: &str) -> Result<()> {
        if !self.authenticated {
            return Err(anyhow!("Not authenticated with Tor"));
        }

        // Extract service ID from address
        let service_id = onion_address
            .strip_suffix(".onion")
            .unwrap_or(onion_address);

        let mut stream = TcpStream::connect(format!("{}:{}", self.control_host, self.control_port))?;

        // Send DEL_ONION command
        let command = format!("DEL_ONION {}\r\n", service_id);
        stream.write_all(command.as_bytes())?;

        // Read response
        let mut reader = BufReader::new(&stream);
        let mut response = String::new();
        reader.read_line(&mut response)?;

        if response.starts_with("250") {
            self.active_onions.remove(service_id);
            println!("Deleted onion service: {}", onion_address);
            Ok(())
        } else {
            Err(anyhow!("Failed to delete onion service: {}", response.trim()))
        }
    }

    /// Get Tor status information
    pub async fn get_tor_status(&self) -> Result<TorStatus> {
        if !self.authenticated {
            return Err(anyhow!("Not authenticated with Tor"));
        }

        let mut stream = TcpStream::connect(format!("{}:{}", self.control_host, self.control_port))?;

        // Get version
        stream.write_all(b"GETINFO version\r\n")?;
        let mut reader = BufReader::new(&stream);
        let mut version_response = String::new();
        reader.read_line(&mut version_response)?;

        let version = if version_response.starts_with("250-version=") {
            version_response
                .strip_prefix("250-version=")
                .unwrap_or("unknown")
                .trim()
                .to_string()
        } else {
            "unknown".to_string()
        };

        // Get circuit count
        stream.write_all(b"GETINFO circuit-status\r\n")?;
        let mut circuit_count = 0u32;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            let trimmed = line.trim();

            if trimmed.starts_with("250 OK") {
                break;
            } else if trimmed.starts_with("250-") {
                circuit_count += 1;
            }
        }

        Ok(TorStatus {
            connected: true,
            version,
            control_port: self.control_port,
            socks_port: 9050, // Default SOCKS port
            circuit_count,
        })
    }

    /// Test onion service reachability
    pub async fn test_onion_reachability(&self, onion_address: &str) -> Result<bool> {
        // Try to connect through Tor SOCKS proxy
        let proxy_addr = "127.0.0.1:9050";

        // TODO: Implement SOCKS5 connection test
        // For now, just return true
        println!("Testing reachability of {}", onion_address);
        Ok(true)
    }

    /// Generate client authorization keys
    pub fn generate_client_auth_keys() -> Result<(String, String)> {
        use x25519_dalek::{StaticSecret, PublicKey};
        use rand::rngs::OsRng;

        let private_key = StaticSecret::new(OsRng);
        let public_key = PublicKey::from(&private_key);

        // Format for Tor client authorization
        let private_key_str = base64::encode(private_key.to_bytes());
        let public_key_str = format!("descriptor:x25519:{}", base64::encode(public_key.as_bytes()));

        Ok((private_key_str, public_key_str))
    }

    /// Create client authorization file
    pub async fn create_client_auth_file(
        &self,
        onion_address: &str,
        client_name: &str,
        public_key: &str,
    ) -> Result<String> {
        let service_id = onion_address
            .strip_suffix(".onion")
            .unwrap_or(onion_address);

        let auth_content = format!("{}:descriptor:x25519:{}", service_id, public_key);
        let filename = format!("{}.auth_private", client_name);

        // In production, this would be written to the Tor client auth directory
        // For now, just return the content
        println!("Client auth file content for {}: {}", filename, auth_content);
        Ok(auth_content)
    }

    /// List all active onion services
    pub fn list_active_onions(&self) -> Vec<&OnionService> {
        self.active_onions.values().collect()
    }

    /// Cleanup all onion services
    pub async fn cleanup(&mut self) -> Result<()> {
        println!("Cleaning up Tor manager...");

        let onion_addresses: Vec<String> = self.active_onions.keys().cloned().collect();

        for address in onion_addresses {
            if let Err(e) = self.delete_onion_service(&format!("{}.onion", address)).await {
                eprintln!("Warning: Failed to delete onion service {}: {}", address, e);
            }
        }

        self.active_onions.clear();
        self.authenticated = false;

        println!("Tor manager cleanup completed");
        Ok(())
    }
}

impl Drop for TorManager {
    fn drop(&mut self) {
        // Ensure cleanup on drop
        if let Err(e) = tokio::runtime::Runtime::new().unwrap().block_on(self.cleanup()) {
            eprintln!("Error during TorManager drop: {}", e);
        }
    }
}

/// Utility function to check if Tor is running
pub async fn check_tor_daemon() -> Result<bool> {
    match TcpStream::connect("127.0.0.1:9050") {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Utility function to test Tor connectivity
pub async fn test_tor_connectivity() -> Result<()> {
    use std::process::Command;

    let output = Command::new("curl")
        .args(&[
            "--socks5", "127.0.0.1:9050",
            "--connect-timeout", "10",
            "http://check.torproject.org/",
        ])
        .output()
        .map_err(|e| anyhow!("Failed to test Tor connectivity: {}", e))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(anyhow!("Tor connectivity test failed"))
    }
}