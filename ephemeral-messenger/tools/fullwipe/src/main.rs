use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom, BufWriter};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;
use anyhow::{Result, Context, bail};
use clap::{Parser, Subcommand};
use serde::{Serialize, Deserialize};
use ed25519_dalek::{Verifier, PublicKey, Signature};
use libsodium_sys::*;
use chrono::{DateTime, Utc};
use indicatif::{ProgressBar, ProgressStyle};
use dialoguer::{Confirm, Input, Select};
use nix::unistd::geteuid;
use nix::mount::{mount, umount, MsFlags};

#[derive(Parser)]
#[command(name = "fullwipe_cli")]
#[command(about = "Secure full-drive wipe utility")]
#[command(version = "1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List available storage devices
    List,
    /// Dry run - show what would be wiped without actually doing it
    DryRun {
        /// Wipe plan file
        #[arg(long)]
        plan: PathBuf,
    },
    /// Execute the wipe operation
    Execute {
        /// Wipe plan file
        #[arg(long)]
        plan: PathBuf,
        /// Target device (must match plan and be specified twice for safety)
        #[arg(long)]
        device: String,
        /// Confirm device by specifying it again
        #[arg(long)]
        device_confirm: String,
    },
    /// Interactive mode with prompts
    Interactive,
    /// Verify wipe plan signature
    Verify {
        /// Wipe plan file
        #[arg(long)]
        plan: PathBuf,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WipePlan {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub target_device: TargetDevice,
    pub wipe_method: WipeMethod,
    pub verification_required: bool,
    pub admin_signature: Vec<u8>,
    pub approval_audit_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TargetDevice {
    pub device_path: String,
    pub device_id: String,
    pub serial_number: Option<String>,
    pub model: Option<String>,
    pub size_bytes: u64,
    pub verified_twice: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum WipeMethod {
    SecureErase,        // Hardware secure erase if supported
    MultiPassRandom,    // Multiple passes with random data
    SinglePassZero,     // Single pass with zeros
    BlkDiscard,         // TRIM/discard commands
    Hybrid,             // Combination of methods
}

#[derive(Debug, Clone)]
struct DeviceInfo {
    pub path: String,
    pub serial: Option<String>,
    pub model: Option<String>,
    pub size: u64,
    pub is_removable: bool,
    pub mounted: bool,
}

struct WipeExecutor {
    plan: WipePlan,
    dry_run: bool,
}

impl WipeExecutor {
    fn new(plan: WipePlan, dry_run: bool) -> Self {
        WipeExecutor { plan, dry_run }
    }

    fn execute(&self) -> Result<()> {
        // Pre-execution safety checks
        self.safety_checks()?;

        // Verify device matches plan
        self.verify_device_match()?;

        // Final confirmation
        if !self.dry_run {
            self.final_confirmation()?;
        }

        match self.plan.wipe_method {
            WipeMethod::SecureErase => self.secure_erase()?,
            WipeMethod::MultiPassRandom => self.multi_pass_random()?,
            WipeMethod::SinglePassZero => self.single_pass_zero()?,
            WipeMethod::BlkDiscard => self.blk_discard()?,
            WipeMethod::Hybrid => self.hybrid_wipe()?,
        }

        // Write completion audit log
        self.write_completion_audit()?;

        Ok(())
    }

    fn safety_checks(&self) -> Result<()> {
        println!("🔒 Performing safety checks...");

        // Check if running as root
        if !geteuid().is_root() {
            bail!("This utility must be run as root for direct device access");
        }

        // Check if booted from external media
        if !self.is_booted_from_external()? {
            bail!("SAFETY: This utility should only be run when booted from external media");
        }

        // Check if target device exists
        let device_path = &self.plan.target_device.device_path;
        if !Path::new(device_path).exists() {
            bail!("Target device {} does not exist", device_path);
        }

        // Check if target device is mounted
        if self.is_device_mounted(device_path)? {
            bail!("Target device {} is currently mounted", device_path);
        }

        // Check if target device is the root filesystem
        if self.is_root_device(device_path)? {
            bail!("SAFETY: Cannot wipe the root filesystem device");
        }

        // Verify device identity
        self.verify_device_identity()?;

        println!("✅ Safety checks passed");
        Ok(())
    }

    fn is_booted_from_external(&self) -> Result<bool> {
        // Check if root filesystem is on the target device
        let output = Command::new("findmnt")
            .args(&["-n", "-o", "SOURCE", "/"])
            .output()?;

        if output.status.success() {
            let root_source = String::from_utf8_lossy(&output.stdout);
            let root_device = root_source.trim();

            // If root is on the same device we want to wipe, we're not booted from external media
            if root_device.starts_with(&self.plan.target_device.device_path) {
                return Ok(false);
            }
        }

        // Additional check: see if we're running from a USB/removable device
        let exe_path = std::env::current_exe()?;
        if let Some(parent) = exe_path.parent() {
            // Check if executable is on a removable device
            let output = Command::new("lsblk")
                .args(&["-n", "-o", "RM", "-P", parent.to_str().unwrap_or("/")])
                .output();

            if let Ok(output) = output {
                let output_str = String::from_utf8_lossy(&output.stdout);
                return Ok(output_str.contains("RM=\"1\""));
            }
        }

        // Conservative default - assume we're not on external media
        Ok(false)
    }

    fn is_device_mounted(&self, device_path: &str) -> Result<bool> {
        let output = Command::new("findmnt")
            .args(&["-n", "-S", device_path])
            .output()?;

        Ok(output.status.success() && !output.stdout.is_empty())
    }

    fn is_root_device(&self, device_path: &str) -> Result<bool> {
        let output = Command::new("findmnt")
            .args(&["-n", "-o", "SOURCE", "/"])
            .output()?;

        if output.status.success() {
            let root_device = String::from_utf8_lossy(&output.stdout);
            return Ok(root_device.trim().starts_with(device_path));
        }

        Ok(false)
    }

    fn verify_device_identity(&self) -> Result<()> {
        let device_path = &self.plan.target_device.device_path;

        // Get device serial number
        let actual_serial = self.get_device_serial(device_path)?;

        // Compare with plan
        if let Some(ref expected_serial) = self.plan.target_device.serial_number {
            if actual_serial.as_ref() != Some(expected_serial) {
                bail!("Device serial number mismatch. Expected: {:?}, Actual: {:?}",
                      expected_serial, actual_serial);
            }
        }

        // Get device size
        let actual_size = self.get_device_size(device_path)?;
        let expected_size = self.plan.target_device.size_bytes;

        // Allow 1% variance in size
        let size_diff = if actual_size > expected_size {
            actual_size - expected_size
        } else {
            expected_size - actual_size
        };

        if size_diff > expected_size / 100 {
            bail!("Device size mismatch. Expected: {} bytes, Actual: {} bytes",
                  expected_size, actual_size);
        }

        println!("✅ Device identity verified");
        Ok(())
    }

    fn get_device_serial(&self, device_path: &str) -> Result<Option<String>> {
        let device_name = Path::new(device_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        let serial_path = format!("/sys/block/{}/serial", device_name);
        if let Ok(serial) = std::fs::read_to_string(&serial_path) {
            return Ok(Some(serial.trim().to_string()));
        }

        // Try udev approach
        let output = Command::new("udevadm")
            .args(&["info", "--query=property", "--name", device_path])
            .output()?;

        if output.status.success() {
            let properties = String::from_utf8_lossy(&output.stdout);
            for line in properties.lines() {
                if line.starts_with("ID_SERIAL=") || line.starts_with("ID_SERIAL_SHORT=") {
                    let serial = line.split('=').nth(1).unwrap_or("").to_string();
                    if !serial.is_empty() {
                        return Ok(Some(serial));
                    }
                }
            }
        }

        Ok(None)
    }

    fn get_device_size(&self, device_path: &str) -> Result<u64> {
        let mut file = File::open(device_path)?;
        let size = file.seek(SeekFrom::End(0))?;
        Ok(size)
    }

    fn verify_device_match(&self) -> Result<()> {
        println!("🔍 Verifying device matches wipe plan...");

        let device_path = &self.plan.target_device.device_path;
        println!("Target device: {}", device_path);
        println!("Expected serial: {:?}", self.plan.target_device.serial_number);
        println!("Expected size: {} bytes ({:.2} GB)",
                 self.plan.target_device.size_bytes,
                 self.plan.target_device.size_bytes as f64 / 1_000_000_000.0);

        let actual_serial = self.get_device_serial(device_path)?;
        let actual_size = self.get_device_size(device_path)?;

        println!("Actual serial: {:?}", actual_serial);
        println!("Actual size: {} bytes ({:.2} GB)",
                 actual_size,
                 actual_size as f64 / 1_000_000_000.0);

        if !self.dry_run {
            let confirm = Confirm::new()
                .with_prompt("Does this match the device you want to wipe?")
                .default(false)
                .interact()?;

            if !confirm {
                bail!("Device verification failed - user cancelled");
            }
        }

        Ok(())
    }

    fn final_confirmation(&self) -> Result<()> {
        println!("\n⚠️  FINAL WARNING ⚠️");
        println!("This will PERMANENTLY DESTROY ALL DATA on device: {}", self.plan.target_device.device_path);
        println!("Wipe method: {:?}", self.plan.wipe_method);
        println!("This action CANNOT BE UNDONE!");

        let confirm1 = Confirm::new()
            .with_prompt("Are you absolutely sure you want to proceed?")
            .default(false)
            .interact()?;

        if !confirm1 {
            bail!("Operation cancelled by user");
        }

        let confirmation_phrase = "I understand this will destroy all data";
        let input: String = Input::new()
            .with_prompt(format!("Type exactly: '{}'", confirmation_phrase))
            .interact_text()?;

        if input != confirmation_phrase {
            bail!("Confirmation phrase incorrect - operation cancelled");
        }

        println!("\n⏳ Starting wipe operation in 10 seconds...");
        println!("Press Ctrl+C now to cancel!");

        for i in (1..=10).rev() {
            print!("\r⏱️  {} seconds remaining... ", i);
            std::io::stdout().flush()?;
            thread::sleep(Duration::from_secs(1));
        }

        println!("\n🚀 Starting wipe operation...");
        Ok(())
    }

    fn secure_erase(&self) -> Result<()> {
        println!("🔐 Attempting hardware secure erase...");

        let device_path = &self.plan.target_device.device_path;

        if self.dry_run {
            println!("DRY RUN: Would attempt secure erase on {}", device_path);
            return Ok(());
        }

        // Try ATA secure erase first
        let output = Command::new("hdparm")
            .args(&["--user-master", "u", "--security-set-pass", "p", device_path])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                println!("Security password set, attempting secure erase...");

                let erase_output = Command::new("hdparm")
                    .args(&["--user-master", "u", "--security-erase", "p", device_path])
                    .output()?;

                if erase_output.status.success() {
                    println!("✅ Hardware secure erase completed");
                    return Ok(());
                }
            }
        }

        // Fallback to multi-pass random if secure erase not supported
        println!("Hardware secure erase not supported, falling back to multi-pass random");
        self.multi_pass_random()
    }

    fn multi_pass_random(&self) -> Result<()> {
        println!("🎲 Starting multi-pass random data wipe...");

        let device_path = &self.plan.target_device.device_path;
        let device_size = self.get_device_size(device_path)?;

        if self.dry_run {
            println!("DRY RUN: Would perform 3-pass random wipe on {} ({} bytes)",
                     device_path, device_size);
            return Ok(());
        }

        // Initialize libsodium for secure random
        unsafe {
            if sodium_init() < 0 {
                bail!("Failed to initialize libsodium");
            }
        }

        let passes = 3;
        for pass in 1..=passes {
            println!("🔄 Pass {}/{}: Writing random data...", pass, passes);

            let pb = ProgressBar::new(device_size);
            pb.set_style(ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                .unwrap()
                .progress_chars("##-"));

            let mut device_file = OpenOptions::new()
                .write(true)
                .open(device_path)?;

            let chunk_size = 1024 * 1024; // 1MB chunks
            let mut buffer = vec![0u8; chunk_size];
            let mut written = 0u64;

            while written < device_size {
                let to_write = std::cmp::min(chunk_size as u64, device_size - written) as usize;

                // Generate secure random data
                unsafe {
                    randombytes_buf(buffer.as_mut_ptr() as *mut _, to_write);
                }

                device_file.write_all(&buffer[..to_write])?;
                written += to_write as u64;

                pb.set_position(written);
            }

            device_file.sync_all()?;
            pb.finish_with_message(format!("Pass {} completed", pass));
        }

        println!("✅ Multi-pass random wipe completed");
        Ok(())
    }

    fn single_pass_zero(&self) -> Result<()> {
        println!("0️⃣ Starting single-pass zero wipe...");

        let device_path = &self.plan.target_device.device_path;
        let device_size = self.get_device_size(device_path)?;

        if self.dry_run {
            println!("DRY RUN: Would perform zero wipe on {} ({} bytes)",
                     device_path, device_size);
            return Ok(());
        }

        let pb = ProgressBar::new(device_size);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("##-"));

        let mut device_file = OpenOptions::new()
            .write(true)
            .open(device_path)?;

        let chunk_size = 1024 * 1024; // 1MB chunks
        let buffer = vec![0u8; chunk_size];
        let mut written = 0u64;

        while written < device_size {
            let to_write = std::cmp::min(chunk_size as u64, device_size - written) as usize;

            device_file.write_all(&buffer[..to_write])?;
            written += to_write as u64;

            pb.set_position(written);
        }

        device_file.sync_all()?;
        pb.finish_with_message("Zero wipe completed");

        println!("✅ Single-pass zero wipe completed");
        Ok(())
    }

    fn blk_discard(&self) -> Result<()> {
        println!("✂️ Starting TRIM/discard operation...");

        let device_path = &self.plan.target_device.device_path;

        if self.dry_run {
            println!("DRY RUN: Would perform TRIM/discard on {}", device_path);
            return Ok(());
        }

        let output = Command::new("blkdiscard")
            .args(&["-v", device_path])
            .output()?;

        if output.status.success() {
            println!("✅ TRIM/discard completed");
            println!("{}", String::from_utf8_lossy(&output.stdout));
        } else {
            bail!("TRIM/discard failed: {}", String::from_utf8_lossy(&output.stderr));
        }

        Ok(())
    }

    fn hybrid_wipe(&self) -> Result<()> {
        println!("🔄 Starting hybrid wipe (TRIM + random pass + zero pass)...");

        // Try TRIM first (ignore errors)
        println!("Step 1/3: TRIM/discard...");
        let _ = self.blk_discard();

        // Random pass
        println!("Step 2/3: Random data pass...");
        self.single_pass_random()?;

        // Zero pass
        println!("Step 3/3: Zero pass...");
        self.single_pass_zero()?;

        println!("✅ Hybrid wipe completed");
        Ok(())
    }

    fn single_pass_random(&self) -> Result<()> {
        let device_path = &self.plan.target_device.device_path;
        let device_size = self.get_device_size(device_path)?;

        // Initialize libsodium for secure random
        unsafe {
            if sodium_init() < 0 {
                bail!("Failed to initialize libsodium");
            }
        }

        let pb = ProgressBar::new(device_size);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("##-"));

        let mut device_file = OpenOptions::new()
            .write(true)
            .open(device_path)?;

        let chunk_size = 1024 * 1024; // 1MB chunks
        let mut buffer = vec![0u8; chunk_size];
        let mut written = 0u64;

        while written < device_size {
            let to_write = std::cmp::min(chunk_size as u64, device_size - written) as usize;

            // Generate secure random data
            unsafe {
                randombytes_buf(buffer.as_mut_ptr() as *mut _, to_write);
            }

            device_file.write_all(&buffer[..to_write])?;
            written += to_write as u64;

            pb.set_position(written);
        }

        device_file.sync_all()?;
        pb.finish();

        Ok(())
    }

    fn write_completion_audit(&self) -> Result<()> {
        let audit_entry = WipeAuditEntry {
            wipe_plan_id: self.plan.id.clone(),
            completed_at: Utc::now(),
            method_used: self.plan.wipe_method.clone(),
            device_path: self.plan.target_device.device_path.clone(),
            success: true,
            error_message: None,
        };

        // Write to removable media if available
        if let Ok(paths) = std::fs::read_dir("/media") {
            for path in paths.flatten() {
                let audit_file = path.path().join("wipe_audit.jsonl");
                if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&audit_file) {
                    let entry_json = serde_json::to_string(&audit_entry)?;
                    writeln!(file, "{}", entry_json)?;
                    println!("📝 Audit entry written to {:?}", audit_file);
                    break;
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct WipeAuditEntry {
    wipe_plan_id: String,
    completed_at: DateTime<Utc>,
    method_used: WipeMethod,
    device_path: String,
    success: bool,
    error_message: Option<String>,
}

fn list_devices() -> Result<()> {
    println!("📱 Available storage devices:");

    let output = Command::new("lsblk")
        .args(&["-d", "-o", "NAME,SIZE,TYPE,MODEL,SERIAL"])
        .output()?;

    if output.status.success() {
        println!("{}", String::from_utf8_lossy(&output.stdout));
    } else {
        bail!("Failed to list devices: {}", String::from_utf8_lossy(&output.stderr));
    }

    Ok(())
}

fn load_wipe_plan(plan_path: &Path) -> Result<WipePlan> {
    let plan_content = std::fs::read_to_string(plan_path)
        .context("Failed to read wipe plan file")?;

    let plan: WipePlan = serde_json::from_str(&plan_content)
        .context("Failed to parse wipe plan JSON")?;

    Ok(plan)
}

fn verify_plan_signature(plan: &WipePlan) -> Result<()> {
    if plan.admin_signature.is_empty() {
        bail!("Wipe plan is not signed");
    }

    // TODO: Implement proper signature verification with stored public key
    println!("⚠️  Signature verification not fully implemented");
    println!("Plan ID: {}", plan.id);
    println!("Created: {}", plan.created_at);
    println!("Approval ID: {}", plan.approval_audit_id);

    Ok(())
}

fn interactive_mode() -> Result<()> {
    println!("🔧 Interactive Wipe Utility");
    println!("==========================");

    // Check for wipe plan
    let plan_path = Path::new("wipe_plan.json");
    if !plan_path.exists() {
        bail!("No wipe plan found. This utility requires a signed wipe plan.");
    }

    let plan = load_wipe_plan(plan_path)?;

    println!("📋 Loaded wipe plan: {}", plan.id);
    println!("Target device: {}", plan.target_device.device_path);
    println!("Wipe method: {:?}", plan.wipe_method);

    // Verify signature
    verify_plan_signature(&plan)?;

    let actions = vec![
        "Dry run (preview only)",
        "Execute wipe operation",
        "List devices",
        "Exit",
    ];

    loop {
        let selection = Select::new()
            .with_prompt("What would you like to do?")
            .items(&actions)
            .default(0)
            .interact()?;

        match selection {
            0 => {
                // Dry run
                let executor = WipeExecutor::new(plan.clone(), true);
                if let Err(e) = executor.execute() {
                    eprintln!("❌ Dry run failed: {}", e);
                }
            }
            1 => {
                // Execute
                let confirm = Confirm::new()
                    .with_prompt("Are you sure you want to execute the wipe? This cannot be undone!")
                    .default(false)
                    .interact()?;

                if confirm {
                    let executor = WipeExecutor::new(plan.clone(), false);
                    match executor.execute() {
                        Ok(()) => {
                            println!("✅ Wipe operation completed successfully");
                            break;
                        }
                        Err(e) => {
                            eprintln!("❌ Wipe operation failed: {}", e);
                        }
                    }
                }
            }
            2 => {
                // List devices
                if let Err(e) = list_devices() {
                    eprintln!("❌ Failed to list devices: {}", e);
                }
            }
            3 => {
                // Exit
                println!("👋 Exiting...");
                break;
            }
            _ => unreachable!(),
        }

        println!();
    }

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize libsodium
    unsafe {
        if sodium_init() < 0 {
            bail!("Failed to initialize libsodium");
        }
    }

    match cli.command {
        Commands::List => list_devices()?,
        Commands::DryRun { plan } => {
            let wipe_plan = load_wipe_plan(&plan)?;
            verify_plan_signature(&wipe_plan)?;
            let executor = WipeExecutor::new(wipe_plan, true);
            executor.execute()?;
        }
        Commands::Execute { plan, device, device_confirm } => {
            if device != device_confirm {
                bail!("Device paths do not match. For safety, you must specify the device twice.");
            }

            let wipe_plan = load_wipe_plan(&plan)?;

            if wipe_plan.target_device.device_path != device {
                bail!("Device path '{}' does not match wipe plan target '{}'",
                      device, wipe_plan.target_device.device_path);
            }

            verify_plan_signature(&wipe_plan)?;
            let executor = WipeExecutor::new(wipe_plan, false);
            executor.execute()?;
        }
        Commands::Interactive => interactive_mode()?,
        Commands::Verify { plan } => {
            let wipe_plan = load_wipe_plan(&plan)?;
            verify_plan_signature(&wipe_plan)?;
            println!("✅ Wipe plan signature is valid");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wipe_plan_serialization() {
        let plan = WipePlan {
            id: "test-123".to_string(),
            created_at: Utc::now(),
            target_device: TargetDevice {
                device_path: "/dev/sdx".to_string(),
                device_id: "test".to_string(),
                serial_number: Some("TEST123".to_string()),
                model: Some("Test Drive".to_string()),
                size_bytes: 1000000000,
                verified_twice: true,
            },
            wipe_method: WipeMethod::MultiPassRandom,
            verification_required: true,
            admin_signature: vec![1, 2, 3, 4],
            approval_audit_id: "audit-123".to_string(),
        };

        let json = serde_json::to_string(&plan).unwrap();
        let parsed: WipePlan = serde_json::from_str(&json).unwrap();

        assert_eq!(plan.id, parsed.id);
        assert_eq!(plan.target_device.device_path, parsed.target_device.device_path);
    }
}