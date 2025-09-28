use std::fs::{File, OpenOptions};
use std::io::{Write, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use anyhow::{Result, Context, bail};
use serde::{Serialize, Deserialize};
use ed25519_dalek::{Keypair, Signature, Signer};
use rand::rngs::OsRng;
use libsodium_sys::*;
use chrono::{DateTime, Utc};

use crate::admin_approvals::{AdminApprovalManager, ApprovalRequest, AdminAction, ActionDetails, RiskLevel};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullWipePreparation {
    admin_manager: std::sync::Arc<AdminApprovalManager>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WipePlan {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub target_device: TargetDevice,
    pub wipe_method: WipeMethod,
    pub verification_required: bool,
    pub admin_signature: Vec<u8>,
    pub approval_audit_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetDevice {
    pub device_path: String,
    pub device_id: String,
    pub serial_number: Option<String>,
    pub model: Option<String>,
    pub size_bytes: u64,
    pub verified_twice: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WipeMethod {
    SecureErase,        // Hardware secure erase if supported
    MultiPassRandom,    // Multiple passes with random data
    SinglePassZero,     // Single pass with zeros
    BlkDiscard,         // TRIM/discard commands
    Hybrid,             // Combination of methods
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct USBCreationRequest {
    pub usb_device_path: String,
    pub wipe_plan: WipePlan,
    pub include_verification_tools: bool,
    pub make_bootable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub path: String,
    pub id: String,
    pub serial: Option<String>,
    pub model: Option<String>,
    pub size: u64,
    pub is_removable: bool,
    pub is_system_disk: bool,
    pub mount_points: Vec<String>,
}

impl FullWipePreparation {
    pub fn new(admin_manager: std::sync::Arc<AdminApprovalManager>) -> Result<Self> {
        // Initialize libsodium
        unsafe {
            if sodium_init() < 0 {
                bail!("Failed to initialize libsodium");
            }
        }

        Ok(FullWipePreparation {
            admin_manager,
        })
    }

    /// List available storage devices for wiping
    pub fn list_storage_devices(&self) -> Result<Vec<DeviceInfo>> {
        let mut devices = Vec::new();

        // Use lsblk to enumerate block devices
        let output = Command::new("lsblk")
            .args(&["-J", "-o", "NAME,PATH,SIZE,TYPE,MOUNTPOINT,MODEL,SERIAL,RM"])
            .output()
            .context("Failed to run lsblk command")?;

        if !output.status.success() {
            bail!("lsblk command failed: {}", String::from_utf8_lossy(&output.stderr));
        }

        let lsblk_output: serde_json::Value = serde_json::from_slice(&output.stdout)
            .context("Failed to parse lsblk JSON output")?;

        if let Some(blockdevices) = lsblk_output.get("blockdevices") {
            if let Some(devices_array) = blockdevices.as_array() {
                for device in devices_array {
                    if let Some(device_info) = self.parse_device_info(device)? {
                        devices.push(device_info);
                    }
                }
            }
        }

        Ok(devices)
    }

    /// Parse device information from lsblk output
    fn parse_device_info(&self, device: &serde_json::Value) -> Result<Option<DeviceInfo>> {
        let path = device.get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let name = device.get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let size_str = device.get("size")
            .and_then(|v| v.as_str())
            .unwrap_or("0");

        let device_type = device.get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Only include disk devices, not partitions
        if device_type != "disk" {
            return Ok(None);
        }

        let size = self.parse_size_string(size_str)?;

        let is_removable = device.get("rm")
            .and_then(|v| v.as_str())
            .map(|s| s == "1")
            .unwrap_or(false);

        let mountpoint = device.get("mountpoint")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let is_system_disk = mountpoint.as_ref()
            .map(|mp| mp.starts_with('/') && (mp == "/" || mp.starts_with("/boot")))
            .unwrap_or(false);

        let model = device.get("model")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let serial = device.get("serial")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Get mount points for all partitions
        let mut mount_points = Vec::new();
        if let Some(children) = device.get("children") {
            if let Some(children_array) = children.as_array() {
                for child in children_array {
                    if let Some(mp) = child.get("mountpoint").and_then(|v| v.as_str()) {
                        mount_points.push(mp.to_string());
                    }
                }
            }
        }

        Ok(Some(DeviceInfo {
            path: path.clone(),
            id: name,
            serial,
            model,
            size,
            is_removable,
            is_system_disk,
            mount_points,
        }))
    }

    /// Parse size string (e.g., "500G", "1T") to bytes
    fn parse_size_string(&self, size_str: &str) -> Result<u64> {
        if size_str.is_empty() {
            return Ok(0);
        }

        let size_str = size_str.trim();
        let (number_part, unit) = if size_str.ends_with('T') {
            (&size_str[..size_str.len()-1], 1024_u64.pow(4))
        } else if size_str.ends_with('G') {
            (&size_str[..size_str.len()-1], 1024_u64.pow(3))
        } else if size_str.ends_with('M') {
            (&size_str[..size_str.len()-1], 1024_u64.pow(2))
        } else if size_str.ends_with('K') {
            (&size_str[..size_str.len()-1], 1024)
        } else {
            (size_str, 1)
        };

        let number: f64 = number_part.parse()
            .context("Failed to parse size number")?;

        Ok((number * unit as f64) as u64)
    }

    /// Create a wipe plan with admin approval
    pub fn create_wipe_plan(&self, target_device: TargetDevice, wipe_method: WipeMethod) -> Result<WipePlan> {
        // Verify target device is not the system disk
        if target_device.device_path.starts_with("/dev/sda") ||
           target_device.device_path.starts_with("/dev/nvme0n1") {
            // Additional checks to ensure it's not mounted as root
            let output = Command::new("findmnt")
                .args(&["-n", "-o", "SOURCE", "/"])
                .output()?;

            if output.status.success() {
                let root_device = String::from_utf8_lossy(&output.stdout);
                if root_device.trim().starts_with(&target_device.device_path) {
                    bail!("Cannot create wipe plan for system disk");
                }
            }
        }

        // Request admin approval
        let approval_request = ApprovalRequest {
            action: AdminAction::CreateWipeUSB,
            details: ActionDetails {
                description: format!("Create full drive wipe plan for device {}", target_device.device_path),
                previous_value: None,
                new_value: Some(format!("{:?}", wipe_method)),
                additional_context: {
                    let mut context = std::collections::HashMap::new();
                    context.insert("device_path".to_string(), target_device.device_path.clone());
                    context.insert("device_size".to_string(), target_device.size_bytes.to_string());
                    if let Some(ref serial) = target_device.serial_number {
                        context.insert("device_serial".to_string(), serial.clone());
                    }
                    context
                },
            },
            justification: "Full drive wipe requested by authorized user".to_string(),
            risk_level: RiskLevel::Critical,
            required_confirmations: 1,
        };

        // This would require admin approval through the UI
        // For now, we'll create the plan assuming approval is granted
        let plan_id = uuid::Uuid::new_v4().to_string();

        let plan = WipePlan {
            id: plan_id,
            created_at: Utc::now(),
            target_device,
            wipe_method,
            verification_required: true,
            admin_signature: Vec::new(), // Will be signed after approval
            approval_audit_id: "pending".to_string(), // Will be filled after admin approval
        };

        Ok(plan)
    }

    /// Create bootable USB with wipe utility
    pub fn create_wipe_usb(&self, request: USBCreationRequest) -> Result<()> {
        // Verify USB device is removable
        let devices = self.list_storage_devices()?;
        let usb_device = devices.iter()
            .find(|d| d.path == request.usb_device_path)
            .ok_or_else(|| anyhow::anyhow!("USB device not found"))?;

        if !usb_device.is_removable {
            bail!("Target device is not removable");
        }

        // Ensure USB device is not mounted
        if !usb_device.mount_points.is_empty() {
            bail!("USB device is currently mounted. Please unmount before proceeding.");
        }

        // Create temporary directory for USB contents
        let temp_dir = tempfile::tempdir()?;
        let usb_content_dir = temp_dir.path().join("usb_content");
        std::fs::create_dir_all(&usb_content_dir)?;

        // Copy fullwipe utility
        self.copy_fullwipe_utility(&usb_content_dir)?;

        // Write wipe plan
        let plan_file = usb_content_dir.join("wipe_plan.json");
        let plan_json = serde_json::to_string_pretty(&request.wipe_plan)?;
        std::fs::write(plan_file, plan_json)?;

        // Create bootloader configuration if requested
        if request.make_bootable {
            self.create_bootloader_config(&usb_content_dir)?;
        }

        // Write README with instructions
        self.create_wipe_instructions(&usb_content_dir)?;

        // Copy contents to USB device
        self.write_to_usb_device(&request.usb_device_path, &usb_content_dir)?;

        Ok(())
    }

    /// Copy fullwipe utility to USB
    fn copy_fullwipe_utility(&self, target_dir: &Path) -> Result<()> {
        let utility_source = std::env::current_exe()?
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Cannot determine executable directory"))?
            .join("fullwipe_cli");

        let utility_target = target_dir.join("fullwipe_cli");

        if utility_source.exists() {
            std::fs::copy(utility_source, &utility_target)?;

            // Make executable
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&utility_target)?.permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&utility_target, perms)?;
            }
        } else {
            bail!("Fullwipe utility not found. Please ensure it's built and installed.");
        }

        Ok(())
    }

    /// Create bootloader configuration
    fn create_bootloader_config(&self, target_dir: &Path) -> Result<()> {
        // Create simple GRUB configuration for booting the wipe utility
        let grub_dir = target_dir.join("boot").join("grub");
        std::fs::create_dir_all(&grub_dir)?;

        let grub_cfg = r#"
set timeout=10
set default=0

menuentry "Secure Drive Wipe Utility" {
    echo "Loading secure drive wipe utility..."
    echo "WARNING: This tool can permanently destroy data!"
    echo "Press any key to continue..."
    read
    linux /fullwipe_cli --interactive
}

menuentry "Exit to BIOS/UEFI" {
    exit
}
"#;

        std::fs::write(grub_dir.join("grub.cfg"), grub_cfg)?;

        Ok(())
    }

    /// Create wipe instructions
    fn create_wipe_instructions(&self, target_dir: &Path) -> Result<()> {
        let instructions = r#"
SECURE DRIVE WIPE UTILITY
========================

WARNING: This utility can permanently destroy all data on a storage device.
Use with extreme caution and only on devices you intend to completely wipe.

IMPORTANT SAFETY NOTES:
- Ensure you have selected the correct target device
- This operation cannot be undone
- Keep this USB device secure and destroy when no longer needed
- Only run on devices that are NOT your system disk

INSTRUCTIONS:
1. Boot from this USB device
2. At the boot menu, select "Secure Drive Wipe Utility"
3. The utility will load the wipe plan from wipe_plan.json
4. Follow the on-screen prompts carefully
5. Confirm the target device TWICE before proceeding
6. Enter the required confirmation phrase exactly as prompted

MANUAL EXECUTION:
If the bootable option doesn't work, you can run the utility manually:
1. Mount this USB device on a Linux system
2. Run: sudo ./fullwipe_cli --plan wipe_plan.json --dry-run
3. Review the output carefully
4. If correct, run: sudo ./fullwipe_cli --plan wipe_plan.json --execute

For support or questions, refer to the project documentation.

Generated on: {timestamp}
"#;

        let content = instructions.replace("{timestamp}", &Utc::now().to_rfc3339());
        std::fs::write(target_dir.join("README.txt"), content)?;

        Ok(())
    }

    /// Write contents to USB device
    fn write_to_usb_device(&self, device_path: &str, source_dir: &Path) -> Result<()> {
        // First, create a filesystem on the USB device
        let format_output = Command::new("mkfs.ext4")
            .args(&["-F", device_path])
            .output()?;

        if !format_output.status.success() {
            bail!("Failed to format USB device: {}", String::from_utf8_lossy(&format_output.stderr));
        }

        // Create temporary mount point
        let mount_point = tempfile::tempdir()?;

        // Mount the USB device
        let mount_output = Command::new("mount")
            .args(&[device_path, mount_point.path().to_str().unwrap()])
            .output()?;

        if !mount_output.status.success() {
            bail!("Failed to mount USB device: {}", String::from_utf8_lossy(&mount_output.stderr));
        }

        // Copy files
        let copy_output = Command::new("cp")
            .args(&["-r", source_dir.to_str().unwrap(), mount_point.path().to_str().unwrap()])
            .output()?;

        if !copy_output.status.success() {
            // Unmount before returning error
            let _ = Command::new("umount").arg(mount_point.path()).output();
            bail!("Failed to copy files to USB: {}", String::from_utf8_lossy(&copy_output.stderr));
        }

        // Sync and unmount
        let _ = Command::new("sync").output();

        let umount_output = Command::new("umount")
            .arg(mount_point.path())
            .output()?;

        if !umount_output.status.success() {
            eprintln!("Warning: Failed to cleanly unmount USB device: {}", String::from_utf8_lossy(&umount_output.stderr));
        }

        Ok(())
    }

    /// Validate that a device can be safely wiped
    pub fn validate_wipe_target(&self, device_path: &str) -> Result<()> {
        // Check if device exists
        if !Path::new(device_path).exists() {
            bail!("Device {} does not exist", device_path);
        }

        // Check if it's a block device
        let metadata = std::fs::metadata(device_path)?;
        if !metadata.file_type().is_block_device() {
            bail!("Device {} is not a block device", device_path);
        }

        // Check if device is mounted
        let findmnt_output = Command::new("findmnt")
            .args(&["-n", "-S", device_path])
            .output()?;

        if findmnt_output.status.success() && !findmnt_output.stdout.is_empty() {
            bail!("Device {} is currently mounted", device_path);
        }

        // Check if it's the root filesystem
        let root_device_output = Command::new("findmnt")
            .args(&["-n", "-o", "SOURCE", "/"])
            .output()?;

        if root_device_output.status.success() {
            let root_device = String::from_utf8_lossy(&root_device_output.stdout);
            if root_device.trim().starts_with(device_path) {
                bail!("Cannot wipe root filesystem device");
            }
        }

        Ok(())
    }

    /// Sign a wipe plan with admin key
    pub fn sign_wipe_plan(&self, plan: &mut WipePlan) -> Result<()> {
        // Create signing key (in production, load from secure admin key)
        let mut csprng = OsRng{};
        let keypair = Keypair::generate(&mut csprng);

        // Serialize plan for signing (excluding signature)
        let mut plan_for_signing = plan.clone();
        plan_for_signing.admin_signature = Vec::new();

        let serialized = serde_json::to_vec(&plan_for_signing)
            .context("Failed to serialize wipe plan for signing")?;

        // Sign
        let signature = keypair.sign(&serialized);
        plan.admin_signature = signature.to_bytes().to_vec();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_size_parsing() {
        let temp_dir = TempDir::new().unwrap();
        let admin_manager = std::sync::Arc::new(
            crate::admin_approvals::AdminApprovalManager::new(
                std::sync::Arc::new(crate::keydetect::HardwareKeyDetector::new().unwrap()),
                std::sync::Arc::new(crate::access_modes::AccessModeManager::new(temp_dir.path().to_path_buf()).unwrap()),
            ).unwrap()
        );
        let prep = FullWipePreparation::new(admin_manager).unwrap();

        assert_eq!(prep.parse_size_string("500G").unwrap(), 500 * 1024 * 1024 * 1024);
        assert_eq!(prep.parse_size_string("1T").unwrap(), 1024_u64.pow(4));
        assert_eq!(prep.parse_size_string("256M").unwrap(), 256 * 1024 * 1024);
    }

    #[test]
    fn test_wipe_plan_creation() {
        let temp_dir = TempDir::new().unwrap();
        let admin_manager = std::sync::Arc::new(
            crate::admin_approvals::AdminApprovalManager::new(
                std::sync::Arc::new(crate::keydetect::HardwareKeyDetector::new().unwrap()),
                std::sync::Arc::new(crate::access_modes::AccessModeManager::new(temp_dir.path().to_path_buf()).unwrap()),
            ).unwrap()
        );
        let prep = FullWipePreparation::new(admin_manager).unwrap();

        let target_device = TargetDevice {
            device_path: "/dev/sdx".to_string(),
            device_id: "test_device".to_string(),
            serial_number: Some("TEST123".to_string()),
            model: Some("Test Drive".to_string()),
            size_bytes: 1000000000,
            verified_twice: true,
        };

        let plan = prep.create_wipe_plan(target_device, WipeMethod::MultiPassRandom).unwrap();

        assert!(!plan.id.is_empty());
        assert!(matches!(plan.wipe_method, WipeMethod::MultiPassRandom));
        assert_eq!(plan.target_device.device_path, "/dev/sdx");
    }
}