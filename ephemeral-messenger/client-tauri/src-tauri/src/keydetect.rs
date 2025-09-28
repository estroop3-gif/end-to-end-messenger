use anyhow::{Result, Context};
use std::fs;
use std::path::{Path, PathBuf};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedKey {
    pub device_id: String,
    pub device_path: String,
    pub mount_point: Option<String>,
}

pub struct HardwareKeyDetector {
    // Detector state can be added here if needed
}

impl HardwareKeyDetector {
    pub fn new() -> Result<Self> {
        Ok(HardwareKeyDetector {})
    }

    pub fn scan_for_keys(&self) -> Result<Vec<DetectedKey>> {
        let mut keys = Vec::new();

        // Check common mount points for removable media
        #[cfg(target_os = "linux")]
        {
            keys.extend(self.scan_linux_mounts()?);
        }

        #[cfg(target_os = "windows")]
        {
            keys.extend(self.scan_windows_drives()?);
        }

        #[cfg(target_os = "macos")]
        {
            keys.extend(self.scan_macos_volumes()?);
        }

        Ok(keys)
    }

    pub fn validate_key(&self, device_path: &str) -> Result<bool> {
        // Look for the expected keystore structure
        let keystore_path = Path::new(device_path).join("KEYSTORE").join("secure_key.json");

        if !keystore_path.exists() {
            return Ok(false);
        }

        // Validate the key file structure
        let content = fs::read_to_string(&keystore_path)
            .context("Failed to read key file")?;

        // Basic validation - check if it's valid JSON with expected structure
        let _: serde_json::Value = serde_json::from_str(&content)
            .context("Invalid JSON in key file")?;

        Ok(true)
    }

    #[cfg(target_os = "linux")]
    fn scan_linux_mounts(&self) -> Result<Vec<DetectedKey>> {
        let mut keys = Vec::new();

        // Read /proc/mounts to find mounted filesystems
        let mounts = fs::read_to_string("/proc/mounts")
            .context("Failed to read /proc/mounts")?;

        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let device = parts[0];
                let mount_point = parts[1];

                // Check if this looks like a removable device
                if device.starts_with("/dev/sd") || device.starts_with("/dev/nvme") {
                    // Check if KEYSTORE exists on this mount
                    let keystore_path = Path::new(mount_point).join("KEYSTORE");
                    if keystore_path.exists() {
                        keys.push(DetectedKey {
                            device_id: self.get_device_serial(device).unwrap_or_else(|_| device.to_string()),
                            device_path: mount_point.to_string(),
                            mount_point: Some(mount_point.to_string()),
                        });
                    }
                }
            }
        }

        Ok(keys)
    }

    #[cfg(target_os = "windows")]
    fn scan_windows_drives(&self) -> Result<Vec<DetectedKey>> {
        let mut keys = Vec::new();

        // Check drive letters A-Z
        for drive_letter in 'A'..='Z' {
            let drive_path = format!("{}:\\", drive_letter);
            let path = Path::new(&drive_path);

            if path.exists() {
                let keystore_path = path.join("KEYSTORE");
                if keystore_path.exists() {
                    keys.push(DetectedKey {
                        device_id: drive_path.clone(),
                        device_path: drive_path.clone(),
                        mount_point: Some(drive_path),
                    });
                }
            }
        }

        Ok(keys)
    }

    #[cfg(target_os = "macos")]
    fn scan_macos_volumes(&self) -> Result<Vec<DetectedKey>> {
        let mut keys = Vec::new();

        let volumes_dir = Path::new("/Volumes");
        if volumes_dir.exists() {
            for entry in fs::read_dir(volumes_dir)? {
                let entry = entry?;
                let volume_path = entry.path();

                if volume_path.is_dir() {
                    let keystore_path = volume_path.join("KEYSTORE");
                    if keystore_path.exists() {
                        let volume_name = volume_path.file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("Unknown")
                            .to_string();

                        keys.push(DetectedKey {
                            device_id: volume_name.clone(),
                            device_path: volume_path.to_string_lossy().to_string(),
                            mount_point: Some(volume_path.to_string_lossy().to_string()),
                        });
                    }
                }
            }
        }

        Ok(keys)
    }

    #[cfg(target_os = "linux")]
    fn get_device_serial(&self, device: &str) -> Result<String> {
        // Try to get device serial from udev or sysfs
        // This is a simplified implementation
        let device_name = Path::new(device)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        let serial_path = format!("/sys/class/block/{}/device/serial", device_name);

        if let Ok(serial) = fs::read_to_string(&serial_path) {
            Ok(serial.trim().to_string())
        } else {
            // Fallback to device path
            Ok(device.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_detector_creation() {
        let detector = HardwareKeyDetector::new().unwrap();
        // Basic smoke test
        let _keys = detector.scan_for_keys();
    }

    #[test]
    fn test_key_validation() {
        let temp_dir = TempDir::new().unwrap();
        let detector = HardwareKeyDetector::new().unwrap();

        // Test with no keystore
        assert!(!detector.validate_key(temp_dir.path().to_str().unwrap()).unwrap());

        // Create keystore structure
        let keystore_dir = temp_dir.path().join("KEYSTORE");
        fs::create_dir_all(&keystore_dir).unwrap();

        // Create a valid key file
        let key_file = keystore_dir.join("secure_key.json");
        fs::write(&key_file, r#"{"version": 1, "type": "hardware_key"}"#).unwrap();

        // Should now validate
        assert!(detector.validate_key(temp_dir.path().to_str().unwrap()).unwrap());
    }
}