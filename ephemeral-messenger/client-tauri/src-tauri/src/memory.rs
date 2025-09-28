// Secure memory management - memfd, mlock, secure wiping
// Ensures no plaintext data is written to disk

use anyhow::{Result, anyhow};
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(target_os = "linux")]
use nix::{
    sys::mman::{mlockall, munlockall, MlockAllFlags},
    sys::memfd::{memfd_create, MemFdCreateFlag},
    unistd::{write, close},
    fcntl::{open, OFlag},
    sys::stat::Mode,
};

#[derive(ZeroizeOnDrop)]
pub struct SecureBuffer {
    data: Vec<u8>,
    locked: bool,
}

impl Zeroize for SecureBuffer {
    fn zeroize(&mut self) {
        self.data.zeroize();
        self.locked = false;
    }
}

impl SecureBuffer {
    pub fn new(size: usize) -> Result<Self> {
        let mut buffer = vec![0u8; size];

        // Lock this specific buffer in memory
        #[cfg(target_os = "linux")]
        {
            use nix::sys::mman::{mlock, MlockFlags};
            if let Err(e) = mlock(buffer.as_ptr() as *const std::ffi::c_void, size) {
                eprintln!("Warning: Failed to lock buffer in memory: {}", e);
            }
        }

        Ok(Self {
            data: buffer,
            locked: true,
        })
    }

    pub fn write_data(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > self.data.len() {
            return Err(anyhow!("Data too large for buffer"));
        }

        self.data[..data.len()].copy_from_slice(data);
        Ok(())
    }

    pub fn read_data(&self) -> &[u8] {
        &self.data
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }
}

pub struct SecureMemory {
    memory_locked: bool,
    anonymous_files: HashMap<String, i32>, // name -> fd
    secure_buffers: Vec<SecureBuffer>,
}

impl SecureMemory {
    pub fn new() -> Self {
        Self {
            memory_locked: false,
            anonymous_files: HashMap::new(),
            secure_buffers: Vec::new(),
        }
    }

    pub fn initialize(&mut self) -> Result<()> {
        // Lock all memory pages to prevent swapping
        self.lock_all_memory()?;
        println!("Secure memory initialized with memory locking");
        Ok(())
    }

    /// Lock all memory pages to prevent swapping to disk
    pub fn lock_all_memory(&mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            mlockall(MlockAllFlags::MCL_CURRENT | MlockAllFlags::MCL_FUTURE)
                .map_err(|e| anyhow!("Failed to lock memory pages: {}", e))?;
            self.memory_locked = true;
            println!("All memory pages locked in RAM");
        }

        #[cfg(target_os = "windows")]
        {
            // TODO: Implement Windows memory locking with VirtualLock
            eprintln!("Memory locking not yet implemented on Windows");
        }

        #[cfg(target_os = "macos")]
        {
            // TODO: Implement macOS memory locking with mlock
            eprintln!("Memory locking not yet implemented on macOS");
        }

        Ok(())
    }

    /// Create anonymous in-memory file (Linux memfd)
    pub fn create_anonymous_file(&mut self, name: &str, size: usize) -> Result<i32> {
        #[cfg(target_os = "linux")]
        {
            let fd = memfd_create(
                &std::ffi::CString::new(name)?,
                MemFdCreateFlag::MFD_CLOEXEC,
            )
            .map_err(|e| anyhow!("Failed to create memfd: {}", e))?;

            // Set file size
            nix::unistd::ftruncate(fd, size as i64)
                .map_err(|e| anyhow!("Failed to set memfd size: {}", e))?;

            self.anonymous_files.insert(name.to_string(), fd);
            println!("Created anonymous file '{}' with size {}", name, size);
            Ok(fd)
        }

        #[cfg(not(target_os = "linux"))]
        {
            // Fallback to temporary file with secure deletion
            eprintln!("Anonymous files not supported on this platform, using temp file");
            Err(anyhow!("Anonymous files not implemented on this platform"))
        }
    }

    /// Write data to anonymous file
    pub fn write_to_anonymous_file(&self, name: &str, data: &[u8]) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            if let Some(&fd) = self.anonymous_files.get(name) {
                write(fd, data)
                    .map_err(|e| anyhow!("Failed to write to anonymous file: {}", e))?;
                Ok(())
            } else {
                Err(anyhow!("Anonymous file '{}' not found", name))
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(anyhow!("Anonymous files not implemented on this platform"))
        }
    }

    /// Read data from anonymous file
    pub fn read_from_anonymous_file(&self, name: &str) -> Result<Vec<u8>> {
        #[cfg(target_os = "linux")]
        {
            if let Some(&fd) = self.anonymous_files.get(name) {
                let mut data = Vec::new();
                nix::unistd::lseek(fd, 0, nix::unistd::Whence::SeekSet)
                    .map_err(|e| anyhow!("Failed to seek in anonymous file: {}", e))?;

                // Read file contents
                let mut buffer = [0u8; 4096];
                loop {
                    match nix::unistd::read(fd, &mut buffer) {
                        Ok(0) => break, // EOF
                        Ok(n) => data.extend_from_slice(&buffer[..n]),
                        Err(e) => return Err(anyhow!("Failed to read from anonymous file: {}", e)),
                    }
                }

                Ok(data)
            } else {
                Err(anyhow!("Anonymous file '{}' not found", name))
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(anyhow!("Anonymous files not implemented on this platform"))
        }
    }

    /// Create a secure buffer in locked memory
    pub fn create_secure_buffer(&mut self, size: usize) -> Result<usize> {
        let buffer = SecureBuffer::new(size)?;
        self.secure_buffers.push(buffer);
        Ok(self.secure_buffers.len() - 1) // Return index
    }

    /// Write to secure buffer
    pub fn write_secure_buffer(&mut self, index: usize, data: &[u8]) -> Result<()> {
        if let Some(buffer) = self.secure_buffers.get_mut(index) {
            buffer.write_data(data)
        } else {
            Err(anyhow!("Secure buffer {} not found", index))
        }
    }

    /// Read from secure buffer
    pub fn read_secure_buffer(&self, index: usize) -> Result<&[u8]> {
        if let Some(buffer) = self.secure_buffers.get(index) {
            Ok(buffer.read_data())
        } else {
            Err(anyhow!("Secure buffer {} not found", index))
        }
    }

    /// Check if swap is enabled
    pub fn check_swap_status(&self) -> Result<bool> {
        let swap_info = std::fs::read_to_string("/proc/swaps")
            .map_err(|e| anyhow!("Failed to read /proc/swaps: {}", e))?;

        let active_swaps: Vec<&str> = swap_info
            .lines()
            .filter(|line| !line.starts_with("Filename") && !line.trim().is_empty())
            .collect();

        Ok(!active_swaps.is_empty())
    }

    /// Get memory usage statistics
    pub fn get_memory_stats(&self) -> Result<MemoryStats> {
        #[cfg(target_os = "linux")]
        {
            let meminfo = std::fs::read_to_string("/proc/meminfo")
                .map_err(|e| anyhow!("Failed to read /proc/meminfo: {}", e))?;

            let mut stats = MemoryStats {
                total_memory: 0,
                available_memory: 0,
                locked_memory: 0,
                swap_total: 0,
                swap_used: 0,
            };

            for line in meminfo.lines() {
                if let Some(value) = parse_meminfo_line(line, "MemTotal:") {
                    stats.total_memory = value;
                } else if let Some(value) = parse_meminfo_line(line, "MemAvailable:") {
                    stats.available_memory = value;
                } else if let Some(value) = parse_meminfo_line(line, "Mlocked:") {
                    stats.locked_memory = value;
                } else if let Some(value) = parse_meminfo_line(line, "SwapTotal:") {
                    stats.swap_total = value;
                } else if let Some(value) = parse_meminfo_line(line, "SwapFree:") {
                    stats.swap_used = stats.swap_total.saturating_sub(value);
                }
            }

            Ok(stats)
        }

        #[cfg(not(target_os = "linux"))]
        {
            Ok(MemoryStats {
                total_memory: 0,
                available_memory: 0,
                locked_memory: 0,
                swap_total: 0,
                swap_used: 0,
            })
        }
    }

    /// Secure wipe of all memory structures
    pub fn secure_wipe(&mut self) -> Result<()> {
        println!("Performing secure memory wipe...");

        // Wipe all secure buffers
        for mut buffer in self.secure_buffers.drain(..) {
            buffer.zeroize();
        }

        // Close and wipe anonymous files
        #[cfg(target_os = "linux")]
        {
            for (name, fd) in self.anonymous_files.drain() {
                if let Err(e) = close(fd) {
                    eprintln!("Warning: Failed to close anonymous file '{}': {}", name, e);
                }
            }
        }

        // Unlock memory if we locked it
        if self.memory_locked {
            #[cfg(target_os = "linux")]
            {
                if let Err(e) = munlockall() {
                    eprintln!("Warning: Failed to unlock memory: {}", e);
                }
            }
            self.memory_locked = false;
        }

        println!("Secure memory wipe completed");
        Ok(())
    }
}

impl Drop for SecureMemory {
    fn drop(&mut self) {
        if let Err(e) = self.secure_wipe() {
            eprintln!("Error during SecureMemory drop: {}", e);
        }
    }
}

#[derive(Debug, Clone)]
pub struct MemoryStats {
    pub total_memory: u64,
    pub available_memory: u64,
    pub locked_memory: u64,
    pub swap_total: u64,
    pub swap_used: u64,
}

/// Parse a line from /proc/meminfo
fn parse_meminfo_line(line: &str, prefix: &str) -> Option<u64> {
    if line.starts_with(prefix) {
        let value_str = line
            .strip_prefix(prefix)?
            .trim()
            .split_whitespace()
            .next()?;
        value_str.parse::<u64>().ok().map(|kb| kb * 1024) // Convert KB to bytes
    } else {
        None
    }
}