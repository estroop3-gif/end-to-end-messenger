// Padding utilities for onion transport layers
// Implements bucketized padding to prevent traffic analysis

use anyhow::{anyhow, Result};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Standard bucket sizes for message padding
pub const BUCKET_SIZES: &[usize] = &[
    4_096,      // 4 KiB
    16_384,     // 16 KiB
    65_536,     // 64 KiB
    262_144,    // 256 KiB
    1_048_576,  // 1 MiB
];

/// Maximum message size before padding
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024; // 64 KiB

/// Padding policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PaddingPolicy {
    Enabled,
    Disabled,
}

/// Padding metadata for integrity verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaddingInfo {
    pub bucket_size: usize,
    pub original_size: usize,
    pub padding_type: PaddingType,
    pub mac: [u8; 16], // HMAC of original data
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PaddingType {
    Random,
    ZeroFill,
    Pattern(u8),
}

/// Find the appropriate bucket size for a given message length
pub fn bucketize(len: usize) -> usize {
    if len > MAX_MESSAGE_SIZE {
        // Messages larger than max size use the largest bucket
        return *BUCKET_SIZES.last().unwrap();
    }

    // Find the smallest bucket that can contain the message
    for &bucket_size in BUCKET_SIZES {
        if len <= bucket_size {
            return bucket_size;
        }
    }

    // Fallback to largest bucket
    *BUCKET_SIZES.last().unwrap()
}

/// Add padding to message to reach target bucket size
pub fn add_padding(data: &[u8], target_bucket: usize) -> Result<Vec<u8>> {
    if data.len() > target_bucket {
        return Err(anyhow!(
            "Data size {} exceeds target bucket {}",
            data.len(),
            target_bucket
        ));
    }

    if !BUCKET_SIZES.contains(&target_bucket) {
        return Err(anyhow!("Invalid bucket size: {}", target_bucket));
    }

    let padding_needed = target_bucket - data.len();
    if padding_needed == 0 {
        return Ok(data.to_vec());
    }

    // Create padded message
    let mut padded = Vec::with_capacity(target_bucket);
    padded.extend_from_slice(data);

    // Add random padding
    add_random_padding(&mut padded, padding_needed)?;

    Ok(padded)
}

/// Remove padding from message and verify integrity
pub fn remove_padding(padded_data: &[u8], original_size: usize) -> Result<Vec<u8>> {
    if original_size > padded_data.len() {
        return Err(anyhow!(
            "Original size {} exceeds padded data length {}",
            original_size,
            padded_data.len()
        ));
    }

    if original_size > MAX_MESSAGE_SIZE {
        return Err(anyhow!(
            "Original size {} exceeds maximum allowed {}",
            original_size,
            MAX_MESSAGE_SIZE
        ));
    }

    // Extract original data
    let original_data = &padded_data[..original_size];

    // Verify bucket size consistency
    let expected_bucket = bucketize(original_size);
    if padded_data.len() != expected_bucket {
        return Err(anyhow!(
            "Padded size {} doesn't match expected bucket {}",
            padded_data.len(),
            expected_bucket
        ));
    }

    // Verify padding region (basic check for non-malicious padding)
    verify_padding_region(&padded_data[original_size..])?;

    Ok(original_data.to_vec())
}

/// Add cryptographically secure random padding
fn add_random_padding(buffer: &mut Vec<u8>, padding_len: usize) -> Result<()> {
    let mut rng = ChaCha20Rng::from_entropy();
    let current_len = buffer.len();

    // Resize buffer to final size
    buffer.resize(current_len + padding_len, 0);

    // Fill padding region with random bytes
    rng.fill_bytes(&mut buffer[current_len..]);

    Ok(())
}

/// Verify padding region contains expected pattern
fn verify_padding_region(padding: &[u8]) -> Result<()> {
    // For random padding, we just verify it's not all zeros or all the same byte
    // (which would indicate potential tampering or incorrect padding)

    if padding.is_empty() {
        return Ok(());
    }

    // Check for all-zero padding (suspicious)
    if padding.iter().all(|&b| b == 0) {
        return Err(anyhow!("Suspicious all-zero padding detected"));
    }

    // Check for all-same-byte padding (suspicious for random padding)
    let first_byte = padding[0];
    if padding.len() > 16 && padding.iter().all(|&b| b == first_byte) {
        return Err(anyhow!("Suspicious uniform padding detected"));
    }

    Ok(())
}

/// Calculate HMAC for padding integrity
pub fn calculate_padding_mac(data: &[u8], key: &[u8; 32]) -> [u8; 16] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key).expect("Valid key length");
    mac.update(data);

    let result = mac.finalize().into_bytes();
    let mut mac_bytes = [0u8; 16];
    mac_bytes.copy_from_slice(&result[..16]);
    mac_bytes
}

/// Verify padding integrity using HMAC
pub fn verify_padding_mac(data: &[u8], expected_mac: &[u8; 16], key: &[u8; 32]) -> bool {
    let calculated_mac = calculate_padding_mac(data, key);

    // Constant-time comparison
    use subtle::ConstantTimeEq;
    calculated_mac.ct_eq(expected_mac).into()
}

/// Advanced padding with integrity protection
pub struct SecurePadding {
    mac_key: [u8; 32],
}

impl SecurePadding {
    pub fn new(mac_key: [u8; 32]) -> Self {
        Self { mac_key }
    }

    /// Add padding with integrity protection
    pub fn pad_with_integrity(&self, data: &[u8]) -> Result<(Vec<u8>, PaddingInfo)> {
        let bucket_size = bucketize(data.len());
        let padded_data = add_padding(data, bucket_size)?;

        let mac = calculate_padding_mac(data, &self.mac_key);

        let padding_info = PaddingInfo {
            bucket_size,
            original_size: data.len(),
            padding_type: PaddingType::Random,
            mac,
        };

        Ok((padded_data, padding_info))
    }

    /// Remove padding and verify integrity
    pub fn unpad_with_verification(
        &self,
        padded_data: &[u8],
        padding_info: &PaddingInfo,
    ) -> Result<Vec<u8>> {
        // Verify bucket size
        if padded_data.len() != padding_info.bucket_size {
            return Err(anyhow!("Bucket size mismatch"));
        }

        // Extract original data
        let original_data = remove_padding(padded_data, padding_info.original_size)?;

        // Verify MAC
        if !verify_padding_mac(&original_data, &padding_info.mac, &self.mac_key) {
            return Err(anyhow!("Padding MAC verification failed"));
        }

        Ok(original_data)
    }
}

/// Cover traffic padding utilities
pub struct CoverTrafficPadding;

impl CoverTrafficPadding {
    /// Generate dummy message of random size within bucket
    pub fn generate_dummy_message(target_bucket: usize) -> Result<Vec<u8>> {
        if !BUCKET_SIZES.contains(&target_bucket) {
            return Err(anyhow!("Invalid target bucket: {}", target_bucket));
        }

        let mut rng = ChaCha20Rng::from_entropy();

        // Generate random size between 50% and 100% of bucket
        let min_size = target_bucket / 2;
        let max_size = target_bucket;
        let dummy_size = min_size + (rng.next_u32() as usize % (max_size - min_size));

        let mut dummy_data = vec![0u8; dummy_size];
        rng.fill_bytes(&mut dummy_data);

        // Add special marker to identify as cover traffic
        dummy_data[0] = 0xFF; // Cover traffic marker
        dummy_data[1] = 0xFE;

        Ok(dummy_data)
    }

    /// Check if message is cover traffic
    pub fn is_cover_traffic(data: &[u8]) -> bool {
        data.len() >= 2 && data[0] == 0xFF && data[1] == 0xFE
    }

    /// Generate realistic cover traffic schedule
    pub fn generate_cover_schedule(base_interval_ms: u64) -> Vec<u64> {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut schedule = Vec::new();
        let mut current_time = 0u64;

        // Generate 10 cover traffic intervals with jitter
        for _ in 0..10 {
            let jitter = rng.next_u32() as u64 % (base_interval_ms / 2);
            let interval = base_interval_ms + jitter;
            current_time += interval;
            schedule.push(current_time);
        }

        schedule
    }
}

/// Bucket statistics for monitoring
#[derive(Debug, Clone)]
pub struct BucketStats {
    pub bucket_usage: std::collections::HashMap<usize, u64>,
    pub total_messages: u64,
    pub total_padding_bytes: u64,
    pub efficiency_ratio: f64,
}

impl BucketStats {
    pub fn new() -> Self {
        Self {
            bucket_usage: std::collections::HashMap::new(),
            total_messages: 0,
            total_padding_bytes: 0,
            efficiency_ratio: 0.0,
        }
    }

    pub fn record_message(&mut self, original_size: usize, bucket_size: usize) {
        *self.bucket_usage.entry(bucket_size).or_insert(0) += 1;
        self.total_messages += 1;
        self.total_padding_bytes += (bucket_size - original_size) as u64;

        self.update_efficiency();
    }

    fn update_efficiency(&mut self) {
        if self.total_messages > 0 {
            let total_original_bytes = self.total_messages * 1000; // Estimate
            let total_transmitted_bytes = total_original_bytes + self.total_padding_bytes;
            self.efficiency_ratio = total_original_bytes as f64 / total_transmitted_bytes as f64;
        }
    }

    pub fn get_most_used_bucket(&self) -> Option<usize> {
        self.bucket_usage
            .iter()
            .max_by_key(|(_, &count)| count)
            .map(|(&bucket, _)| bucket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bucketize() {
        assert_eq!(bucketize(100), 4_096);
        assert_eq!(bucketize(4_096), 4_096);
        assert_eq!(bucketize(4_097), 16_384);
        assert_eq!(bucketize(16_384), 16_384);
        assert_eq!(bucketize(65_536), 65_536);
        assert_eq!(bucketize(1_000_000), 1_048_576);
        assert_eq!(bucketize(2_000_000), 1_048_576); // Beyond max, use largest
    }

    #[test]
    fn test_padding_roundtrip() {
        let original_data = b"Hello, padding world!";
        let bucket = bucketize(original_data.len());

        // Add padding
        let padded = add_padding(original_data, bucket).unwrap();
        assert_eq!(padded.len(), bucket);
        assert_eq!(&padded[..original_data.len()], original_data);

        // Remove padding
        let recovered = remove_padding(&padded, original_data.len()).unwrap();
        assert_eq!(recovered, original_data);
    }

    #[test]
    fn test_secure_padding_with_integrity() {
        let mac_key = [0x42u8; 32];
        let padding = SecurePadding::new(mac_key);
        let original_data = b"Test message for integrity checking";

        // Pad with integrity
        let (padded_data, padding_info) = padding.pad_with_integrity(original_data).unwrap();

        // Verify integrity
        let recovered = padding.unpad_with_verification(&padded_data, &padding_info).unwrap();
        assert_eq!(recovered, original_data);

        // Test tampering detection
        let mut tampered_info = padding_info.clone();
        tampered_info.mac[0] ^= 1; // Flip a bit

        assert!(padding.unpad_with_verification(&padded_data, &tampered_info).is_err());
    }

    #[test]
    fn test_cover_traffic() {
        let dummy = CoverTrafficPadding::generate_dummy_message(4_096).unwrap();
        assert_eq!(dummy.len(), 4_096);
        assert!(CoverTrafficPadding::is_cover_traffic(&dummy));

        let normal_message = b"Normal message";
        assert!(!CoverTrafficPadding::is_cover_traffic(normal_message));
    }

    #[test]
    fn test_bucket_stats() {
        let mut stats = BucketStats::new();

        stats.record_message(1000, 4_096);
        stats.record_message(2000, 4_096);
        stats.record_message(10_000, 16_384);

        assert_eq!(stats.total_messages, 3);
        assert_eq!(stats.get_most_used_bucket(), Some(4_096));
        assert!(stats.efficiency_ratio > 0.0 && stats.efficiency_ratio < 1.0);
    }

    #[test]
    fn test_padding_validation() {
        // Test oversized data
        let large_data = vec![0u8; 5_000];
        assert!(add_padding(&large_data, 4_096).is_err());

        // Test invalid bucket
        let small_data = b"small";
        assert!(add_padding(small_data, 12345).is_err());

        // Test remove padding with wrong size
        let padded = vec![0u8; 4_096];
        assert!(remove_padding(&padded, 5_000).is_err());
    }

    #[test]
    fn test_mac_calculation() {
        let key = [0x5Au8; 32];
        let data = b"test data for MAC";

        let mac1 = calculate_padding_mac(data, &key);
        let mac2 = calculate_padding_mac(data, &key);

        // Same input should produce same MAC
        assert_eq!(mac1, mac2);

        // Verification should succeed
        assert!(verify_padding_mac(data, &mac1, &key));

        // Wrong MAC should fail
        let mut wrong_mac = mac1;
        wrong_mac[0] ^= 1;
        assert!(!verify_padding_mac(data, &wrong_mac, &key));
    }

    #[test]
    fn test_cover_traffic_schedule() {
        let schedule = CoverTrafficPadding::generate_cover_schedule(1000);
        assert_eq!(schedule.len(), 10);

        // Times should be increasing
        for i in 1..schedule.len() {
            assert!(schedule[i] > schedule[i-1]);
        }

        // Each interval should be roughly around base interval
        for i in 1..schedule.len() {
            let interval = schedule[i] - schedule[i-1];
            assert!(interval >= 1000 && interval <= 1500); // Base + jitter
        }
    }

    #[test]
    fn test_padding_region_verification() {
        // Random padding should pass
        let mut random_padding = vec![0u8; 100];
        rand::thread_rng().fill_bytes(&mut random_padding);
        assert!(verify_padding_region(&random_padding).is_ok());

        // All-zero padding should fail
        let zero_padding = vec![0u8; 100];
        assert!(verify_padding_region(&zero_padding).is_err());

        // All-same-byte padding should fail for large regions
        let uniform_padding = vec![0x42u8; 100];
        assert!(verify_padding_region(&uniform_padding).is_err());

        // Small uniform padding should pass
        let small_uniform = vec![0x42u8; 8];
        assert!(verify_padding_region(&small_uniform).is_ok());

        // Empty padding should pass
        assert!(verify_padding_region(&[]).is_ok());
    }
}