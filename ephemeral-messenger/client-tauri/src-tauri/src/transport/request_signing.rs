use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use ed25519_dalek::{Signer, Verifier, Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

type HmacSha256 = Hmac<Sha256>;

/// Request signing methods supported by the system
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum SigningMethod {
    /// HMAC-SHA256 with shared secret
    HmacSha256,
    /// Ed25519 digital signature
    Ed25519,
    /// RSA-PSS signature (future enhancement)
    RsaPss,
}

/// Request signer for API authentication
#[derive(Debug, Clone)]
pub struct RequestSigner {
    method: SigningMethod,
    key_material: KeyMaterial,
    key_id: String,
}

#[derive(Debug, Clone)]
enum KeyMaterial {
    HmacKey(Vec<u8>),
    Ed25519Key(SigningKey),
}

/// Signed request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRequest {
    /// HTTP method (GET, POST, etc.)
    pub method: String,
    /// Request path (without query parameters)
    pub path: String,
    /// Request headers (canonicalized)
    pub headers: HashMap<String, String>,
    /// Request body hash (SHA-256)
    pub body_hash: String,
    /// Timestamp when request was signed (Unix timestamp)
    pub timestamp: u64,
    /// Random nonce to prevent replay attacks
    pub nonce: String,
    /// Key identifier
    pub key_id: String,
    /// Signing method used
    pub signing_method: SigningMethod,
    /// The actual signature
    pub signature: String,
}

/// Signature verification result
#[derive(Debug, Clone)]
pub enum VerificationResult {
    Valid,
    InvalidSignature,
    Expired { max_age_seconds: u64 },
    ReplayAttack { nonce: String },
    KeyNotFound { key_id: String },
    UnsupportedMethod { method: SigningMethod },
}

impl RequestSigner {
    /// Create a new HMAC-SHA256 request signer
    pub fn new_hmac(key_id: String, secret: &[u8]) -> Self {
        Self {
            method: SigningMethod::HmacSha256,
            key_material: KeyMaterial::HmacKey(secret.to_vec()),
            key_id,
        }
    }

    /// Create a new Ed25519 request signer
    pub fn new_ed25519(key_id: String, signing_key: SigningKey) -> Self {
        Self {
            method: SigningMethod::Ed25519,
            key_material: KeyMaterial::Ed25519Key(signing_key),
            key_id,
        }
    }

    /// Generate a new Ed25519 keypair
    pub fn generate_ed25519_keypair() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    /// Sign an HTTP request
    pub fn sign_request(
        &self,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> Result<SignedRequest> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        let nonce = generate_nonce();
        let body_hash = sha256_hash(body);

        // Canonicalize headers (sort by key, lowercase)
        let mut canonical_headers = HashMap::new();
        for (key, value) in headers {
            canonical_headers.insert(key.to_lowercase(), value.clone());
        }

        // Create string to sign
        let string_to_sign = create_string_to_sign(
            method,
            path,
            &canonical_headers,
            &body_hash,
            timestamp,
            &nonce,
            &self.key_id,
            self.method,
        );

        // Generate signature based on method
        let signature = match (&self.key_material, self.method) {
            (KeyMaterial::HmacKey(key), SigningMethod::HmacSha256) => {
                sign_hmac_sha256(key, &string_to_sign)?
            }
            (KeyMaterial::Ed25519Key(key), SigningMethod::Ed25519) => {
                sign_ed25519(key, &string_to_sign)?
            }
            _ => return Err(anyhow!("Key material doesn't match signing method")),
        };

        Ok(SignedRequest {
            method: method.to_string(),
            path: path.to_string(),
            headers: canonical_headers,
            body_hash,
            timestamp,
            nonce,
            key_id: self.key_id.clone(),
            signing_method: self.method,
            signature,
        })
    }

    /// Get the public key for Ed25519 signing (for sharing with verifiers)
    pub fn get_public_key(&self) -> Result<Vec<u8>> {
        match &self.key_material {
            KeyMaterial::Ed25519Key(signing_key) => {
                Ok(signing_key.verifying_key().to_bytes().to_vec())
            }
            _ => Err(anyhow!("Public key not available for this signing method")),
        }
    }
}

/// Request signature verifier
#[derive(Debug)]
pub struct RequestVerifier {
    hmac_keys: HashMap<String, Vec<u8>>,
    ed25519_keys: HashMap<String, VerifyingKey>,
    max_timestamp_skew: u64,
    nonce_cache: HashMap<String, u64>, // nonce -> expiry timestamp
}

impl RequestVerifier {
    pub fn new(max_timestamp_skew_seconds: u64) -> Self {
        Self {
            hmac_keys: HashMap::new(),
            ed25519_keys: HashMap::new(),
            max_timestamp_skew: max_timestamp_skew_seconds,
            nonce_cache: HashMap::new(),
        }
    }

    /// Add an HMAC key for verification
    pub fn add_hmac_key(&mut self, key_id: String, secret: &[u8]) {
        self.hmac_keys.insert(key_id, secret.to_vec());
    }

    /// Add an Ed25519 public key for verification
    pub fn add_ed25519_key(&mut self, key_id: String, public_key: &[u8]) -> Result<()> {
        if public_key.len() != 32 {
            return Err(anyhow!("Ed25519 public key must be 32 bytes"));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(public_key);

        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| anyhow!("Invalid Ed25519 public key: {}", e))?;

        self.ed25519_keys.insert(key_id, verifying_key);
        Ok(())
    }

    /// Verify a signed request
    pub fn verify_request(&mut self, signed_request: &SignedRequest) -> VerificationResult {
        let current_time = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs(),
            Err(_) => return VerificationResult::InvalidSignature,
        };

        // Check timestamp
        if current_time.abs_diff(signed_request.timestamp) > self.max_timestamp_skew {
            return VerificationResult::Expired {
                max_age_seconds: self.max_timestamp_skew,
            };
        }

        // Check for replay attack
        if let Some(&expiry) = self.nonce_cache.get(&signed_request.nonce) {
            if expiry > current_time {
                return VerificationResult::ReplayAttack {
                    nonce: signed_request.nonce.clone(),
                };
            }
        }

        // Add nonce to cache (expire after max skew time)
        self.nonce_cache.insert(
            signed_request.nonce.clone(),
            current_time + self.max_timestamp_skew,
        );

        // Clean expired nonces
        self.nonce_cache.retain(|_, &mut expiry| expiry > current_time);

        // Recreate string to sign
        let string_to_sign = create_string_to_sign(
            &signed_request.method,
            &signed_request.path,
            &signed_request.headers,
            &signed_request.body_hash,
            signed_request.timestamp,
            &signed_request.nonce,
            &signed_request.key_id,
            signed_request.signing_method,
        );

        // Verify signature based on method
        match signed_request.signing_method {
            SigningMethod::HmacSha256 => {
                if let Some(key) = self.hmac_keys.get(&signed_request.key_id) {
                    match verify_hmac_sha256(key, &string_to_sign, &signed_request.signature) {
                        Ok(true) => VerificationResult::Valid,
                        _ => VerificationResult::InvalidSignature,
                    }
                } else {
                    VerificationResult::KeyNotFound {
                        key_id: signed_request.key_id.clone(),
                    }
                }
            }
            SigningMethod::Ed25519 => {
                if let Some(key) = self.ed25519_keys.get(&signed_request.key_id) {
                    match verify_ed25519(key, &string_to_sign, &signed_request.signature) {
                        Ok(true) => VerificationResult::Valid,
                        _ => VerificationResult::InvalidSignature,
                    }
                } else {
                    VerificationResult::KeyNotFound {
                        key_id: signed_request.key_id.clone(),
                    }
                }
            }
            method => VerificationResult::UnsupportedMethod { method },
        }
    }

    /// Get statistics about the verifier state
    pub fn get_stats(&self) -> VerifierStats {
        VerifierStats {
            hmac_keys_count: self.hmac_keys.len(),
            ed25519_keys_count: self.ed25519_keys.len(),
            cached_nonces_count: self.nonce_cache.len(),
            max_timestamp_skew: self.max_timestamp_skew,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct VerifierStats {
    pub hmac_keys_count: usize,
    pub ed25519_keys_count: usize,
    pub cached_nonces_count: usize,
    pub max_timestamp_skew: u64,
}

/// Create the canonical string to sign
fn create_string_to_sign(
    method: &str,
    path: &str,
    headers: &HashMap<String, String>,
    body_hash: &str,
    timestamp: u64,
    nonce: &str,
    key_id: &str,
    signing_method: SigningMethod,
) -> String {
    // Sort headers by key for canonical representation
    let mut sorted_headers: Vec<_> = headers.iter().collect();
    sorted_headers.sort_by_key(|(key, _)| *key);

    let headers_str = sorted_headers
        .iter()
        .map(|(key, value)| format!("{}:{}", key, value))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{:?}",
        method,
        path,
        headers_str,
        body_hash,
        timestamp,
        nonce,
        key_id,
        signing_method
    )
}

/// Generate a random nonce
fn generate_nonce() -> String {
    use rand::RngCore;
    let mut nonce_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut nonce_bytes);
    hex::encode(nonce_bytes)
}

/// Compute SHA-256 hash of data
fn sha256_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Sign using HMAC-SHA256
fn sign_hmac_sha256(key: &[u8], data: &str) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| anyhow!("Invalid HMAC key: {}", e))?;
    mac.update(data.as_bytes());
    let signature = mac.finalize().into_bytes();
    Ok(BASE64.encode(signature))
}

/// Verify HMAC-SHA256 signature
fn verify_hmac_sha256(key: &[u8], data: &str, signature: &str) -> Result<bool> {
    let expected_signature = sign_hmac_sha256(key, data)?;
    Ok(constant_time_eq(signature.as_bytes(), expected_signature.as_bytes()))
}

/// Sign using Ed25519
fn sign_ed25519(key: &SigningKey, data: &str) -> Result<String> {
    let signature = key.sign(data.as_bytes());
    Ok(BASE64.encode(signature.to_bytes()))
}

/// Verify Ed25519 signature
fn verify_ed25519(key: &VerifyingKey, data: &str, signature: &str) -> Result<bool> {
    let signature_bytes = BASE64.decode(signature)
        .map_err(|e| anyhow!("Invalid base64 signature: {}", e))?;

    if signature_bytes.len() != 64 {
        return Ok(false);
    }

    let signature = Signature::from_bytes(&signature_bytes.try_into().unwrap());

    match key.verify(data.as_bytes(), &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Constant-time string comparison
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// HTTP headers for request signing
pub struct SigningHeaders;

impl SigningHeaders {
    pub const SIGNATURE: &'static str = "X-Signature";
    pub const KEY_ID: &'static str = "X-Key-ID";
    pub const TIMESTAMP: &'static str = "X-Timestamp";
    pub const NONCE: &'static str = "X-Nonce";
    pub const SIGNING_METHOD: &'static str = "X-Signing-Method";
    pub const BODY_HASH: &'static str = "X-Body-Hash";
}

/// Add signature headers to HTTP request
pub fn add_signature_headers(
    headers: &mut HashMap<String, String>,
    signed_request: &SignedRequest,
) {
    headers.insert(SigningHeaders::SIGNATURE.to_string(), signed_request.signature.clone());
    headers.insert(SigningHeaders::KEY_ID.to_string(), signed_request.key_id.clone());
    headers.insert(SigningHeaders::TIMESTAMP.to_string(), signed_request.timestamp.to_string());
    headers.insert(SigningHeaders::NONCE.to_string(), signed_request.nonce.clone());
    headers.insert(SigningHeaders::SIGNING_METHOD.to_string(),
                  serde_json::to_string(&signed_request.signing_method).unwrap_or_default());
    headers.insert(SigningHeaders::BODY_HASH.to_string(), signed_request.body_hash.clone());
}

/// Extract signature information from HTTP headers
pub fn extract_signature_from_headers(
    headers: &HashMap<String, String>,
    method: &str,
    path: &str,
) -> Result<SignedRequest> {
    let signature = headers.get(SigningHeaders::SIGNATURE)
        .ok_or_else(|| anyhow!("Missing signature header"))?;
    let key_id = headers.get(SigningHeaders::KEY_ID)
        .ok_or_else(|| anyhow!("Missing key ID header"))?;
    let timestamp = headers.get(SigningHeaders::TIMESTAMP)
        .ok_or_else(|| anyhow!("Missing timestamp header"))?
        .parse::<u64>()
        .map_err(|e| anyhow!("Invalid timestamp: {}", e))?;
    let nonce = headers.get(SigningHeaders::NONCE)
        .ok_or_else(|| anyhow!("Missing nonce header"))?;
    let signing_method_str = headers.get(SigningHeaders::SIGNING_METHOD)
        .ok_or_else(|| anyhow!("Missing signing method header"))?;
    let body_hash = headers.get(SigningHeaders::BODY_HASH)
        .ok_or_else(|| anyhow!("Missing body hash header"))?;

    let signing_method: SigningMethod = serde_json::from_str(signing_method_str)
        .map_err(|e| anyhow!("Invalid signing method: {}", e))?;

    // Filter out signature-specific headers for canonical representation
    let mut canonical_headers = headers.clone();
    canonical_headers.remove(SigningHeaders::SIGNATURE);
    canonical_headers.remove(SigningHeaders::KEY_ID);
    canonical_headers.remove(SigningHeaders::TIMESTAMP);
    canonical_headers.remove(SigningHeaders::NONCE);
    canonical_headers.remove(SigningHeaders::SIGNING_METHOD);
    canonical_headers.remove(SigningHeaders::BODY_HASH);

    Ok(SignedRequest {
        method: method.to_string(),
        path: path.to_string(),
        headers: canonical_headers,
        body_hash: body_hash.clone(),
        timestamp,
        nonce: nonce.clone(),
        key_id: key_id.clone(),
        signing_method,
        signature: signature.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_signing() {
        let secret = b"test-secret-key";
        let signer = RequestSigner::new_hmac("test-key".to_string(), secret);

        let headers = HashMap::new();
        let body = b"test body";

        let signed_request = signer.sign_request("POST", "/api/test", &headers, body).unwrap();

        assert_eq!(signed_request.method, "POST");
        assert_eq!(signed_request.path, "/api/test");
        assert_eq!(signed_request.key_id, "test-key");
        assert_eq!(signed_request.signing_method, SigningMethod::HmacSha256);
        assert!(!signed_request.signature.is_empty());
        assert!(!signed_request.nonce.is_empty());

        // Verify signature
        let mut verifier = RequestVerifier::new(300); // 5 minutes
        verifier.add_hmac_key("test-key".to_string(), secret);

        let result = verifier.verify_request(&signed_request);
        assert!(matches!(result, VerificationResult::Valid));
    }

    #[test]
    fn test_ed25519_signing() {
        let (signing_key, verifying_key) = RequestSigner::generate_ed25519_keypair();
        let signer = RequestSigner::new_ed25519("ed25519-key".to_string(), signing_key);

        let headers = HashMap::new();
        let body = b"test body";

        let signed_request = signer.sign_request("GET", "/api/data", &headers, body).unwrap();

        assert_eq!(signed_request.signing_method, SigningMethod::Ed25519);

        // Verify signature
        let mut verifier = RequestVerifier::new(300);
        verifier.add_ed25519_key("ed25519-key".to_string(), &verifying_key.to_bytes()).unwrap();

        let result = verifier.verify_request(&signed_request);
        assert!(matches!(result, VerificationResult::Valid));
    }

    #[test]
    fn test_replay_attack_detection() {
        let secret = b"test-secret";
        let signer = RequestSigner::new_hmac("test".to_string(), secret);

        let headers = HashMap::new();
        let signed_request = signer.sign_request("POST", "/api", &headers, b"body").unwrap();

        let mut verifier = RequestVerifier::new(300);
        verifier.add_hmac_key("test".to_string(), secret);

        // First verification should succeed
        let result = verifier.verify_request(&signed_request);
        assert!(matches!(result, VerificationResult::Valid));

        // Second verification should detect replay
        let result = verifier.verify_request(&signed_request);
        assert!(matches!(result, VerificationResult::ReplayAttack { .. }));
    }

    #[test]
    fn test_timestamp_expiry() {
        let secret = b"test-secret";
        let signer = RequestSigner::new_hmac("test".to_string(), secret);

        // Create a signed request with modified timestamp
        let headers = HashMap::new();
        let mut signed_request = signer.sign_request("POST", "/api", &headers, b"body").unwrap();

        // Modify timestamp to be too old
        signed_request.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() - 1000; // 1000 seconds ago

        let mut verifier = RequestVerifier::new(300); // Allow 5 minutes skew
        verifier.add_hmac_key("test".to_string(), secret);

        let result = verifier.verify_request(&signed_request);
        assert!(matches!(result, VerificationResult::Expired { .. }));
    }
}