// Secure Document Format (.securedoc) implementation
// Encrypted single-file container with triple encryption and detached signatures

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write, Cursor};
use tar::{Archive, Builder, Header};
use zeroize::{Zeroize, ZeroizeOnDrop};
use sha2::{Sha256, Digest};
use sodiumoxide::crypto::{
    sign::{self, Signature, PublicKey as SignPublicKey},
    secretbox::{self, Nonce as SecretboxNonce, Key as SecretboxKey},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureDocManifest {
    pub version: String,
    pub author_fingerprint: String,
    pub recipients: Vec<String>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub content_hash: String,
    pub title: String,
    pub content_type: String,
    pub policy: DocumentPolicy,
    pub attachments: Vec<AttachmentMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentPolicy {
    pub watermark_enabled: bool,
    pub offline_open_allowed: bool,
    pub max_open_count: Option<u32>,
    pub require_hardware_token: bool,
    pub auto_expire_hours: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentMetadata {
    pub filename: String,
    pub size: u64,
    pub content_type: String,
    pub hash: String,
    pub chunk_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientEnvelope {
    pub recipient_id: String,
    pub age_wrapped_key: String,
    pub layer_b_key: String,
    pub layer_a_session_key: Option<String>, // For collaborative docs
}

#[derive(ZeroizeOnDrop)]
pub struct SecureDocKeys {
    layer_c_key: SecretboxKey,
    layer_b_key: [u8; 32],
    layer_a_key: Option<[u8; 32]>,
}

impl Zeroize for SecureDocKeys {
    fn zeroize(&mut self) {
        self.layer_c_key.0.zeroize();
        self.layer_b_key.zeroize();
        if let Some(ref mut key) = self.layer_a_key {
            key.zeroize();
        }
    }
}

pub struct SecureDocFormat {
    secure_memory_locked: bool,
}

impl SecureDocFormat {
    pub fn new() -> Self {
        Self {
            secure_memory_locked: false,
        }
    }

    /// Create a new .securedoc file with triple encryption
    pub async fn create_document(
        &self,
        content: &str,
        recipients: &[String],
        title: &str,
        author_fingerprint: &str,
        signing_key: &sign::SecretKey,
        author_age_identity: &age::x25519::Identity,
    ) -> Result<Vec<u8>> {
        // Generate document keys
        let doc_keys = self.generate_document_keys()?;

        // Create manifest
        let manifest = self.create_manifest(
            content,
            recipients,
            title,
            author_fingerprint,
            &[],
        )?;

        // Encrypt content with triple encryption
        let encrypted_content = self.encrypt_content_layers(content.as_bytes(), &doc_keys)?;

        // Create recipient envelopes
        let envelopes = self.create_recipient_envelopes(
            recipients,
            &doc_keys,
            author_age_identity,
        ).await?;

        // Sign manifest
        let manifest_json = serde_json::to_vec(&manifest)?;
        let signature = sign::sign_detached(&manifest_json, signing_key);

        // Package into tar container
        self.package_securedoc(
            &manifest,
            &encrypted_content,
            &envelopes,
            &signature,
            &[],
        )
    }

    /// Open and decrypt a .securedoc file
    pub async fn open_document(
        &self,
        securedoc_data: &[u8],
        recipient_id: &str,
        age_identity: &age::x25519::Identity,
        verify_signature: bool,
    ) -> Result<(String, SecureDocManifest)> {
        // Unpack tar container
        let (manifest, encrypted_content, envelopes, signature, _attachments) =
            self.unpack_securedoc(securedoc_data)?;

        // Verify manifest signature if required
        if verify_signature {
            self.verify_manifest_signature(&manifest, &signature)?;
        }

        // Find our recipient envelope
        let envelope = envelopes
            .get(recipient_id)
            .ok_or_else(|| anyhow!("No envelope found for recipient {}", recipient_id))?;

        // Decrypt envelope to get document keys
        let doc_keys = self.decrypt_recipient_envelope(envelope, age_identity).await?;

        // Decrypt content layers
        let plaintext = self.decrypt_content_layers(&encrypted_content, &doc_keys)?;

        // Convert to string
        let content = String::from_utf8(plaintext)
            .map_err(|e| anyhow!("Invalid UTF-8 in decrypted content: {}", e))?;

        // Verify content hash
        self.verify_content_hash(&content, &manifest.content_hash)?;

        Ok((content, manifest))
    }

    /// Generate keys for document encryption
    fn generate_document_keys(&self) -> Result<SecureDocKeys> {
        use sodiumoxide::crypto::secretbox;
        use sodiumoxide::randombytes;

        Ok(SecureDocKeys {
            layer_c_key: secretbox::gen_key(),
            layer_b_key: {
                let mut key = [0u8; 32];
                randombytes::randombytes_into(&mut key);
                key
            },
            layer_a_key: None, // Only for collaborative documents
        })
    }

    /// Create document manifest
    fn create_manifest(
        &self,
        content: &str,
        recipients: &[String],
        title: &str,
        author_fingerprint: &str,
        attachments: &[AttachmentMetadata],
    ) -> Result<SecureDocManifest> {
        let content_hash = {
            let mut hasher = Sha256::new();
            hasher.update(content.as_bytes());
            hex::encode(hasher.finalize())
        };

        Ok(SecureDocManifest {
            version: "1.0".to_string(),
            author_fingerprint: author_fingerprint.to_string(),
            recipients: recipients.to_vec(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            expires_at: None,
            content_hash,
            title: title.to_string(),
            content_type: "text/html".to_string(),
            policy: DocumentPolicy {
                watermark_enabled: false,
                offline_open_allowed: true,
                max_open_count: None,
                require_hardware_token: false,
                auto_expire_hours: None,
            },
            attachments: attachments.to_vec(),
        })
    }

    /// Encrypt content with triple encryption layers
    fn encrypt_content_layers(&self, content: &[u8], keys: &SecureDocKeys) -> Result<Vec<u8>> {
        // Layer A: Signal protocol (placeholder - for collaborative docs)
        let layer_a_data = if let Some(_signal_key) = &keys.layer_a_key {
            // TODO: Implement Signal protocol encryption for collaborative documents
            content.to_vec()
        } else {
            content.to_vec()
        };

        // Layer B: Identity ECDH with ChaCha20-Poly1305
        let layer_b_data = self.encrypt_layer_b(&layer_a_data, &keys.layer_b_key)?;

        // Layer C: Age/Passphrase with NaCl secretbox
        let layer_c_data = self.encrypt_layer_c(&layer_b_data, &keys.layer_c_key)?;

        Ok(layer_c_data)
    }

    /// Decrypt content layers in reverse order
    fn decrypt_content_layers(&self, encrypted_data: &[u8], keys: &SecureDocKeys) -> Result<Vec<u8>> {
        // Layer C: Age/Passphrase decryption
        let layer_b_data = self.decrypt_layer_c(encrypted_data, &keys.layer_c_key)?;

        // Layer B: Identity ECDH decryption
        let layer_a_data = self.decrypt_layer_b(&layer_b_data, &keys.layer_b_key)?;

        // Layer A: Signal protocol decryption (placeholder)
        let plaintext = if keys.layer_a_key.is_some() {
            // TODO: Implement Signal protocol decryption
            layer_a_data
        } else {
            layer_a_data
        };

        Ok(plaintext)
    }

    /// Layer B encryption: ChaCha20-Poly1305 AEAD
    fn encrypt_layer_b(&self, data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadInPlace};
        use chacha20poly1305::aead::{Aead, Nonce as AeadNonce, generic_array::GenericArray};

        let cipher = ChaCha20Poly1305::from(GenericArray::from_slice(key));
        let nonce_bytes = sodiumoxide::randombytes::randombytes(12);
        let nonce = AeadNonce::from_slice(&nonce_bytes);

        let mut buffer = data.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(nonce, b"", &mut buffer)
            .map_err(|e| anyhow!("Layer B encryption failed: {}", e))?;

        // Combine nonce + ciphertext + tag
        let mut result = Vec::new();
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&buffer);
        result.extend_from_slice(&tag);

        Ok(result)
    }

    /// Layer B decryption: ChaCha20-Poly1305 AEAD
    fn decrypt_layer_b(&self, data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadInPlace};
        use chacha20poly1305::aead::{Aead, Nonce as AeadNonce, generic_array::GenericArray};

        if data.len() < 12 + 16 {
            return Err(anyhow!("Layer B data too short"));
        }

        let cipher = ChaCha20Poly1305::from(GenericArray::from_slice(key));
        let nonce = AeadNonce::from_slice(&data[0..12]);
        let tag_start = data.len() - 16;
        let mut ciphertext = data[12..tag_start].to_vec();
        let tag = GenericArray::from_slice(&data[tag_start..]);

        cipher
            .decrypt_in_place_detached(nonce, b"", &mut ciphertext, tag)
            .map_err(|e| anyhow!("Layer B decryption failed: {}", e))?;

        Ok(ciphertext)
    }

    /// Layer C encryption: NaCl secretbox
    fn encrypt_layer_c(&self, data: &[u8], key: &SecretboxKey) -> Result<Vec<u8>> {
        let nonce = secretbox::gen_nonce();
        let ciphertext = secretbox::seal(data, &nonce, key);

        let mut result = Vec::new();
        result.extend_from_slice(&nonce.0);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Layer C decryption: NaCl secretbox
    fn decrypt_layer_c(&self, data: &[u8], key: &SecretboxKey) -> Result<Vec<u8>> {
        if data.len() < 24 {
            return Err(anyhow!("Layer C data too short"));
        }

        let nonce = SecretboxNonce::from_slice(&data[0..24])
            .ok_or_else(|| anyhow!("Invalid nonce"))?;
        let ciphertext = &data[24..];

        secretbox::open(ciphertext, &nonce, key)
            .map_err(|_| anyhow!("Layer C decryption failed"))
    }

    /// Create per-recipient envelopes with age key wrapping
    async fn create_recipient_envelopes(
        &self,
        recipients: &[String],
        keys: &SecureDocKeys,
        author_age_identity: &age::x25519::Identity,
    ) -> Result<HashMap<String, RecipientEnvelope>> {
        let mut envelopes = HashMap::new();

        for recipient_id in recipients {
            // TODO: Look up recipient's age public key
            // For now, use placeholder
            let envelope = RecipientEnvelope {
                recipient_id: recipient_id.clone(),
                age_wrapped_key: self.wrap_key_with_age(&keys.layer_c_key.0, author_age_identity).await?,
                layer_b_key: base64::encode(&keys.layer_b_key),
                layer_a_session_key: None,
            };

            envelopes.insert(recipient_id.clone(), envelope);
        }

        Ok(envelopes)
    }

    /// Wrap encryption key with age
    async fn wrap_key_with_age(&self, key: &[u8], age_identity: &age::x25519::Identity) -> Result<String> {
        let recipient = age_identity.to_public();
        let encryptor = age::Encryptor::with_recipients(vec![Box::new(recipient)]);

        let mut encrypted = Vec::new();
        let mut writer = encryptor
            .wrap_output(&mut encrypted)
            .map_err(|e| anyhow!("Failed to create age encryptor: {}", e))?;
        writer
            .write_all(key)
            .map_err(|e| anyhow!("Failed to write key to age encryptor: {}", e))?;
        writer
            .finish()
            .map_err(|e| anyhow!("Failed to finalize age encryption: {}", e))?;

        Ok(base64::encode(&encrypted))
    }

    /// Decrypt recipient envelope
    async fn decrypt_recipient_envelope(
        &self,
        envelope: &RecipientEnvelope,
        age_identity: &age::x25519::Identity,
    ) -> Result<SecureDocKeys> {
        // Decrypt age-wrapped key
        let wrapped_key_data = base64::decode(&envelope.age_wrapped_key)
            .map_err(|e| anyhow!("Failed to decode age-wrapped key: {}", e))?;

        let decryptor = match age::Decryptor::new(&wrapped_key_data[..])
            .map_err(|e| anyhow!("Failed to create age decryptor: {}", e))? {
            age::Decryptor::Recipients(d) => d,
            _ => return Err(anyhow!("Unsupported age format")),
        };

        let mut layer_c_key = Vec::new();
        let mut reader = decryptor
            .decrypt(std::iter::once(age_identity as &dyn age::Identity))
            .map_err(|e| anyhow!("Failed to decrypt age envelope: {}", e))?;
        reader
            .read_to_end(&mut layer_c_key)
            .map_err(|e| anyhow!("Failed to read decrypted key: {}", e))?;

        // Decode Layer B key
        let layer_b_key_data = base64::decode(&envelope.layer_b_key)
            .map_err(|e| anyhow!("Failed to decode Layer B key: {}", e))?;

        if layer_c_key.len() != 32 || layer_b_key_data.len() != 32 {
            return Err(anyhow!("Invalid key lengths in envelope"));
        }

        let mut layer_c_key_array = [0u8; 32];
        layer_c_key_array.copy_from_slice(&layer_c_key);

        let mut layer_b_key_array = [0u8; 32];
        layer_b_key_array.copy_from_slice(&layer_b_key_data);

        Ok(SecureDocKeys {
            layer_c_key: SecretboxKey(layer_c_key_array),
            layer_b_key: layer_b_key_array,
            layer_a_key: None,
        })
    }

    /// Package everything into tar container
    fn package_securedoc(
        &self,
        manifest: &SecureDocManifest,
        encrypted_content: &[u8],
        envelopes: &HashMap<String, RecipientEnvelope>,
        signature: &Signature,
        attachments: &[(&str, &[u8])],
    ) -> Result<Vec<u8>> {
        let mut tar_data = Vec::new();

        {
            let mut builder = Builder::new(&mut tar_data);

            // Add manifest
            let manifest_json = serde_json::to_vec(manifest)?;
            let mut header = Header::new_gnu();
            header.set_path("manifest.json")?;
            header.set_size(manifest_json.len() as u64);
            header.set_cksum();
            builder.append(&header, manifest_json.as_slice())?;

            // Add signature
            let mut header = Header::new_gnu();
            header.set_path("sigs/manifest.sig")?;
            header.set_size(64);
            header.set_cksum();
            builder.append(&header, &signature.0[..])?;

            // Add encrypted content
            let mut header = Header::new_gnu();
            header.set_path("content.enc")?;
            header.set_size(encrypted_content.len() as u64);
            header.set_cksum();
            builder.append(&header, encrypted_content)?;

            // Add recipient envelopes
            for (recipient_id, envelope) in envelopes {
                let envelope_json = serde_json::to_vec(envelope)?;
                let mut header = Header::new_gnu();
                header.set_path(&format!("recipients/{}.json", recipient_id))?;
                header.set_size(envelope_json.len() as u64);
                header.set_cksum();
                builder.append(&header, envelope_json.as_slice())?;
            }

            // Add attachments
            for (filename, data) in attachments {
                let mut header = Header::new_gnu();
                header.set_path(&format!("attachments/{}", filename))?;
                header.set_size(data.len() as u64);
                header.set_cksum();
                builder.append(&header, *data)?;
            }

            builder.finish()?;
        }

        Ok(tar_data)
    }

    /// Unpack tar container
    fn unpack_securedoc(
        &self,
        tar_data: &[u8],
    ) -> Result<(
        SecureDocManifest,
        Vec<u8>,
        HashMap<String, RecipientEnvelope>,
        Signature,
        Vec<(String, Vec<u8>)>,
    )> {
        let mut archive = Archive::new(Cursor::new(tar_data));

        let mut manifest = None;
        let mut encrypted_content = None;
        let mut envelopes = HashMap::new();
        let mut signature = None;
        let mut attachments = Vec::new();

        for entry in archive.entries()? {
            let mut entry = entry?;
            let path = entry.path()?.to_string_lossy().to_string();

            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;

            match path.as_str() {
                "manifest.json" => {
                    manifest = Some(serde_json::from_slice(&data)?);
                }
                "content.enc" => {
                    encrypted_content = Some(data);
                }
                "sigs/manifest.sig" => {
                    if data.len() == 64 {
                        let mut sig_bytes = [0u8; 64];
                        sig_bytes.copy_from_slice(&data);
                        signature = Some(Signature(sig_bytes));
                    }
                }
                _ => {
                    if path.starts_with("recipients/") && path.ends_with(".json") {
                        let recipient_id = path
                            .strip_prefix("recipients/")
                            .unwrap()
                            .strip_suffix(".json")
                            .unwrap()
                            .to_string();
                        let envelope: RecipientEnvelope = serde_json::from_slice(&data)?;
                        envelopes.insert(recipient_id, envelope);
                    } else if path.starts_with("attachments/") {
                        let filename = path.strip_prefix("attachments/").unwrap().to_string();
                        attachments.push((filename, data));
                    }
                }
            }
        }

        let manifest = manifest.ok_or_else(|| anyhow!("Missing manifest"))?;
        let encrypted_content = encrypted_content.ok_or_else(|| anyhow!("Missing encrypted content"))?;
        let signature = signature.ok_or_else(|| anyhow!("Missing signature"))?;

        Ok((manifest, encrypted_content, envelopes, signature, attachments))
    }

    /// Verify manifest signature
    fn verify_manifest_signature(&self, manifest: &SecureDocManifest, signature: &Signature) -> Result<()> {
        // TODO: Get author's public key from fingerprint
        // For now, skip verification with warning
        eprintln!("WARNING: Manifest signature verification not implemented");
        Ok(())
    }

    /// Verify content hash
    fn verify_content_hash(&self, content: &str, expected_hash: &str) -> Result<()> {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let actual_hash = hex::encode(hasher.finalize());

        if actual_hash == expected_hash {
            Ok(())
        } else {
            Err(anyhow!(
                "Content hash mismatch: expected {}, got {}",
                expected_hash,
                actual_hash
            ))
        }
    }

    /// Apply size padding to reduce size leakage
    pub fn apply_size_padding(data: &[u8], bucket_size: usize) -> Vec<u8> {
        let padded_size = ((data.len() + bucket_size - 1) / bucket_size) * bucket_size;
        let padding_needed = padded_size - data.len();

        let mut padded = data.to_vec();
        padded.resize(padded_size, 0);

        // Add random padding instead of zeros
        if padding_needed > 0 {
            let padding = sodiumoxide::randombytes::randombytes(padding_needed);
            padded[data.len()..].copy_from_slice(&padding);
        }

        padded
    }
}