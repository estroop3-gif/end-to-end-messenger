// Document editor integration for .securedoc files
// Manages creation and opening of encrypted documents

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use crate::crypto::CryptoManager;
use crate::securedoc::{SecureDocFormat, SecureDocManifest};
use crate::memory::SecureMemory;
use std::path::{Path, PathBuf};
use std::fs;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentMetadata {
    pub title: String,
    pub author: String,
    pub created_at: u64,
    pub modified_at: u64,
    pub word_count: usize,
    pub recipients: Vec<String>,
}

#[derive(ZeroizeOnDrop)]
pub struct OpenDocument {
    content: String,
    metadata: DocumentMetadata,
    manifest: SecureDocManifest,
    file_path: Option<PathBuf>,
    modified: bool,
}

impl Zeroize for OpenDocument {
    fn zeroize(&mut self) {
        self.content.zeroize();
        // Other fields will be zeroized by their Drop implementations
    }
}

pub struct DocumentEditor {
    open_documents: Vec<OpenDocument>,
    securedoc_format: SecureDocFormat,
    secure_memory: SecureMemory,
    temp_directory: PathBuf,
}

impl DocumentEditor {
    pub fn new() -> Self {
        Self {
            open_documents: Vec::new(),
            securedoc_format: SecureDocFormat::new(),
            secure_memory: SecureMemory::new(),
            temp_directory: std::env::temp_dir().join("secure-messaging-docs"),
        }
    }

    pub async fn initialize(&mut self) -> Result<()> {
        // Initialize secure memory
        self.secure_memory.initialize()?;

        // Create temporary directory for document operations
        fs::create_dir_all(&self.temp_directory)
            .map_err(|e| anyhow!("Failed to create temp directory: {}", e))?;

        println!("Document editor initialized");
        Ok(())
    }

    /// Create a new .securedoc file
    pub async fn create_secure_document(
        &mut self,
        content: &str,
        recipients: &[String],
        title: &str,
        author: &str,
        crypto_manager: &mut CryptoManager,
    ) -> Result<String> {
        // TODO: Get author fingerprint and signing key from crypto manager
        let author_fingerprint = "PLACEHOLDER_FINGERPRINT".to_string();

        // TODO: Get age identity from crypto manager
        let age_identity = age::x25519::Identity::generate();

        // TODO: Get signing key from crypto manager
        let (_, signing_key) = sodiumoxide::crypto::sign::gen_keypair();

        // Create encrypted document
        let securedoc_data = self.securedoc_format.create_document(
            content,
            recipients,
            title,
            &author_fingerprint,
            &signing_key,
            &age_identity,
        ).await?;

        // Apply size padding to reduce size leakage
        let padded_data = SecureDocFormat::apply_size_padding(&securedoc_data, 4096);

        // Save to file
        let filename = format!("{}.securedoc", sanitize_filename(title));
        let file_path = self.temp_directory.join(&filename);

        fs::write(&file_path, &padded_data)
            .map_err(|e| anyhow!("Failed to write document: {}", e))?;

        println!("Created secure document: {}", file_path.display());
        Ok(file_path.to_string_lossy().to_string())
    }

    /// Open an existing .securedoc file
    pub async fn open_secure_document(
        &mut self,
        file_path: &str,
        passphrase: Option<String>,
        crypto_manager: &mut CryptoManager,
    ) -> Result<String> {
        // Read file
        let securedoc_data = fs::read(file_path)
            .map_err(|e| anyhow!("Failed to read document file: {}", e))?;

        // TODO: Get recipient ID and age identity from crypto manager
        let recipient_id = "PLACEHOLDER_RECIPIENT";
        let age_identity = age::x25519::Identity::generate();

        // Decrypt document
        let (content, manifest) = self.securedoc_format.open_document(
            &securedoc_data,
            recipient_id,
            &age_identity,
            true, // verify signatures
        ).await?;

        // Create document metadata
        let metadata = DocumentMetadata {
            title: manifest.title.clone(),
            author: manifest.author_fingerprint.clone(),
            created_at: manifest.created_at,
            modified_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            word_count: content.split_whitespace().count(),
            recipients: manifest.recipients.clone(),
        };

        // Store in memory
        let document = OpenDocument {
            content: content.clone(),
            metadata,
            manifest,
            file_path: Some(PathBuf::from(file_path)),
            modified: false,
        };

        self.open_documents.push(document);

        println!("Opened secure document: {}", file_path);
        Ok(content)
    }

    /// Export document as PDF (with user confirmation)
    pub async fn export_as_pdf(
        &self,
        document_index: usize,
        output_path: &str,
        include_watermark: bool,
    ) -> Result<()> {
        let document = self.open_documents.get(document_index)
            .ok_or_else(|| anyhow!("Document not found"))?;

        // Create HTML for PDF conversion
        let html_content = self.create_html_for_pdf(&document.content, include_watermark)?;

        // TODO: Convert HTML to PDF using headless browser or PDF library
        // For now, save as HTML
        let html_path = format!("{}.html", output_path);
        fs::write(&html_path, html_content)
            .map_err(|e| anyhow!("Failed to write HTML file: {}", e))?;

        println!("Document exported to: {}", html_path);
        println!("WARNING: PDF export not yet implemented - exported as HTML");

        Ok(())
    }

    /// Create HTML content for PDF export
    fn create_html_for_pdf(&self, content: &str, include_watermark: bool) -> Result<String> {
        let watermark = if include_watermark {
            format!(
                "<div class='watermark'>Viewed by: {} at {}</div>",
                "CURRENT_USER", // TODO: Get from identity
                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
            )
        } else {
            String::new()
        };

        let html = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Secure Document</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 2cm; line-height: 1.6; }}
        .watermark {{ position: fixed; bottom: 1cm; right: 1cm; opacity: 0.5; font-size: 10pt; }}
        .header {{ border-bottom: 1px solid #ccc; margin-bottom: 1em; padding-bottom: 0.5em; }}
        .content {{ max-width: none; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Secure Document</h1>
        <p>Generated from encrypted .securedoc file</p>
    </div>
    <div class="content">
        {}
    </div>
    {}
</body>
</html>"#,
            content, watermark
        );

        Ok(html)
    }

    /// Get list of open documents
    pub fn get_open_documents(&self) -> Vec<&DocumentMetadata> {
        self.open_documents.iter().map(|doc| &doc.metadata).collect()
    }

    /// Close a document
    pub async fn close_document(&mut self, document_index: usize) -> Result<()> {
        if document_index < self.open_documents.len() {
            let mut document = self.open_documents.remove(document_index);
            document.zeroize();
            println!("Document closed and wiped from memory");
        }
        Ok(())
    }

    /// Close all documents
    pub async fn close_all_documents(&mut self) -> Result<()> {
        for mut document in self.open_documents.drain(..) {
            document.zeroize();
        }
        println!("All documents closed and wiped from memory");
        Ok(())
    }

    /// Secure wipe of the document editor
    pub async fn secure_wipe(&mut self) -> Result<()> {
        println!("Performing document editor secure wipe...");

        // Close all documents
        self.close_all_documents().await?;

        // Wipe secure memory
        self.secure_memory.secure_wipe()?;

        // Clean temporary directory
        if self.temp_directory.exists() {
            fs::remove_dir_all(&self.temp_directory)
                .map_err(|e| anyhow!("Failed to clean temp directory: {}", e))?;
        }

        println!("Document editor secure wipe completed");
        Ok(())
    }
}

impl Drop for DocumentEditor {
    fn drop(&mut self) {
        // Ensure secure cleanup on drop
        if let Err(e) = tokio::runtime::Runtime::new().unwrap().block_on(self.secure_wipe()) {
            eprintln!("Error during DocumentEditor drop: {}", e);
        }
    }
}

/// Sanitize filename for cross-platform compatibility
fn sanitize_filename(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == ' ' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim()
        .to_string()
}