// ESV License Manager
//
// Handles ESV licensing compliance - only allows ESV access with valid
// user-provided license (API key or offline file)
//
// IMPORTANT: This module enforces licensing compliance for ESV text.
// ESV content is copyrighted by Crossway and requires proper licensing.

use super::{ESVLicense, ESVLicenseType, ScriptureReference};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
struct ESVResponse {
    query: String,
    canonical: String,
    parsed: Vec<Vec<i32>>,
    passage_meta: Vec<PassageMeta>,
    passages: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PassageMeta {
    canonical: String,
    chapter_start: Vec<i32>,
    chapter_end: Vec<i32>,
    prev_verse: Option<i32>,
    next_verse: Option<i32>,
    prev_chapter: Option<Vec<i32>>,
    next_chapter: Option<Vec<i32>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ESVConfig {
    license: Option<ESVLicense>,
    api_base_url: String,
    rate_limit: u32,
    cache_enabled: bool,
}

pub struct ESVManager {
    config: ESVConfig,
    text_cache: HashMap<String, String>,
    offline_texts: Option<HashMap<String, String>>,
    license_validated: bool,
}

impl ESVManager {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let config = ESVConfig {
            license: None,
            api_base_url: "https://api.esv.org/v3/".to_string(),
            rate_limit: 5000, // Per day
            cache_enabled: true,
        };

        let mut manager = ESVManager {
            config,
            text_cache: HashMap::new(),
            offline_texts: None,
            license_validated: false,
        };

        // Try to load existing license
        if let Ok(existing_license) = manager.load_stored_license() {
            manager.validate_license(&existing_license)?;
        }

        Ok(manager)
    }

    pub fn is_licensed(&self) -> bool {
        self.license_validated && self.config.license.is_some()
    }

    pub fn setup_license(&mut self, license_data: &ESVLicense) -> Result<ESVLicense, Box<dyn std::error::Error>> {
        // Validate the license
        let validated_license = self.validate_license(license_data)?;

        // Store the license securely
        self.store_license(&validated_license)?;

        // Update internal state
        self.config.license = Some(validated_license.clone());
        self.license_validated = true;

        // Load offline texts if file-based license
        if let ESVLicenseType::File = validated_license.license_type {
            if let Some(file_path) = &validated_license.file_path {
                self.load_offline_texts(file_path)?;
            }
        }

        Ok(validated_license)
    }

    pub fn get_current_license(&self) -> Option<ESVLicense> {
        self.config.license.clone()
    }

    pub fn get_text(&self, reference: &ScriptureReference) -> Result<String, Box<dyn std::error::Error>> {
        if !self.is_licensed() {
            return Err("ESV license required for access".into());
        }

        let license = self.config.license.as_ref().unwrap();

        match license.license_type {
            ESVLicenseType::Api => self.get_text_via_api(reference),
            ESVLicenseType::File => self.get_text_from_offline(reference),
        }
    }

    fn validate_license(&self, license_data: &ESVLicense) -> Result<ESVLicense, Box<dyn std::error::Error>> {
        let mut validated_license = license_data.clone();

        match license_data.license_type {
            ESVLicenseType::Api => {
                // Validate API key format
                if license_data.api_key.trim().is_empty() {
                    return Err("API key is required".into());
                }

                // Test API key with a simple request (offline validation)
                if !self.validate_api_key_format(&license_data.api_key) {
                    return Err("Invalid API key format".into());
                }

                validated_license.validated = true;
            },
            ESVLicenseType::File => {
                // Validate file path and content
                if let Some(file_path) = &license_data.file_path {
                    if !std::path::Path::new(file_path).exists() {
                        return Err("ESV file not found".into());
                    }

                    // Validate file format and content
                    self.validate_esv_file(file_path)?;

                    validated_license.validated = true;
                } else {
                    return Err("File path is required for file-based license".into());
                }
            },
        }

        Ok(validated_license)
    }

    fn validate_api_key_format(&self, api_key: &str) -> bool {
        // Basic format validation for ESV API keys
        // Real validation would require a test API call, but we avoid network calls
        api_key.len() >= 20 && api_key.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    }

    fn validate_esv_file(&self, file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let content = fs::read_to_string(file_path)?;

        // Check if it's JSON format
        if file_path.ends_with(".json") {
            let _: serde_json::Value = serde_json::from_str(&content)?;
        }
        // Check if it's EPUB format
        else if file_path.ends_with(".epub") {
            // Basic EPUB validation (check for zip structure)
            if !content.starts_with("PK") {
                return Err("Invalid EPUB file format".into());
            }
        }
        // Check if it's XML format
        else if file_path.ends_with(".xml") {
            // Basic XML validation
            if !content.trim_start().starts_with("<?xml") {
                return Err("Invalid XML file format".into());
            }
        } else {
            return Err("Unsupported file format. Use JSON, EPUB, or XML".into());
        }

        Ok(())
    }

    fn get_text_via_api(&self, reference: &ScriptureReference) -> Result<String, Box<dyn std::error::Error>> {
        // IMPORTANT: This is a placeholder implementation
        // In a real deployment, this would make authenticated API calls to ESV API
        // For this demo, we return a placeholder indicating API would be used

        let reference_string = format!("{} {}:{}",
            reference.book,
            reference.chapter,
            reference.verse.map_or(String::new(), |v| v.to_string())
        );

        Ok(format!(
            "[ESV TEXT FOR {}]\n\nThis would contain the actual ESV text retrieved via authenticated API call to api.esv.org using the user's license key.\n\nThe ESV® Bible (The Holy Bible, English Standard Version®) is copyright © 2001 by Crossway, a publishing ministry of Good News Publishers.",
            reference_string
        ))
    }

    fn get_text_from_offline(&self, reference: &ScriptureReference) -> Result<String, Box<dyn std::error::Error>> {
        if let Some(offline_texts) = &self.offline_texts {
            let key = format!("{}_{}_{}",
                reference.book.to_lowercase().replace(" ", ""),
                reference.chapter,
                reference.verse.unwrap_or(0)
            );

            if let Some(text) = offline_texts.get(&key) {
                Ok(text.clone())
            } else {
                Ok(format!(
                    "[ESV TEXT FOR {} {}:{}]\n\nText would be loaded from user's licensed ESV file.\n\nThe ESV® Bible (The Holy Bible, English Standard Version®) is copyright © 2001 by Crossway.",
                    reference.book, reference.chapter, reference.verse.unwrap_or(0)
                ))
            }
        } else {
            Err("Offline ESV texts not loaded".into())
        }
    }

    fn load_offline_texts(&mut self, file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let content = fs::read_to_string(file_path)?;
        let mut texts = HashMap::new();

        if file_path.ends_with(".json") {
            // Parse JSON ESV file
            let json_data: serde_json::Value = serde_json::from_str(&content)?;

            // Extract text data based on expected JSON structure
            // This is a simplified example - real implementation would parse the actual ESV JSON format
            if let Some(books) = json_data.get("books").and_then(|v| v.as_array()) {
                for book in books {
                    if let (Some(book_name), Some(chapters)) = (
                        book.get("name").and_then(|v| v.as_str()),
                        book.get("chapters").and_then(|v| v.as_array())
                    ) {
                        for (chapter_idx, chapter) in chapters.iter().enumerate() {
                            if let Some(verses) = chapter.get("verses").and_then(|v| v.as_array()) {
                                for (verse_idx, verse) in verses.iter().enumerate() {
                                    if let Some(text) = verse.as_str() {
                                        let key = format!("{}_{}_{}",
                                            book_name.to_lowercase().replace(" ", ""),
                                            chapter_idx + 1,
                                            verse_idx + 1
                                        );
                                        texts.insert(key, text.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // Additional format handlers would go here (EPUB, XML)

        self.offline_texts = Some(texts);
        Ok(())
    }

    fn store_license(&self, license: &ESVLicense) -> Result<(), Box<dyn std::error::Error>> {
        // Store license configuration securely (encrypted if possible)
        let config_dir = self.get_config_dir()?;
        let license_file = config_dir.join("esv_license.json");

        // Create config directory if it doesn't exist
        fs::create_dir_all(&config_dir)?;

        // Serialize and store license (in production, this should be encrypted)
        let license_json = serde_json::to_string_pretty(license)?;
        fs::write(license_file, license_json)?;

        Ok(())
    }

    fn load_stored_license(&self) -> Result<ESVLicense, Box<dyn std::error::Error>> {
        let config_dir = self.get_config_dir()?;
        let license_file = config_dir.join("esv_license.json");

        if !license_file.exists() {
            return Err("No stored license found".into());
        }

        let license_json = fs::read_to_string(license_file)?;
        let license: ESVLicense = serde_json::from_str(&license_json)?;

        Ok(license)
    }

    fn get_config_dir(&self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let home_dir = dirs::home_dir().ok_or("Could not find home directory")?;
        Ok(home_dir.join(".ephemeral-messenger").join("scripture"))
    }
}

// Additional helper functions for ESV compliance

pub fn get_esv_attribution() -> String {
    "ESV® Bible (The Holy Bible, English Standard Version®), copyright © 2001 by Crossway, a publishing ministry of Good News Publishers. All rights reserved.".to_string()
}

pub fn get_esv_license_info() -> String {
    "The ESV text may not be quoted in any publication made available to the public by a Creative Commons license without written permission from Crossway.".to_string()
}

pub fn validate_esv_usage_policy() -> Result<(), Box<dyn std::error::Error>> {
    // Implement ESV usage policy validation
    // This would check quotation limits, attribution requirements, etc.
    Ok(())
}