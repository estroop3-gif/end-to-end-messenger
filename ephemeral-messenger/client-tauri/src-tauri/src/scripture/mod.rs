// Scripture Module for Ephemeral Messenger
//
// Provides offline Scripture access with proper licensing compliance:
// - ESV via user-provided license/API key only
// - Public domain translations (KJV)
// - Original languages (Hebrew WLC, Greek SBLGNT)
// - Morphological analysis and Strong's numbers
// - Completely offline operation (no network calls)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tauri::command;

pub mod esv_manager;
pub mod original_texts;
pub mod public_domain;
pub mod morphology;
pub mod search;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScriptureReference {
    pub book: String,
    pub chapter: u16,
    pub verse: Option<u16>,
    pub end_verse: Option<u16>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScriptureText {
    pub reference: ScriptureReference,
    pub text: String,
    pub translation: String,
    pub original_text: Option<OriginalLanguageText>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OriginalLanguageText {
    pub language: OriginalLanguage,
    pub text: String,
    pub words: Vec<OriginalWord>,
    pub morphology: Option<Vec<MorphologyData>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum OriginalLanguage {
    Hebrew,
    Greek,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OriginalWord {
    pub text: String,
    pub transliteration: String,
    pub gloss: String,
    pub strongs: Option<String>,
    pub morphology: Option<String>,
    pub lemma: Option<String>,
    pub position: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MorphologyData {
    pub position: u16,
    pub parsing: String,
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Translation {
    pub id: String,
    pub name: String,
    pub abbreviation: String,
    pub language: String,
    pub license_required: bool,
    pub available: bool,
    pub description: String,
    pub copyright: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ESVLicense {
    pub api_key: String,
    pub license_type: ESVLicenseType,
    pub file_path: Option<String>,
    pub validated: bool,
    pub expires_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ESVLicenseType {
    #[serde(rename = "api")]
    Api,
    #[serde(rename = "file")]
    File,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Book {
    pub name: String,
    pub abbreviation: String,
    pub testament: Testament,
    pub chapters: u16,
    pub verses: Vec<u16>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Testament {
    #[serde(rename = "old")]
    Old,
    #[serde(rename = "new")]
    New,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DailyVerse {
    pub text: String,
    pub reference: String,
    pub translation: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScriptureRequest {
    pub reference: ScriptureReference,
    pub translation: String,
    pub include_original: bool,
    pub include_morphology: bool,
}

// Scripture Manager - Main interface
pub struct ScriptureManager {
    esv_manager: esv_manager::ESVManager,
    original_texts: original_texts::OriginalTexts,
    public_domain: public_domain::PublicDomainTexts,
    morphology: morphology::MorphologyEngine,
    search: search::SearchEngine,
    available_translations: Vec<Translation>,
}

impl ScriptureManager {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(ScriptureManager {
            esv_manager: esv_manager::ESVManager::new()?,
            original_texts: original_texts::OriginalTexts::new()?,
            public_domain: public_domain::PublicDomainTexts::new()?,
            morphology: morphology::MorphologyEngine::new()?,
            search: search::SearchEngine::new()?,
            available_translations: Self::create_translation_list(),
        })
    }

    pub fn get_available_translations(&self) -> Vec<Translation> {
        let mut translations = self.available_translations.clone();

        // Update ESV availability based on license status
        for translation in &mut translations {
            if translation.id == "esv" {
                translation.available = self.esv_manager.is_licensed();
            }
        }

        translations
    }

    pub fn get_scripture_text(&self, request: &ScriptureRequest) -> Result<ScriptureText, Box<dyn std::error::Error>> {
        let base_text = match request.translation.as_str() {
            "esv" => {
                if !self.esv_manager.is_licensed() {
                    return Err("ESV license required".into());
                }
                self.esv_manager.get_text(&request.reference)?
            },
            "kjv" => self.public_domain.get_kjv_text(&request.reference)?,
            _ => return Err("Unknown translation".into()),
        };

        let mut scripture_text = ScriptureText {
            reference: request.reference.clone(),
            text: base_text,
            translation: request.translation.clone(),
            original_text: None,
        };

        // Add original language text if requested
        if request.include_original {
            let original = self.get_original_text(&request.reference)?;
            if let Some(mut original_text) = original {
                // Add morphology if requested
                if request.include_morphology {
                    original_text.morphology = Some(
                        self.morphology.get_morphology_data(&request.reference, &original_text.language)?
                    );
                }
                scripture_text.original_text = Some(original_text);
            }
        }

        Ok(scripture_text)
    }

    pub fn search_scripture(&self, query: &str, translation: &str, include_original: bool) -> Result<Vec<ScriptureText>, Box<dyn std::error::Error>> {
        self.search.search_text(query, translation, include_original)
    }

    pub fn search_by_strongs(&self, strongs_number: &str, include_context: bool) -> Result<Vec<ScriptureText>, Box<dyn std::error::Error>> {
        self.search.search_by_strongs(strongs_number, include_context)
    }

    pub fn get_bible_books(&self) -> Vec<Book> {
        create_bible_books()
    }

    pub fn setup_esv_license(&mut self, license_data: &ESVLicense) -> Result<ESVLicense, Box<dyn std::error::Error>> {
        self.esv_manager.setup_license(license_data)
    }

    pub fn get_esv_license(&self) -> Option<ESVLicense> {
        self.esv_manager.get_current_license()
    }

    pub fn get_daily_verse(&self) -> DailyVerse {
        self.public_domain.get_daily_verse()
    }

    fn get_original_text(&self, reference: &ScriptureReference) -> Result<Option<OriginalLanguageText>, Box<dyn std::error::Error>> {
        // Determine if this is OT (Hebrew) or NT (Greek)
        let book_info = self.get_book_info(&reference.book)?;

        match book_info.testament {
            Testament::Old => {
                self.original_texts.get_hebrew_text(reference)
            },
            Testament::New => {
                self.original_texts.get_greek_text(reference)
            },
        }
    }

    fn get_book_info(&self, book_name: &str) -> Result<Book, Box<dyn std::error::Error>> {
        let books = self.get_bible_books();
        books.into_iter()
            .find(|b| b.name.eq_ignore_ascii_case(book_name) || b.abbreviation.eq_ignore_ascii_case(book_name))
            .ok_or_else(|| format!("Book not found: {}", book_name).into())
    }

    fn create_translation_list() -> Vec<Translation> {
        vec![
            Translation {
                id: "kjv".to_string(),
                name: "King James Version".to_string(),
                abbreviation: "KJV".to_string(),
                language: "English".to_string(),
                license_required: false,
                available: true,
                description: "Public domain English translation from 1611".to_string(),
                copyright: None,
            },
            Translation {
                id: "esv".to_string(),
                name: "English Standard Version".to_string(),
                abbreviation: "ESV".to_string(),
                language: "English".to_string(),
                license_required: true,
                available: false, // Will be updated based on license status
                description: "Modern English translation requiring Crossway license".to_string(),
                copyright: Some("ESV® Bible (The Holy Bible, English Standard Version®), copyright © 2001 by Crossway Bibles".to_string()),
            },
        ]
    }
}

// Tauri Commands
#[command]
pub async fn get_available_translations(
    scripture_manager: tauri::State<'_, std::sync::Mutex<ScriptureManager>>
) -> Result<Vec<Translation>, String> {
    let manager = scripture_manager.lock().map_err(|e| e.to_string())?;
    Ok(manager.get_available_translations())
}

#[command]
pub async fn get_scripture_text(
    request: ScriptureRequest,
    scripture_manager: tauri::State<'_, std::sync::Mutex<ScriptureManager>>
) -> Result<ScriptureText, String> {
    let manager = scripture_manager.lock().map_err(|e| e.to_string())?;
    manager.get_scripture_text(&request).map_err(|e| e.to_string())
}

#[command]
pub async fn search_scripture(
    query: String,
    translation: String,
    include_original: bool,
    scripture_manager: tauri::State<'_, std::sync::Mutex<ScriptureManager>>
) -> Result<Vec<ScriptureText>, String> {
    let manager = scripture_manager.lock().map_err(|e| e.to_string())?;
    manager.search_scripture(&query, &translation, include_original).map_err(|e| e.to_string())
}

#[command]
pub async fn search_by_strongs(
    strongs_number: String,
    include_context: bool,
    scripture_manager: tauri::State<'_, std::sync::Mutex<ScriptureManager>>
) -> Result<Vec<ScriptureText>, String> {
    let manager = scripture_manager.lock().map_err(|e| e.to_string())?;
    manager.search_by_strongs(&strongs_number, include_context).map_err(|e| e.to_string())
}

#[command]
pub async fn get_bible_books(
    scripture_manager: tauri::State<'_, std::sync::Mutex<ScriptureManager>>
) -> Result<Vec<Book>, String> {
    let manager = scripture_manager.lock().map_err(|e| e.to_string())?;
    Ok(manager.get_bible_books())
}

#[command]
pub async fn setup_esv_license(
    license_data: ESVLicense,
    scripture_manager: tauri::State<'_, std::sync::Mutex<ScriptureManager>>
) -> Result<ESVLicense, String> {
    let mut manager = scripture_manager.lock().map_err(|e| e.to_string())?;
    manager.setup_esv_license(&license_data).map_err(|e| e.to_string())
}

#[command]
pub async fn get_esv_license(
    scripture_manager: tauri::State<'_, std::sync::Mutex<ScriptureManager>>
) -> Result<Option<ESVLicense>, String> {
    let manager = scripture_manager.lock().map_err(|e| e.to_string())?;
    Ok(manager.get_esv_license())
}

#[command]
pub async fn get_daily_verse(
    scripture_manager: tauri::State<'_, std::sync::Mutex<ScriptureManager>>
) -> Result<DailyVerse, String> {
    let manager = scripture_manager.lock().map_err(|e| e.to_string())?;
    Ok(manager.get_daily_verse())
}

// Bible book data
fn create_bible_books() -> Vec<Book> {
    vec![
        // Old Testament
        Book {
            name: "Genesis".to_string(),
            abbreviation: "Gen".to_string(),
            testament: Testament::Old,
            chapters: 50,
            verses: vec![31, 25, 24, 26, 32, 22, 24, 22, 29, 32, 32, 20, 18, 24, 21, 16, 27, 33, 38, 18, 34, 24, 20, 67, 34, 35, 46, 22, 35, 43, 55, 32, 20, 31, 29, 43, 36, 30, 23, 23, 57, 38, 34, 34, 28, 34, 31, 22, 33, 26],
        },
        Book {
            name: "Exodus".to_string(),
            abbreviation: "Exod".to_string(),
            testament: Testament::Old,
            chapters: 40,
            verses: vec![22, 25, 22, 31, 23, 30, 25, 32, 35, 29, 10, 51, 22, 31, 27, 36, 16, 27, 25, 26, 36, 31, 33, 18, 40, 37, 21, 43, 46, 38, 18, 35, 23, 35, 35, 38, 29, 31, 43, 38],
        },
        // Add more OT books...

        // New Testament
        Book {
            name: "Matthew".to_string(),
            abbreviation: "Matt".to_string(),
            testament: Testament::New,
            chapters: 28,
            verses: vec![25, 23, 17, 25, 48, 34, 29, 34, 38, 42, 30, 50, 58, 36, 39, 28, 27, 35, 30, 34, 46, 46, 39, 51, 46, 75, 66, 20],
        },
        Book {
            name: "Mark".to_string(),
            abbreviation: "Mark".to_string(),
            testament: Testament::New,
            chapters: 16,
            verses: vec![45, 28, 35, 41, 43, 56, 37, 38, 50, 52, 33, 44, 37, 72, 47, 20],
        },
        Book {
            name: "John".to_string(),
            abbreviation: "John".to_string(),
            testament: Testament::New,
            chapters: 21,
            verses: vec![51, 25, 36, 54, 47, 71, 53, 59, 41, 42, 57, 50, 38, 31, 27, 33, 26, 40, 42, 31, 25],
        },
        // Add more NT books...
    ]
}