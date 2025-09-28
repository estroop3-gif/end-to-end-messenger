// Public Domain Scripture Texts
//
// Provides access to public domain Bible translations (KJV)
// and daily verse functionality

use super::{ScriptureReference, DailyVerse};
use std::collections::HashMap;

pub struct PublicDomainTexts {
    kjv_texts: HashMap<String, String>,
    daily_verses: Vec<DailyVerse>,
}

impl PublicDomainTexts {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut texts = PublicDomainTexts {
            kjv_texts: HashMap::new(),
            daily_verses: create_daily_verses(),
        };

        // Load KJV text data
        texts.load_kjv_texts()?;

        Ok(texts)
    }

    pub fn get_kjv_text(&self, reference: &ScriptureReference) -> Result<String, Box<dyn std::error::Error>> {
        let key = format!("{}_{}_{}",
            reference.book.to_lowercase().replace(" ", ""),
            reference.chapter,
            reference.verse.unwrap_or(0)
        );

        if let Some(text) = self.kjv_texts.get(&key) {
            Ok(text.clone())
        } else {
            // Return sample text for demo purposes
            Ok(format!(
                "In the beginning God created the heaven and the earth. ({} {}:{})",
                reference.book, reference.chapter, reference.verse.unwrap_or(1)
            ))
        }
    }

    pub fn get_daily_verse(&self) -> DailyVerse {
        use std::time::{SystemTime, UNIX_EPOCH};

        // Use day of year to select verse
        let days_since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() / 86400;

        let index = (days_since_epoch as usize) % self.daily_verses.len();
        self.daily_verses[index].clone()
    }

    fn load_kjv_texts(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // In a real implementation, this would load from bundled KJV text files
        // For now, we'll include some sample verses

        // Genesis 1:1
        self.kjv_texts.insert("genesis_1_1".to_string(),
            "In the beginning God created the heaven and the earth.".to_string());

        // John 3:16
        self.kjv_texts.insert("john_3_16".to_string(),
            "For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life.".to_string());

        // Psalm 23:1
        self.kjv_texts.insert("psalms_23_1".to_string(),
            "The LORD is my shepherd; I shall not want.".to_string());

        // Romans 8:28
        self.kjv_texts.insert("romans_8_28".to_string(),
            "And we know that all things work together for good to them that love God, to them who are the called according to his purpose.".to_string());

        // Proverbs 3:5-6
        self.kjv_texts.insert("proverbs_3_5".to_string(),
            "Trust in the LORD with all thine heart; and lean not unto thine own understanding.".to_string());
        self.kjv_texts.insert("proverbs_3_6".to_string(),
            "In all thy ways acknowledge him, and he shall direct thy paths.".to_string());

        Ok(())
    }
}

fn create_daily_verses() -> Vec<DailyVerse> {
    vec![
        DailyVerse {
            text: "For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life.".to_string(),
            reference: "John 3:16".to_string(),
            translation: "KJV".to_string(),
        },
        DailyVerse {
            text: "Trust in the LORD with all thine heart; and lean not unto thine own understanding. In all thy ways acknowledge him, and he shall direct thy paths.".to_string(),
            reference: "Proverbs 3:5-6".to_string(),
            translation: "KJV".to_string(),
        },
        DailyVerse {
            text: "And we know that all things work together for good to them that love God, to them who are the called according to his purpose.".to_string(),
            reference: "Romans 8:28".to_string(),
            translation: "KJV".to_string(),
        },
        DailyVerse {
            text: "The LORD is my shepherd; I shall not want. He maketh me to lie down in green pastures: he leadeth me beside the still waters.".to_string(),
            reference: "Psalm 23:1-2".to_string(),
            translation: "KJV".to_string(),
        },
        DailyVerse {
            text: "Be not afraid nor dismayed by reason of this great multitude; for the battle is not yours, but God's.".to_string(),
            reference: "2 Chronicles 20:15".to_string(),
            translation: "KJV".to_string(),
        },
        DailyVerse {
            text: "I can do all things through Christ which strengtheneth me.".to_string(),
            reference: "Philippians 4:13".to_string(),
            translation: "KJV".to_string(),
        },
        DailyVerse {
            text: "For by grace are ye saved through faith; and that not of yourselves: it is the gift of God.".to_string(),
            reference: "Ephesians 2:8".to_string(),
            translation: "KJV".to_string(),
        },
        DailyVerse {
            text: "Be strong and of a good courage; be not afraid, neither be thou dismayed: for the LORD thy God is with thee whithersoever thou goest.".to_string(),
            reference: "Joshua 1:9".to_string(),
            translation: "KJV".to_string(),
        },
        DailyVerse {
            text: "But they that wait upon the LORD shall renew their strength; they shall mount up with wings as eagles; they shall run, and not be weary; and they shall walk, and not faint.".to_string(),
            reference: "Isaiah 40:31".to_string(),
            translation: "KJV".to_string(),
        },
        DailyVerse {
            text: "For I know the thoughts that I think toward you, saith the LORD, thoughts of peace, and not of evil, to give you an expected end.".to_string(),
            reference: "Jeremiah 29:11".to_string(),
            translation: "KJV".to_string(),
        },
    ]
}