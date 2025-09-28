/**
 * Scripture Module for Ephemeral Messenger
 *
 * Provides offline Scripture viewing with:
 * - ESV integration (user-provided license/API key only)
 * - Public domain translations (KJV fallback)
 * - Original languages (Hebrew WLC, Greek SBLGNT)
 * - Interlinear view with morphology
 * - Completely offline operation
 */

import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { VerseLookup } from './VerseLookup';
import { InterlinearView } from './InterlinearView';
import { TranslationManager } from './TranslationManager';

interface ScriptureReference {
  book: string;
  chapter: number;
  verse?: number;
  endVerse?: number;
}

interface ScriptureText {
  reference: ScriptureReference;
  text: string;
  translation: string;
  originalText?: OriginalLanguageText;
}

interface OriginalLanguageText {
  language: 'hebrew' | 'greek';
  text: string;
  words: OriginalWord[];
  morphology?: MorphologyData[];
}

interface OriginalWord {
  text: string;
  transliteration: string;
  gloss: string;
  strongs?: string;
  morphology?: string;
  lemma?: string;
}

interface MorphologyData {
  position: number;
  parsing: string;
  description: string;
}

interface Translation {
  id: string;
  name: string;
  abbreviation: string;
  language: string;
  licenseRequired: boolean;
  available: boolean;
  description: string;
}

interface ESVLicense {
  apiKey: string;
  licenseType: 'api' | 'file';
  filePath?: string;
  validated: boolean;
  expiresAt?: string;
}

export const ScriptureModule: React.FC = () => {
  // Core state
  const [selectedTranslation, setSelectedTranslation] = useState<string>('kjv');
  const [currentReference, setCurrentReference] = useState<ScriptureReference>({
    book: 'Genesis',
    chapter: 1,
    verse: 1
  });
  const [scriptureText, setScriptureText] = useState<ScriptureText | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  // Translation management
  const [availableTranslations, setAvailableTranslations] = useState<Translation[]>([]);
  const [esvLicense, setEsvLicense] = useState<ESVLicense | null>(null);

  // View options
  const [showOriginal, setShowOriginal] = useState(false);
  const [showInterlinear, setShowInterlinear] = useState(false);
  const [showMorphology, setShowMorphology] = useState(false);

  // Search and study tools
  const [searchTerm, setSearchTerm] = useState('');
  const [searchResults, setSearchResults] = useState<ScriptureText[]>([]);
  const [strongsNumber, setStrongsNumber] = useState('');

  useEffect(() => {
    initializeScriptureModule();
  }, []);

  useEffect(() => {
    if (currentReference) {
      loadScriptureText();
    }
  }, [currentReference, selectedTranslation, showOriginal]);

  const initializeScriptureModule = async () => {
    try {
      // Load available translations
      const translations = await invoke('get_available_translations');
      setAvailableTranslations(translations);

      // Check for existing ESV license
      const esvConfig = await invoke('get_esv_license');
      setEsvLicense(esvConfig);

      // Set default translation (KJV if no ESV license)
      if (!esvConfig?.validated) {
        setSelectedTranslation('kjv');
      } else {
        setSelectedTranslation('esv');
      }

      // Load initial Scripture text
      await loadScriptureText();

    } catch (error) {
      console.error('Failed to initialize Scripture module:', error);
    }
  };

  const loadScriptureText = async () => {
    if (!currentReference) return;

    setIsLoading(true);
    try {
      const request = {
        reference: currentReference,
        translation: selectedTranslation,
        includeOriginal: showOriginal,
        includeMorphology: showMorphology
      };

      const text = await invoke('get_scripture_text', { request });
      setScriptureText(text);

    } catch (error) {
      console.error('Failed to load Scripture text:', error);
      // Show error message to user
    } finally {
      setIsLoading(false);
    }
  };

  const handleReferenceChange = (reference: ScriptureReference) => {
    setCurrentReference(reference);
  };

  const handleTranslationChange = (translationId: string) => {
    setSelectedTranslation(translationId);
  };

  const handleESVLicenseSetup = async (licenseData: Partial<ESVLicense>) => {
    try {
      const validatedLicense = await invoke('setup_esv_license', { licenseData });
      setEsvLicense(validatedLicense);

      if (validatedLicense.validated) {
        setSelectedTranslation('esv');
        // Refresh available translations
        const translations = await invoke('get_available_translations');
        setAvailableTranslations(translations);
      }

    } catch (error) {
      console.error('Failed to setup ESV license:', error);
      alert('ESV license validation failed. Please check your API key or file path.');
    }
  };

  const handleSearch = async () => {
    if (!searchTerm.trim()) return;

    setIsLoading(true);
    try {
      const results = await invoke('search_scripture', {
        query: searchTerm,
        translation: selectedTranslation,
        includeOriginal: showOriginal
      });
      setSearchResults(results);

    } catch (error) {
      console.error('Scripture search failed:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleStrongsSearch = async () => {
    if (!strongsNumber.trim()) return;

    setIsLoading(true);
    try {
      const results = await invoke('search_by_strongs', {
        strongsNumber,
        includeContext: true
      });
      setSearchResults(results);

    } catch (error) {
      console.error('Strongs search failed:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const needsESVLicense = selectedTranslation === 'esv' && (!esvLicense || !esvLicense.validated);

  return (
    <div className="scripture-viewer">
      {/* Sidebar */}
      <div className="scripture-sidebar">
        {/* Translation Selection */}
        <TranslationManager
          translations={availableTranslations}
          selectedTranslation={selectedTranslation}
          onTranslationChange={handleTranslationChange}
          esvLicense={esvLicense}
          onESVLicenseSetup={handleESVLicenseSetup}
        />

        {/* Reference Lookup */}
        <VerseLookup
          currentReference={currentReference}
          onReferenceChange={handleReferenceChange}
        />

        {/* View Options */}
        <div className="card mt-lg">
          <div className="card-header">
            <h3 className="text-lg font-semibold">View Options</h3>
          </div>
          <div className="card-content">
            <div className="form-group">
              <label className="flex items-center gap-sm">
                <input
                  type="checkbox"
                  className="form-checkbox"
                  checked={showOriginal}
                  onChange={(e) => setShowOriginal(e.target.checked)}
                />
                Show Original Language
              </label>
            </div>

            <div className="form-group">
              <label className="flex items-center gap-sm">
                <input
                  type="checkbox"
                  className="form-checkbox"
                  checked={showInterlinear}
                  onChange={(e) => setShowInterlinear(e.target.checked)}
                  disabled={!showOriginal}
                />
                Interlinear View
              </label>
            </div>

            <div className="form-group">
              <label className="flex items-center gap-sm">
                <input
                  type="checkbox"
                  className="form-checkbox"
                  checked={showMorphology}
                  onChange={(e) => setShowMorphology(e.target.checked)}
                  disabled={!showOriginal}
                />
                Morphological Analysis
              </label>
            </div>
          </div>
        </div>

        {/* Search Tools */}
        <div className="card mt-lg">
          <div className="card-header">
            <h3 className="text-lg font-semibold">Search Tools</h3>
          </div>
          <div className="card-content">
            {/* Text Search */}
            <div className="form-group">
              <label className="form-label">Search Scripture</label>
              <div className="flex gap-sm">
                <input
                  type="text"
                  className="form-input flex-1"
                  placeholder="Enter search terms..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
                />
                <button
                  className="btn btn-primary"
                  onClick={handleSearch}
                  disabled={!searchTerm.trim() || isLoading}
                >
                  🔍
                </button>
              </div>
            </div>

            {/* Strong's Search */}
            <div className="form-group">
              <label className="form-label">Strong's Number</label>
              <div className="flex gap-sm">
                <input
                  type="text"
                  className="form-input flex-1"
                  placeholder="e.g., H7225, G26"
                  value={strongsNumber}
                  onChange={(e) => setStrongsNumber(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && handleStrongsSearch()}
                />
                <button
                  className="btn btn-primary"
                  onClick={handleStrongsSearch}
                  disabled={!strongsNumber.trim() || isLoading}
                >
                  📖
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Search Results */}
        {searchResults.length > 0 && (
          <div className="card mt-lg">
            <div className="card-header">
              <h3 className="text-lg font-semibold">Search Results</h3>
              <p className="text-sm text-tertiary">{searchResults.length} results found</p>
            </div>
            <div className="card-content">
              <div className="space-y-sm max-h-60 overflow-y-auto">
                {searchResults.map((result, index) => (
                  <div
                    key={index}
                    className="p-sm bg-surface-elevated rounded-lg cursor-pointer hover:bg-primary-subtle"
                    onClick={() => setCurrentReference(result.reference)}
                  >
                    <div className="font-medium text-primary">
                      {result.reference.book} {result.reference.chapter}:{result.reference.verse}
                    </div>
                    <div className="text-sm text-secondary truncate">
                      {result.text.substring(0, 100)}...
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Main Content */}
      <div className="scripture-content">
        {/* ESV License Warning */}
        {needsESVLicense && (
          <div className="card bg-warning/10 border-warning mb-lg">
            <div className="card-content">
              <h3 className="text-lg font-semibold text-warning mb-md">
                ⚠️ ESV License Required
              </h3>
              <p className="text-sm text-secondary mb-md">
                The ESV translation requires a valid Crossway API key or offline file license.
                Please configure your license in the Translation Manager, or use the KJV (public domain) translation.
              </p>
              <button
                className="btn btn-warning"
                onClick={() => setSelectedTranslation('kjv')}
              >
                Switch to KJV
              </button>
            </div>
          </div>
        )}

        {/* Scripture Display */}
        {isLoading ? (
          <div className="flex items-center justify-center h-64">
            <div className="spinner mr-md"></div>
            <span>Loading Scripture...</span>
          </div>
        ) : scriptureText ? (
          <div>
            {/* Reference Header */}
            <div className="mb-xl">
              <h2 className="text-3xl font-bold text-primary mb-sm">
                {scriptureText.reference.book} {scriptureText.reference.chapter}
                {scriptureText.reference.verse && `:${scriptureText.reference.verse}`}
                {scriptureText.reference.endVerse && `-${scriptureText.reference.endVerse}`}
              </h2>
              <p className="text-lg text-secondary">
                {scriptureText.translation.toUpperCase()}
              </p>
            </div>

            {/* Translation Text */}
            {!showInterlinear && (
              <div className="verse-text mb-xl">
                <p className="text-lg leading-relaxed">
                  {scriptureText.text}
                </p>
              </div>
            )}

            {/* Original Language Text */}
            {showOriginal && scriptureText.originalText && !showInterlinear && (
              <div className="card bg-surface-elevated mb-xl">
                <div className="card-header">
                  <h3 className="text-lg font-semibold">
                    Original {scriptureText.originalText.language === 'hebrew' ? 'Hebrew' : 'Greek'}
                  </h3>
                </div>
                <div className="card-content">
                  <div className={`text-xl font-mono leading-relaxed ${
                    scriptureText.originalText.language === 'hebrew' ? 'text-right' : 'text-left'
                  }`}>
                    {scriptureText.originalText.text}
                  </div>
                </div>
              </div>
            )}

            {/* Interlinear View */}
            {showInterlinear && scriptureText.originalText && (
              <InterlinearView
                originalText={scriptureText.originalText}
                translationText={scriptureText.text}
                showMorphology={showMorphology}
              />
            )}

            {/* Study Notes */}
            <div className="card bg-surface-elevated">
              <div className="card-header">
                <h3 className="text-lg font-semibold">Study Notes</h3>
              </div>
              <div className="card-content">
                <p className="text-sm text-secondary">
                  📖 Offline Scripture study powered by public domain and licensed texts
                </p>
                <div className="mt-md">
                  <h4 className="font-medium mb-sm">Text Sources:</h4>
                  <ul className="text-sm text-tertiary space-y-1">
                    <li>• Hebrew: Westminster Leningrad Codex (Public Domain)</li>
                    <li>• Greek: SBLGNT (CC BY 4.0)</li>
                    <li>• ESV: Crossway (License Required)</li>
                    <li>• KJV: Public Domain</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="text-center text-tertiary py-xl">
            <p>Select a Scripture reference to begin reading</p>
          </div>
        )}
      </div>
    </div>
  );
};