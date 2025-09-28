/**
 * Interlinear Scripture View Component
 *
 * Displays original language text with word-by-word translation,
 * morphological analysis, and Strong's numbers
 */

import React, { useState } from 'react';

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
  position: number;
}

interface MorphologyData {
  position: number;
  parsing: string;
  description: string;
}

interface InterlinearViewProps {
  originalText: OriginalLanguageText;
  translationText: string;
  showMorphology: boolean;
}

export const InterlinearView: React.FC<InterlinearViewProps> = ({
  originalText,
  translationText,
  showMorphology
}) => {
  const [selectedWord, setSelectedWord] = useState<OriginalWord | null>(null);
  const [showDetails, setShowDetails] = useState(false);

  const handleWordClick = (word: OriginalWord) => {
    setSelectedWord(word);
    setShowDetails(true);
  };

  const getMorphologyForWord = (position: number): MorphologyData | undefined => {
    return originalText.morphology?.find(m => m.position === position);
  };

  const formatStrongsNumber = (strongs?: string): string => {
    if (!strongs) return '';
    return strongs.startsWith('H') || strongs.startsWith('G') ? strongs :
           originalText.language === 'hebrew' ? `H${strongs}` : `G${strongs}`;
  };

  const getLanguageDirection = (): 'ltr' | 'rtl' => {
    return originalText.language === 'hebrew' ? 'rtl' : 'ltr';
  };

  return (
    <div className="interlinear-view">
      {/* Header */}
      <div className="card mb-lg">
        <div className="card-header">
          <h3 className="text-lg font-semibold">
            Interlinear View - {originalText.language === 'hebrew' ? 'Hebrew' : 'Greek'}
          </h3>
          <p className="text-sm text-tertiary">
            Click on any word for detailed analysis
          </p>
        </div>
      </div>

      {/* Interlinear Display */}
      <div className="card bg-surface-elevated mb-lg">
        <div className="card-content">
          <div className={`interlinear-container ${getLanguageDirection()}`}>
            <div className="interlinear-words-grid">
              {originalText.words.map((word, index) => {
                const morphology = getMorphologyForWord(word.position);
                const isSelected = selectedWord?.position === word.position;

                return (
                  <div
                    key={index}
                    className={`interlinear-word ${isSelected ? 'selected' : ''}`}
                    onClick={() => handleWordClick(word)}
                  >
                    {/* Original Text */}
                    <div className="original-text">
                      {word.text}
                    </div>

                    {/* Transliteration */}
                    <div className="transliteration">
                      {word.transliteration}
                    </div>

                    {/* Morphology (if enabled) */}
                    {showMorphology && morphology && (
                      <div className="morphology">
                        {morphology.parsing}
                      </div>
                    )}

                    {/* Gloss */}
                    <div className="gloss">
                      {word.gloss}
                    </div>

                    {/* Strong's Number */}
                    {word.strongs && (
                      <div className="strongs">
                        {formatStrongsNumber(word.strongs)}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Translation Reference */}
          <div className="mt-lg pt-lg border-t border-border">
            <h4 className="font-medium mb-sm">Translation:</h4>
            <p className="text-secondary leading-relaxed">
              {translationText}
            </p>
          </div>
        </div>
      </div>

      {/* Word Details Panel */}
      {showDetails && selectedWord && (
        <div className="card bg-primary/5 border-primary">
          <div className="card-header">
            <div className="flex justify-between items-start">
              <h3 className="text-lg font-semibold text-primary">
                Word Analysis: {selectedWord.text}
              </h3>
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => setShowDetails(false)}
              >
                ✕
              </button>
            </div>
          </div>

          <div className="card-content">
            <div className="grid md:grid-cols-2 gap-lg">
              {/* Basic Information */}
              <div>
                <h4 className="font-semibold mb-md">Basic Information</h4>
                <div className="space-y-sm text-sm">
                  <div className="flex justify-between">
                    <span className="text-tertiary">Original:</span>
                    <span className="font-mono text-lg">{selectedWord.text}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-tertiary">Transliteration:</span>
                    <span className="font-medium">{selectedWord.transliteration}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-tertiary">Gloss:</span>
                    <span className="font-medium">{selectedWord.gloss}</span>
                  </div>
                  {selectedWord.lemma && (
                    <div className="flex justify-between">
                      <span className="text-tertiary">Lemma:</span>
                      <span className="font-medium">{selectedWord.lemma}</span>
                    </div>
                  )}
                  {selectedWord.strongs && (
                    <div className="flex justify-between">
                      <span className="text-tertiary">Strong's:</span>
                      <span className="font-mono text-primary">
                        {formatStrongsNumber(selectedWord.strongs)}
                      </span>
                    </div>
                  )}
                </div>
              </div>

              {/* Morphological Analysis */}
              {showMorphology && (
                <div>
                  <h4 className="font-semibold mb-md">Morphological Analysis</h4>
                  {(() => {
                    const morphology = getMorphologyForWord(selectedWord.position);
                    return morphology ? (
                      <div className="space-y-sm text-sm">
                        <div className="flex justify-between">
                          <span className="text-tertiary">Parsing:</span>
                          <span className="font-mono">{morphology.parsing}</span>
                        </div>
                        <div>
                          <span className="text-tertiary">Description:</span>
                          <p className="mt-xs">{morphology.description}</p>
                        </div>
                        {selectedWord.morphology && (
                          <div>
                            <span className="text-tertiary">Full Morphology:</span>
                            <p className="mt-xs font-mono text-xs bg-surface p-sm rounded">
                              {selectedWord.morphology}
                            </p>
                          </div>
                        )}
                      </div>
                    ) : (
                      <p className="text-tertiary text-sm">
                        No morphological data available for this word.
                      </p>
                    );
                  })()}
                </div>
              )}
            </div>

            {/* Study Links */}
            <div className="mt-lg pt-lg border-t border-border">
              <h4 className="font-semibold mb-md">Study Tools</h4>
              <div className="flex gap-sm flex-wrap">
                {selectedWord.strongs && (
                  <button className="btn btn-secondary btn-sm">
                    📖 Find all occurrences of {formatStrongsNumber(selectedWord.strongs)}
                  </button>
                )}
                {selectedWord.lemma && (
                  <button className="btn btn-secondary btn-sm">
                    🔍 Search lemma: {selectedWord.lemma}
                  </button>
                )}
                <button className="btn btn-secondary btn-sm">
                  📚 Morphology help
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Legend */}
      <div className="card bg-background-alt">
        <div className="card-header">
          <h3 className="text-lg font-semibold">Interlinear Legend</h3>
        </div>
        <div className="card-content">
          <div className="grid md:grid-cols-2 gap-lg text-sm">
            <div>
              <h4 className="font-medium mb-sm">Reading Order:</h4>
              <p className="text-tertiary mb-md">
                {originalText.language === 'hebrew'
                  ? 'Hebrew reads right-to-left. Words are arranged in their original order.'
                  : 'Greek reads left-to-right. Words are arranged in their original order.'
                }
              </p>

              <h4 className="font-medium mb-sm">Text Elements:</h4>
              <ul className="space-y-1 text-tertiary">
                <li>• <strong>Original:</strong> {originalText.language === 'hebrew' ? 'Hebrew' : 'Greek'} text</li>
                <li>• <strong>Transliteration:</strong> Pronunciation guide</li>
                <li>• <strong>Gloss:</strong> Basic meaning</li>
                {showMorphology && <li>• <strong>Parsing:</strong> Grammatical form</li>}
                <li>• <strong>Strong's:</strong> Reference number for study</li>
              </ul>
            </div>

            <div>
              <h4 className="font-medium mb-sm">Interaction:</h4>
              <ul className="space-y-1 text-tertiary">
                <li>• Click any word for detailed analysis</li>
                <li>• Hover for quick preview</li>
                <li>• Use study tools to explore further</li>
              </ul>

              <h4 className="font-medium mb-sm mt-md">Sources:</h4>
              <ul className="space-y-1 text-tertiary">
                {originalText.language === 'hebrew' ? (
                  <>
                    <li>• Text: Westminster Leningrad Codex</li>
                    <li>• Morphology: Open Scriptures Hebrew</li>
                  </>
                ) : (
                  <>
                    <li>• Text: SBLGNT (CC BY 4.0)</li>
                    <li>• Morphology: MorphGNT</li>
                  </>
                )}
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// Additional CSS classes (to be added to theme.css)
const interlinearStyles = `
.interlinear-container {
  overflow-x: auto;
  padding: 1rem;
}

.interlinear-words-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  align-items: flex-start;
}

.interlinear-word {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 0.5rem;
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  cursor: pointer;
  transition: all var(--transition-fast);
  min-width: 80px;
  text-align: center;
}

.interlinear-word:hover {
  background: var(--color-primary-subtle);
  border-color: var(--color-primary);
  transform: translateY(-2px);
}

.interlinear-word.selected {
  background: var(--color-primary-subtle);
  border-color: var(--color-primary);
  box-shadow: 0 0 0 2px var(--color-primary-subtle);
}

.interlinear-word .original-text {
  font-family: var(--font-family-mono);
  font-size: 1.125rem;
  font-weight: 600;
  color: var(--color-text-primary);
  margin-bottom: 0.25rem;
  direction: inherit;
}

.interlinear-word .transliteration {
  font-size: 0.75rem;
  color: var(--color-text-tertiary);
  font-style: italic;
  margin-bottom: 0.125rem;
}

.interlinear-word .morphology {
  font-size: 0.625rem;
  color: var(--color-secondary);
  font-family: var(--font-family-mono);
  background: var(--color-secondary-subtle);
  padding: 0.125rem 0.25rem;
  border-radius: var(--radius-sm);
  margin-bottom: 0.125rem;
}

.interlinear-word .gloss {
  font-size: 0.75rem;
  color: var(--color-text-secondary);
  font-weight: 500;
  margin-bottom: 0.125rem;
}

.interlinear-word .strongs {
  font-size: 0.625rem;
  color: var(--color-primary);
  font-family: var(--font-family-mono);
  background: var(--color-primary-subtle);
  padding: 0.125rem 0.25rem;
  border-radius: var(--radius-sm);
}

/* RTL support for Hebrew */
.interlinear-container[dir="rtl"] .interlinear-words-grid {
  direction: rtl;
  justify-content: flex-start;
}

.interlinear-container[dir="rtl"] .original-text {
  direction: rtl;
}
`;