/**
 * Verse Lookup Component
 *
 * Provides book/chapter/verse selection interface for Scripture navigation
 */

import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/tauri';

interface ScriptureReference {
  book: string;
  chapter: number;
  verse?: number;
  endVerse?: number;
}

interface Book {
  name: string;
  abbreviation: string;
  testament: 'old' | 'new';
  chapters: number;
  verses: number[];
}

interface VerseLookupProps {
  currentReference: ScriptureReference;
  onReferenceChange: (reference: ScriptureReference) => void;
}

export const VerseLookup: React.FC<VerseLookupProps> = ({
  currentReference,
  onReferenceChange
}) => {
  const [books, setBooks] = useState<Book[]>([]);
  const [selectedBook, setSelectedBook] = useState<Book | null>(null);
  const [chapter, setChapter] = useState<number>(1);
  const [startVerse, setStartVerse] = useState<number | null>(null);
  const [endVerse, setEndVerse] = useState<number | null>(null);
  const [showVerseRange, setShowVerseRange] = useState(false);

  // Quick navigation
  const [quickReference, setQuickReference] = useState('');

  useEffect(() => {
    loadBibleBooks();
  }, []);

  useEffect(() => {
    if (currentReference && books.length > 0) {
      const book = books.find(b => b.name === currentReference.book);
      if (book) {
        setSelectedBook(book);
        setChapter(currentReference.chapter);
        setStartVerse(currentReference.verse || null);
        setEndVerse(currentReference.endVerse || null);
      }
    }
  }, [currentReference, books]);

  const loadBibleBooks = async () => {
    try {
      const bookList = await invoke<Book[]>('get_bible_books');
      setBooks(bookList);

      // Set initial book if none selected
      if (currentReference.book && bookList.length > 0) {
        const book = bookList.find(b => b.name === currentReference.book);
        if (book) {
          setSelectedBook(book);
        }
      }
    } catch (error) {
      console.error('Failed to load Bible books:', error);
      // Fallback to hardcoded list
      setBooks(getDefaultBooks());
    }
  };

  const handleBookChange = (bookName: string) => {
    const book = books.find(b => b.name === bookName);
    if (book) {
      setSelectedBook(book);
      setChapter(1);
      setStartVerse(null);
      setEndVerse(null);

      const newReference: ScriptureReference = {
        book: book.name,
        chapter: 1
      };
      onReferenceChange(newReference);
    }
  };

  const handleChapterChange = (newChapter: number) => {
    if (!selectedBook) return;

    const chapterNum = Math.max(1, Math.min(newChapter, selectedBook.chapters));
    setChapter(chapterNum);
    setStartVerse(null);
    setEndVerse(null);

    const newReference: ScriptureReference = {
      book: selectedBook.name,
      chapter: chapterNum
    };
    onReferenceChange(newReference);
  };

  const handleVerseChange = () => {
    if (!selectedBook) return;

    const maxVerses = selectedBook.verses[chapter - 1] || 1;
    const validStartVerse = startVerse ? Math.max(1, Math.min(startVerse, maxVerses)) : undefined;
    const validEndVerse = endVerse ? Math.max(validStartVerse || 1, Math.min(endVerse, maxVerses)) : undefined;

    const newReference: ScriptureReference = {
      book: selectedBook.name,
      chapter: chapter,
      verse: validStartVerse,
      endVerse: validEndVerse !== validStartVerse ? validEndVerse : undefined
    };
    onReferenceChange(newReference);
  };

  const handleQuickReference = () => {
    if (!quickReference.trim()) return;

    try {
      // Parse formats like "John 3:16", "Gen 1:1-3", "Psalm 23"
      const reference = parseReferenceString(quickReference);
      if (reference) {
        onReferenceChange(reference);
        setQuickReference('');
      }
    } catch (error) {
      console.error('Failed to parse reference:', error);
      alert('Invalid reference format. Try formats like "John 3:16" or "Genesis 1:1-3"');
    }
  };

  const parseReferenceString = (refString: string): ScriptureReference | null => {
    // Simple parsing - in real implementation would be more robust
    const regex = /^(\d?\s*[A-Za-z]+)\s+(\d+)(?::(\d+)(?:-(\d+))?)?$/;
    const match = refString.match(regex);

    if (!match) return null;

    const [, bookPart, chapterPart, versePart, endVersePart] = match;

    // Find book by name or abbreviation
    const book = books.find(b =>
      b.name.toLowerCase().includes(bookPart.toLowerCase()) ||
      b.abbreviation.toLowerCase() === bookPart.toLowerCase()
    );

    if (!book) return null;

    return {
      book: book.name,
      chapter: parseInt(chapterPart),
      verse: versePart ? parseInt(versePart) : undefined,
      endVerse: endVersePart ? parseInt(endVersePart) : undefined
    };
  };

  const getDefaultBooks = (): Book[] => {
    // Simplified book list - in real implementation would be comprehensive
    return [
      { name: 'Genesis', abbreviation: 'Gen', testament: 'old', chapters: 50, verses: Array(50).fill(31) },
      { name: 'Exodus', abbreviation: 'Exod', testament: 'old', chapters: 40, verses: Array(40).fill(30) },
      { name: 'Psalms', abbreviation: 'Ps', testament: 'old', chapters: 150, verses: Array(150).fill(20) },
      { name: 'Proverbs', abbreviation: 'Prov', testament: 'old', chapters: 31, verses: Array(31).fill(25) },
      { name: 'Matthew', abbreviation: 'Matt', testament: 'new', chapters: 28, verses: Array(28).fill(25) },
      { name: 'John', abbreviation: 'John', testament: 'new', chapters: 21, verses: Array(21).fill(30) },
      { name: 'Romans', abbreviation: 'Rom', testament: 'new', chapters: 16, verses: Array(16).fill(25) },
      { name: 'Revelation', abbreviation: 'Rev', testament: 'new', chapters: 22, verses: Array(22).fill(20) }
    ];
  };

  const oldTestamentBooks = books.filter(b => b.testament === 'old');
  const newTestamentBooks = books.filter(b => b.testament === 'new');
  const maxVerses = selectedBook?.verses[chapter - 1] || 0;

  return (
    <div className="card">
      <div className="card-header">
        <h3 className="text-lg font-semibold">Scripture Reference</h3>
      </div>

      <div className="card-content space-y-md">
        {/* Quick Reference Input */}
        <div className="form-group">
          <label className="form-label">Quick Reference</label>
          <div className="flex gap-sm">
            <input
              type="text"
              className="form-input flex-1"
              placeholder="e.g., John 3:16"
              value={quickReference}
              onChange={(e) => setQuickReference(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleQuickReference()}
            />
            <button
              className="btn btn-primary"
              onClick={handleQuickReference}
              disabled={!quickReference.trim()}
            >
              Go
            </button>
          </div>
        </div>

        {/* Book Selection */}
        <div className="form-group">
          <label className="form-label">Book</label>
          <select
            className="form-input form-select"
            value={selectedBook?.name || ''}
            onChange={(e) => handleBookChange(e.target.value)}
          >
            <option value="">Select a book...</option>
            <optgroup label="Old Testament">
              {oldTestamentBooks.map(book => (
                <option key={book.name} value={book.name}>
                  {book.name}
                </option>
              ))}
            </optgroup>
            <optgroup label="New Testament">
              {newTestamentBooks.map(book => (
                <option key={book.name} value={book.name}>
                  {book.name}
                </option>
              ))}
            </optgroup>
          </select>
        </div>

        {/* Chapter Selection */}
        {selectedBook && (
          <div className="form-group">
            <label className="form-label">
              Chapter (1-{selectedBook.chapters})
            </label>
            <div className="flex gap-sm">
              <input
                type="number"
                className="form-input flex-1"
                min="1"
                max={selectedBook.chapters}
                value={chapter}
                onChange={(e) => handleChapterChange(parseInt(e.target.value) || 1)}
              />
              <div className="flex gap-xs">
                <button
                  className="btn btn-ghost btn-sm"
                  onClick={() => handleChapterChange(chapter - 1)}
                  disabled={chapter <= 1}
                >
                  ←
                </button>
                <button
                  className="btn btn-ghost btn-sm"
                  onClick={() => handleChapterChange(chapter + 1)}
                  disabled={chapter >= selectedBook.chapters}
                >
                  →
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Verse Selection */}
        {selectedBook && maxVerses > 0 && (
          <div className="form-group">
            <div className="flex items-center gap-md mb-sm">
              <label className="form-label mb-0">Verses</label>
              <label className="flex items-center gap-sm text-sm">
                <input
                  type="checkbox"
                  className="form-checkbox"
                  checked={showVerseRange}
                  onChange={(e) => setShowVerseRange(e.target.checked)}
                />
                Range
              </label>
            </div>

            <div className="flex gap-sm">
              <input
                type="number"
                className="form-input flex-1"
                min="1"
                max={maxVerses}
                placeholder="Start verse"
                value={startVerse || ''}
                onChange={(e) => setStartVerse(parseInt(e.target.value) || null)}
                onBlur={handleVerseChange}
              />

              {showVerseRange && (
                <>
                  <span className="flex items-center text-tertiary">to</span>
                  <input
                    type="number"
                    className="form-input flex-1"
                    min={startVerse || 1}
                    max={maxVerses}
                    placeholder="End verse"
                    value={endVerse || ''}
                    onChange={(e) => setEndVerse(parseInt(e.target.value) || null)}
                    onBlur={handleVerseChange}
                  />
                </>
              )}
            </div>

            <p className="text-xs text-tertiary mt-sm">
              Max verses in this chapter: {maxVerses}
            </p>
          </div>
        )}

        {/* Current Reference Display */}
        <div className="bg-surface-elevated p-md rounded-lg border border-border">
          <div className="text-sm font-medium text-primary">Current Reference:</div>
          <div className="text-lg font-semibold">
            {currentReference.book} {currentReference.chapter}
            {currentReference.verse && `:${currentReference.verse}`}
            {currentReference.endVerse && `-${currentReference.endVerse}`}
          </div>
        </div>

        {/* Common References */}
        <div className="form-group">
          <label className="form-label">Popular Passages</label>
          <div className="grid grid-cols-2 gap-xs text-sm">
            {[
              { ref: 'John 3:16', label: 'John 3:16' },
              { ref: 'Psalm 23', label: 'Psalm 23' },
              { ref: 'Romans 8:28', label: 'Rom 8:28' },
              { ref: 'Genesis 1:1', label: 'Gen 1:1' },
              { ref: 'Matthew 5:3-12', label: 'Beatitudes' },
              { ref: '1 Corinthians 13', label: 'Love Ch.' }
            ].map(passage => (
              <button
                key={passage.ref}
                className="btn btn-ghost btn-sm text-xs"
                onClick={() => {
                  setQuickReference(passage.ref);
                  handleQuickReference();
                }}
              >
                {passage.label}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};