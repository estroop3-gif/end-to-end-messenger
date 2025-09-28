/**
 * Moral Code of Conduct Page
 *
 * Displays biblical principles for ethical communication
 * with Scripture references and practical guidance
 */

import React, { useState, useEffect } from 'react';
import { ScriptureText, ScriptureReference } from '../types/scripture';
import { getScriptureText, getDailyVerse } from '../services/scriptureService';

interface MoralPrinciple {
  id: string;
  title: string;
  description: string;
  scriptureReferences: ScriptureReference[];
  practicalGuidance: string[];
  category: 'communication' | 'conduct' | 'character' | 'protection';
}

const moralPrinciples: MoralPrinciple[] = [
  {
    id: 'truthfulness',
    title: 'Truthfulness',
    description: 'Speak truth in love, avoiding deception and bearing false witness',
    scriptureReferences: [
      { book: 'Ephesians', chapter: 4, verse: 15 },
      { book: 'Exodus', chapter: 20, verse: 16 },
      { book: 'Proverbs', chapter: 12, verse: 22 }
    ],
    practicalGuidance: [
      'Share information accurately and completely',
      'Avoid exaggeration or misleading statements',
      'Correct mistakes when discovered',
      'Refuse to spread unverified information'
    ],
    category: 'communication'
  },
  {
    id: 'love-and-respect',
    title: 'Love and Respect',
    description: 'Treat all persons with dignity, showing Christ\'s love in every interaction',
    scriptureReferences: [
      { book: 'John', chapter: 13, verse: 34 },
      { book: '1 Peter', chapter: 2, verse: 17 },
      { book: 'Galatians', chapter: 5, verse: 14 }
    ],
    practicalGuidance: [
      'Use respectful language in all communications',
      'Consider the feelings and dignity of others',
      'Show patience with those who disagree',
      'Pray for those who oppose or mistreat you'
    ],
    category: 'conduct'
  },
  {
    id: 'confidentiality',
    title: 'Confidentiality and Trust',
    description: 'Keep confidences and protect sensitive information entrusted to you',
    scriptureReferences: [
      { book: 'Proverbs', chapter: 11, verse: 13 },
      { book: 'Proverbs', chapter: 17, verse: 9 },
      { book: 'Matthew', chapter: 18, verse: 15 }
    ],
    practicalGuidance: [
      'Protect personal information shared in confidence',
      'Use secure communication methods appropriately',
      'Seek permission before sharing others\' messages',
      'Address conflicts privately before public discussion'
    ],
    category: 'protection'
  },
  {
    id: 'purity',
    title: 'Purity of Heart and Mind',
    description: 'Maintain moral purity in thoughts, words, and digital content',
    scriptureReferences: [
      { book: 'Philippians', chapter: 4, verse: 8 },
      { book: 'Matthew', chapter: 5, verse: 8 },
      { book: '1 Corinthians', chapter: 6, verse: 19 }
    ],
    practicalGuidance: [
      'Avoid sharing or consuming immoral content',
      'Choose edifying conversations and materials',
      'Guard your heart against corrupting influences',
      'Flee from temptation and seek accountability'
    ],
    category: 'character'
  },
  {
    id: 'wisdom-discernment',
    title: 'Wisdom and Discernment',
    description: 'Exercise godly wisdom in digital interactions and information sharing',
    scriptureReferences: [
      { book: 'Proverbs', chapter: 27, verse: 14 },
      { book: 'Ecclesiastes', chapter: 3, verse: 7 },
      { book: 'James', chapter: 1, verse: 5 }
    ],
    practicalGuidance: [
      'Think before you communicate - consider timing and appropriateness',
      'Seek God\'s wisdom in difficult conversations',
      'Avoid hasty responses when emotions are high',
      'Consider the long-term impact of your words'
    ],
    category: 'communication'
  },
  {
    id: 'protection-of-vulnerable',
    title: 'Protection of the Vulnerable',
    description: 'Defend and protect those who cannot protect themselves',
    scriptureReferences: [
      { book: 'Psalm', chapter: 82, verse: 3 },
      { book: 'Isaiah', chapter: 1, verse: 17 },
      { book: 'Proverbs', chapter: 31, verse: 8 }
    ],
    practicalGuidance: [
      'Report illegal or harmful content to appropriate authorities',
      'Stand against cyberbullying and harassment',
      'Protect children from inappropriate content',
      'Support those facing digital persecution for their faith'
    ],
    category: 'protection'
  },
  {
    id: 'stewardship',
    title: 'Digital Stewardship',
    description: 'Use technology and digital platforms as faithful stewards',
    scriptureReferences: [
      { book: '1 Corinthians', chapter: 10, verse: 31 },
      { book: '1 Peter', chapter: 4, verse: 10 },
      { book: 'Matthew', chapter: 25, verse: 21 }
    ],
    practicalGuidance: [
      'Use technology to glorify God and serve others',
      'Avoid wasting time on frivolous digital activities',
      'Support legitimate software and respect intellectual property',
      'Share your digital skills to help others'
    ],
    category: 'character'
  },
  {
    id: 'reconciliation',
    title: 'Reconciliation and Forgiveness',
    description: 'Seek peace and reconciliation, forgiving as Christ forgave',
    scriptureReferences: [
      { book: 'Matthew', chapter: 5, verse: 24 },
      { book: 'Ephesians', chapter: 4, verse: 32 },
      { book: '2 Corinthians', chapter: 5, verse: 20 }
    ],
    practicalGuidance: [
      'Seek to resolve conflicts through direct communication',
      'Forgive those who have wronged you digitally',
      'Make amends when you have caused harm',
      'Be an agent of peace in online communities'
    ],
    category: 'conduct'
  }
];

export const MoralCode: React.FC = () => {
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [expandedPrinciple, setExpandedPrinciple] = useState<string | null>(null);
  const [scriptureTexts, setScriptureTexts] = useState<Map<string, ScriptureText>>(new Map());
  const [isLoadingScripture, setIsLoadingScripture] = useState<Set<string>>(new Set());
  const [dailyVerse, setDailyVerse] = useState<any>(null);

  useEffect(() => {
    loadDailyVerse();
  }, []);

  const loadDailyVerse = async () => {
    try {
      const verse = await getDailyVerse();
      setDailyVerse(verse);
    } catch (error) {
      console.error('Failed to load daily verse:', error);
    }
  };

  const loadScriptureText = async (reference: ScriptureReference) => {
    const key = `${reference.book}_${reference.chapter}_${reference.verse}`;

    if (scriptureTexts.has(key) || isLoadingScripture.has(key)) {
      return;
    }

    setIsLoadingScripture(prev => new Set([...prev, key]));

    try {
      const scriptureText = await getScriptureText({
        reference,
        translation: 'kjv',
        includeOriginal: false,
        includeMorphology: false
      });

      setScriptureTexts(prev => new Map([...prev, [key, scriptureText]]));
    } catch (error) {
      console.error('Failed to load scripture:', error);
    } finally {
      setIsLoadingScripture(prev => {
        const newSet = new Set(prev);
        newSet.delete(key);
        return newSet;
      });
    }
  };

  const getScriptureKey = (reference: ScriptureReference): string => {
    return `${reference.book}_${reference.chapter}_${reference.verse}`;
  };

  const formatReference = (reference: ScriptureReference): string => {
    return `${reference.book} ${reference.chapter}:${reference.verse}`;
  };

  const categories = [
    { value: 'all', label: 'All Principles', icon: '📜' },
    { value: 'communication', label: 'Communication', icon: '💬' },
    { value: 'conduct', label: 'Conduct', icon: '🤝' },
    { value: 'character', label: 'Character', icon: '❤️' },
    { value: 'protection', label: 'Protection', icon: '🛡️' }
  ];

  const filteredPrinciples = selectedCategory === 'all'
    ? moralPrinciples
    : moralPrinciples.filter(p => p.category === selectedCategory);

  const handlePrincipleClick = (principleId: string) => {
    if (expandedPrinciple === principleId) {
      setExpandedPrinciple(null);
    } else {
      setExpandedPrinciple(principleId);
      // Load scripture texts for this principle
      const principle = moralPrinciples.find(p => p.id === principleId);
      if (principle) {
        principle.scriptureReferences.forEach(loadScriptureText);
      }
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-lg">
      {/* Header */}
      <div className="text-center space-y-md">
        <h1 className="text-3xl font-bold text-primary">📖 Moral Code of Conduct</h1>
        <p className="text-lg text-secondary max-w-2xl mx-auto">
          Biblical principles for ethical digital communication and conduct,
          guided by Scripture and the example of Christ
        </p>
      </div>

      {/* Daily Verse */}
      {dailyVerse && (
        <div className="card">
          <div className="card-content">
            <div className="text-center space-y-sm">
              <div className="text-sm font-medium text-primary">Daily Verse</div>
              <blockquote className="text-lg italic text-secondary">
                "{dailyVerse.text}"
              </blockquote>
              <div className="text-sm text-tertiary">
                — {dailyVerse.reference} ({dailyVerse.translation})
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Category Filter */}
      <div className="card">
        <div className="card-content">
          <div className="flex flex-wrap gap-sm">
            {categories.map(category => (
              <button
                key={category.value}
                className={`category-filter ${selectedCategory === category.value ? 'active' : ''}`}
                onClick={() => setSelectedCategory(category.value)}
              >
                <span className="mr-sm">{category.icon}</span>
                {category.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Moral Principles */}
      <div className="space-y-md">
        {filteredPrinciples.map(principle => (
          <div key={principle.id} className="card">
            <div
              className="card-header cursor-pointer"
              onClick={() => handlePrincipleClick(principle.id)}
            >
              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <h3 className="text-lg font-semibold flex items-center gap-sm">
                    <span className="category-icon">
                      {principle.category === 'communication' && '💬'}
                      {principle.category === 'conduct' && '🤝'}
                      {principle.category === 'character' && '❤️'}
                      {principle.category === 'protection' && '🛡️'}
                    </span>
                    {principle.title}
                  </h3>
                  <p className="text-sm text-tertiary">{principle.description}</p>
                </div>
                <div className="chevron-icon">
                  {expandedPrinciple === principle.id ? '▼' : '▶'}
                </div>
              </div>
            </div>

            {expandedPrinciple === principle.id && (
              <div className="card-content">
                {/* Scripture References */}
                <div className="space-y-md mb-lg">
                  <h4 className="font-medium text-primary">📖 Scripture Foundation</h4>
                  <div className="space-y-sm">
                    {principle.scriptureReferences.map((reference, index) => {
                      const key = getScriptureKey(reference);
                      const scriptureText = scriptureTexts.get(key);
                      const isLoading = isLoadingScripture.has(key);

                      return (
                        <div key={index} className="scripture-reference">
                          <div className="flex items-center gap-sm mb-sm">
                            <span className="scripture-ref-label">
                              {formatReference(reference)}
                            </span>
                            {isLoading && <div className="spinner-sm"></div>}
                          </div>
                          {scriptureText && (
                            <blockquote className="scripture-text">
                              "{scriptureText.text}"
                            </blockquote>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Practical Guidance */}
                <div className="space-y-md">
                  <h4 className="font-medium text-primary">🎯 Practical Application</h4>
                  <ul className="practical-guidance">
                    {principle.practicalGuidance.map((guidance, index) => (
                      <li key={index} className="guidance-item">
                        <span className="guidance-bullet">•</span>
                        {guidance}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Commitment Section */}
      <div className="card">
        <div className="card-header">
          <h3 className="text-lg font-semibold">✋ Personal Commitment</h3>
        </div>
        <div className="card-content">
          <div className="space-y-md">
            <p className="text-secondary">
              By using this secure communication platform, I commit to:
            </p>
            <ul className="commitment-list">
              <li>Honor God in all my digital communications</li>
              <li>Treat others with the love and respect Christ commands</li>
              <li>Use truthfulness and integrity in all interactions</li>
              <li>Protect the vulnerable and speak for those who cannot speak</li>
              <li>Maintain purity in content and conversations</li>
              <li>Seek reconciliation and forgiveness when conflicts arise</li>
              <li>Be a faithful steward of the technology entrusted to me</li>
            </ul>
            <div className="bg-surface-elevated p-md rounded-lg border border-border">
              <p className="text-sm text-tertiary text-center italic">
                "Let your light shine before others, that they may see your good deeds and glorify your Father in heaven."
                <br />— Matthew 5:16
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Resources Section */}
      <div className="card">
        <div className="card-header">
          <h3 className="text-lg font-semibold">📚 Additional Resources</h3>
        </div>
        <div className="card-content">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-md">
            <div className="resource-item">
              <h4 className="font-medium">🙏 Prayer for Wisdom</h4>
              <p className="text-sm text-tertiary">
                When facing difficult digital decisions, pray for godly wisdom and discernment.
              </p>
            </div>
            <div className="resource-item">
              <h4 className="font-medium">👥 Accountability</h4>
              <p className="text-sm text-tertiary">
                Seek accountability from mature believers for your digital conduct and habits.
              </p>
            </div>
            <div className="resource-item">
              <h4 className="font-medium">📖 Scripture Study</h4>
              <p className="text-sm text-tertiary">
                Regular study of God's Word provides foundation for ethical decision-making.
              </p>
            </div>
            <div className="resource-item">
              <h4 className="font-medium">✝️ Christ's Example</h4>
              <p className="text-sm text-tertiary">
                Look to Jesus as the perfect example of love, truth, and righteousness.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// Additional CSS styles
const moralCodeStyles = `
.category-filter {
  padding: 0.5rem 1rem;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-full);
  background: var(--color-background);
  color: var(--color-secondary);
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all var(--transition-fast);
  display: flex;
  align-items: center;
}

.category-filter:hover {
  background: var(--color-surface-elevated);
  border-color: var(--color-primary);
}

.category-filter.active {
  background: var(--color-primary);
  color: var(--color-on-primary);
  border-color: var(--color-primary);
}

.category-icon {
  font-size: 1.25rem;
  margin-right: 0.5rem;
}

.chevron-icon {
  color: var(--color-tertiary);
  font-size: 0.875rem;
  transition: transform var(--transition-fast);
}

.scripture-reference {
  background: var(--color-surface-elevated);
  padding: 1rem;
  border-radius: var(--radius-md);
  border: 1px solid var(--color-border);
}

.scripture-ref-label {
  font-size: 0.875rem;
  font-weight: 600;
  color: var(--color-primary);
}

.scripture-text {
  font-style: italic;
  color: var(--color-secondary);
  margin: 0;
  padding-left: 1rem;
  border-left: 3px solid var(--color-primary);
}

.practical-guidance {
  list-style: none;
  margin: 0;
  padding: 0;
  space-y: 0.5rem;
}

.guidance-item {
  display: flex;
  align-items: flex-start;
  gap: 0.75rem;
  padding: 0.5rem 0;
  color: var(--color-secondary);
}

.guidance-bullet {
  color: var(--color-primary);
  font-weight: bold;
  flex-shrink: 0;
  margin-top: 0.125rem;
}

.commitment-list {
  list-style: none;
  margin: 0;
  padding: 0;
  space-y: 0.5rem;
}

.commitment-list li {
  display: flex;
  align-items: flex-start;
  gap: 0.75rem;
  padding: 0.25rem 0;
  color: var(--color-secondary);
}

.commitment-list li::before {
  content: "✓";
  color: var(--color-success);
  font-weight: bold;
  flex-shrink: 0;
}

.resource-item {
  padding: 1rem;
  background: var(--color-surface-elevated);
  border-radius: var(--radius-md);
  border: 1px solid var(--color-border);
}

.spinner-sm {
  width: 1rem;
  height: 1rem;
  border: 2px solid var(--color-border);
  border-top: 2px solid var(--color-primary);
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}
`;