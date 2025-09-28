/**
 * Prayer Manager Component
 *
 * Comprehensive prayer management with categories, sessions, and analytics
 * Provides encrypted local storage and spiritual tracking features
 */

import React, { useState, useEffect } from 'react';
import { prayerService, Prayer, PrayerCategory, PrayerSession, DailyVerse } from '../../services/prayerService';

interface PrayerManagerProps {
  isVisible: boolean;
  onClose: () => void;
}

export const PrayerManager: React.FC<PrayerManagerProps> = ({ isVisible, onClose }) => {
  const [prayers, setPrayers] = useState<Prayer[]>([]);
  const [categories] = useState<PrayerCategory[]>(prayerService.getDefaultCategories());
  const [activeSession, setActiveSession] = useState<PrayerSession | null>(null);
  const [dailyVerse, setDailyVerse] = useState<DailyVerse | null>(null);
  const [prayerStats, setPrayerStats] = useState<any>(null);

  // UI State
  const [activeTab, setActiveTab] = useState<'prayers' | 'session' | 'stats'>('prayers');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [isCreatingPrayer, setIsCreatingPrayer] = useState(false);
  const [editingPrayer, setEditingPrayer] = useState<Prayer | null>(null);

  // Form State
  const [newPrayerTitle, setNewPrayerTitle] = useState('');
  const [newPrayerContent, setNewPrayerContent] = useState('');
  const [newPrayerCategory, setNewPrayerCategory] = useState<string>(categories[0]?.id || '');
  const [newPrayerTags, setNewPrayerTags] = useState<string>('');
  const [isPrivate, setIsPrivate] = useState(true);

  useEffect(() => {
    if (isVisible) {
      loadData();
    }
  }, [isVisible]);

  const loadData = async () => {
    try {
      const [prayersData, dailyVerseData, statsData] = await Promise.all([
        prayerService.getAllPrayers(),
        prayerService.getDailyVerse(),
        prayerService.getPrayerStats()
      ]);

      setPrayers(prayersData);
      setDailyVerse(dailyVerseData);
      setPrayerStats(statsData);
    } catch (error) {
      console.error('Failed to load prayer data:', error);
    }
  };

  const handleCreatePrayer = async () => {
    if (!newPrayerTitle.trim() || !newPrayerContent.trim()) {
      return;
    }

    try {
      const category = categories.find(c => c.id === newPrayerCategory);
      if (!category) return;

      const newPrayer = await prayerService.createPrayer({
        title: newPrayerTitle.trim(),
        content: newPrayerContent.trim(),
        category,
        tags: newPrayerTags.split(',').map(tag => tag.trim()).filter(Boolean),
        isAnswered: false,
        isPrivate,
        scriptureReferences: []
      });

      setPrayers(prev => [newPrayer, ...prev]);

      // Reset form
      setNewPrayerTitle('');
      setNewPrayerContent('');
      setNewPrayerTags('');
      setIsCreatingPrayer(false);

      // Add to active session if one exists
      if (activeSession) {
        await prayerService.addPrayerToSession(activeSession.id, newPrayer.id);
      }
    } catch (error) {
      console.error('Failed to create prayer:', error);
    }
  };

  const handleMarkAnswered = async (prayerId: string, answerDescription: string) => {
    try {
      const updatedPrayer = await prayerService.updatePrayer(prayerId, {
        isAnswered: true,
        answeredAt: new Date(),
        answerDescription
      });

      if (updatedPrayer) {
        setPrayers(prev => prev.map(p => p.id === prayerId ? updatedPrayer : p));
      }
    } catch (error) {
      console.error('Failed to mark prayer as answered:', error);
    }
  };

  const handleDeletePrayer = async (prayerId: string) => {
    if (!confirm('Are you sure you want to delete this prayer?')) {
      return;
    }

    try {
      const success = await prayerService.deletePrayer(prayerId);
      if (success) {
        setPrayers(prev => prev.filter(p => p.id !== prayerId));
      }
    } catch (error) {
      console.error('Failed to delete prayer:', error);
    }
  };

  const handleStartSession = async () => {
    try {
      const session = await prayerService.startPrayerSession();
      setActiveSession(session);
    } catch (error) {
      console.error('Failed to start prayer session:', error);
    }
  };

  const handleEndSession = async (notes?: string) => {
    if (!activeSession) return;

    try {
      await prayerService.endPrayerSession(activeSession.id, notes);
      setActiveSession(null);
      await loadData(); // Refresh stats
    } catch (error) {
      console.error('Failed to end prayer session:', error);
    }
  };

  const filteredPrayers = prayers.filter(prayer => {
    const matchesCategory = selectedCategory === 'all' || prayer.category.id === selectedCategory;
    const matchesSearch = !searchQuery ||
      prayer.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      prayer.content.toLowerCase().includes(searchQuery.toLowerCase()) ||
      prayer.tags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase()));

    return matchesCategory && matchesSearch;
  });

  const formatDuration = (seconds: number): string => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);

    if (hours > 0) {
      return `${hours}h ${minutes}m`;
    }
    return `${minutes}m`;
  };

  if (!isVisible) return null;

  return (
    <div className="fixed inset-0 bg-overlay flex items-center justify-center z-50">
      <div className="prayer-manager">
        <div className="prayer-header">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xl font-bold text-primary">🙏 Prayer Center</h2>
              <p className="text-sm text-tertiary">Spiritual communication and reflection</p>
            </div>
            <button
              className="btn btn-ghost btn-sm"
              onClick={onClose}
            >
              ✕
            </button>
          </div>

          {/* Daily Verse */}
          {dailyVerse && (
            <div className="daily-verse">
              <div className="text-sm font-medium text-primary mb-sm">Daily Verse</div>
              <blockquote className="text-sm italic text-secondary">
                "{dailyVerse.text}"
              </blockquote>
              <div className="text-xs text-tertiary mt-sm">
                — {dailyVerse.reference} ({dailyVerse.translation})
              </div>
            </div>
          )}

          {/* Tab Navigation */}
          <div className="tab-navigation">
            <button
              className={`tab-button ${activeTab === 'prayers' ? 'active' : ''}`}
              onClick={() => setActiveTab('prayers')}
            >
              📖 Prayers
            </button>
            <button
              className={`tab-button ${activeTab === 'session' ? 'active' : ''}`}
              onClick={() => setActiveTab('session')}
            >
              🕐 Session
            </button>
            <button
              className={`tab-button ${activeTab === 'stats' ? 'active' : ''}`}
              onClick={() => setActiveTab('stats')}
            >
              📊 Analytics
            </button>
          </div>
        </div>

        <div className="prayer-content">
          {/* Prayers Tab */}
          {activeTab === 'prayers' && (
            <div className="prayers-tab">
              <div className="prayers-controls">
                {/* Search and Filter */}
                <div className="flex gap-md mb-md">
                  <input
                    type="text"
                    className="form-input flex-1"
                    placeholder="Search prayers..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                  />
                  <select
                    className="form-select"
                    value={selectedCategory}
                    onChange={(e) => setSelectedCategory(e.target.value)}
                  >
                    <option value="all">All Categories</option>
                    {categories.map(category => (
                      <option key={category.id} value={category.id}>
                        {category.icon} {category.name}
                      </option>
                    ))}
                  </select>
                  <button
                    className="btn btn-primary"
                    onClick={() => setIsCreatingPrayer(true)}
                  >
                    ➕ New Prayer
                  </button>
                </div>

                {/* Prayer Creation Form */}
                {isCreatingPrayer && (
                  <div className="prayer-form">
                    <div className="form-group">
                      <label className="form-label">Prayer Title</label>
                      <input
                        type="text"
                        className="form-input"
                        value={newPrayerTitle}
                        onChange={(e) => setNewPrayerTitle(e.target.value)}
                        placeholder="Brief title for this prayer..."
                      />
                    </div>

                    <div className="form-group">
                      <label className="form-label">Prayer Content</label>
                      <textarea
                        className="form-textarea"
                        rows={4}
                        value={newPrayerContent}
                        onChange={(e) => setNewPrayerContent(e.target.value)}
                        placeholder="Share your heart with God..."
                      />
                    </div>

                    <div className="flex gap-md">
                      <div className="form-group flex-1">
                        <label className="form-label">Category</label>
                        <select
                          className="form-select"
                          value={newPrayerCategory}
                          onChange={(e) => setNewPrayerCategory(e.target.value)}
                        >
                          {categories.map(category => (
                            <option key={category.id} value={category.id}>
                              {category.icon} {category.name}
                            </option>
                          ))}
                        </select>
                      </div>

                      <div className="form-group flex-1">
                        <label className="form-label">Tags (comma-separated)</label>
                        <input
                          type="text"
                          className="form-input"
                          value={newPrayerTags}
                          onChange={(e) => setNewPrayerTags(e.target.value)}
                          placeholder="healing, family, guidance"
                        />
                      </div>
                    </div>

                    <div className="form-group">
                      <label className="flex items-center gap-sm">
                        <input
                          type="checkbox"
                          className="form-checkbox"
                          checked={isPrivate}
                          onChange={(e) => setIsPrivate(e.target.checked)}
                        />
                        Keep this prayer private
                      </label>
                    </div>

                    <div className="flex gap-sm justify-end">
                      <button
                        className="btn btn-ghost"
                        onClick={() => {
                          setIsCreatingPrayer(false);
                          setNewPrayerTitle('');
                          setNewPrayerContent('');
                          setNewPrayerTags('');
                        }}
                      >
                        Cancel
                      </button>
                      <button
                        className="btn btn-primary"
                        onClick={handleCreatePrayer}
                        disabled={!newPrayerTitle.trim() || !newPrayerContent.trim()}
                      >
                        Create Prayer
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {/* Prayer List */}
              <div className="prayers-list">
                {filteredPrayers.length === 0 ? (
                  <div className="empty-state">
                    <div className="text-4xl mb-md">🙏</div>
                    <div className="font-medium text-secondary">No prayers found</div>
                    <div className="text-sm text-tertiary">
                      {searchQuery || selectedCategory !== 'all'
                        ? 'Try adjusting your search or filter'
                        : 'Create your first prayer to get started'
                      }
                    </div>
                  </div>
                ) : (
                  filteredPrayers.map(prayer => (
                    <div key={prayer.id} className="prayer-item">
                      <div className="prayer-header">
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <div className="flex items-center gap-sm mb-xs">
                              <span style={{ color: prayer.category.color }}>
                                {prayer.category.icon}
                              </span>
                              <h4 className="font-medium">{prayer.title}</h4>
                              {prayer.isAnswered && (
                                <span className="prayer-status answered">✓ Answered</span>
                              )}
                              {prayer.isPrivate && (
                                <span className="prayer-status private">🔒 Private</span>
                              )}
                            </div>
                            <div className="text-sm text-tertiary">
                              {prayer.category.name} • {prayer.createdAt.toLocaleDateString()}
                            </div>
                          </div>
                        </div>
                      </div>

                      <div className="prayer-content">
                        <p className="text-sm text-secondary mb-sm">{prayer.content}</p>

                        {prayer.tags.length > 0 && (
                          <div className="prayer-tags">
                            {prayer.tags.map(tag => (
                              <span key={tag} className="prayer-tag">#{tag}</span>
                            ))}
                          </div>
                        )}

                        {prayer.isAnswered && prayer.answerDescription && (
                          <div className="answer-section">
                            <div className="text-xs font-medium text-success mb-xs">Answer:</div>
                            <p className="text-sm text-secondary">{prayer.answerDescription}</p>
                            <div className="text-xs text-tertiary">
                              Answered on {prayer.answeredAt?.toLocaleDateString()}
                            </div>
                          </div>
                        )}
                      </div>

                      <div className="prayer-actions">
                        {!prayer.isAnswered && (
                          <button
                            className="btn btn-success btn-sm"
                            onClick={() => {
                              const answer = prompt('How was this prayer answered?');
                              if (answer) {
                                handleMarkAnswered(prayer.id, answer);
                              }
                            }}
                          >
                            Mark Answered
                          </button>
                        )}
                        <button
                          className="btn btn-ghost btn-sm"
                          onClick={() => setEditingPrayer(prayer)}
                        >
                          Edit
                        </button>
                        <button
                          className="btn btn-danger btn-sm"
                          onClick={() => handleDeletePrayer(prayer.id)}
                        >
                          Delete
                        </button>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}

          {/* Session Tab */}
          {activeTab === 'session' && (
            <div className="session-tab">
              {activeSession ? (
                <div className="active-session">
                  <div className="session-info">
                    <h3 className="text-lg font-semibold text-primary">
                      🕐 Prayer Session Active
                    </h3>
                    <p className="text-sm text-tertiary">
                      Started at {activeSession.startTime.toLocaleTimeString()}
                    </p>
                  </div>

                  <div className="session-prayers">
                    <h4 className="font-medium mb-sm">Prayers in this session:</h4>
                    {activeSession.prayers.length === 0 ? (
                      <div className="text-sm text-tertiary">
                        No prayers added yet. Create a new prayer to add it to this session.
                      </div>
                    ) : (
                      <div className="space-y-sm">
                        {activeSession.prayers.map(prayerId => {
                          const prayer = prayers.find(p => p.id === prayerId);
                          return prayer ? (
                            <div key={prayerId} className="session-prayer-item">
                              <span className="mr-sm">{prayer.category.icon}</span>
                              {prayer.title}
                            </div>
                          ) : null;
                        })}
                      </div>
                    )}
                  </div>

                  <button
                    className="btn btn-primary mt-md"
                    onClick={() => {
                      const notes = prompt('Any notes for this prayer session?');
                      handleEndSession(notes || undefined);
                    }}
                  >
                    End Session
                  </button>
                </div>
              ) : (
                <div className="no-session">
                  <div className="text-center space-y-md">
                    <div className="text-4xl">🕐</div>
                    <h3 className="text-lg font-semibold">Start a Prayer Session</h3>
                    <p className="text-sm text-tertiary max-w-md mx-auto">
                      Prayer sessions help you track your prayer time and organize your prayers.
                      All prayers created during a session will be grouped together.
                    </p>
                    <button
                      className="btn btn-primary"
                      onClick={handleStartSession}
                    >
                      Begin Prayer Session
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Stats Tab */}
          {activeTab === 'stats' && prayerStats && (
            <div className="stats-tab">
              <div className="stats-grid">
                <div className="stat-card">
                  <div className="stat-value">{prayerStats.totalPrayers}</div>
                  <div className="stat-label">Total Prayers</div>
                </div>
                <div className="stat-card">
                  <div className="stat-value">{prayerStats.answeredPrayers}</div>
                  <div className="stat-label">Answered</div>
                </div>
                <div className="stat-card">
                  <div className="stat-value">{prayerStats.activePrayers}</div>
                  <div className="stat-label">Active</div>
                </div>
                <div className="stat-card">
                  <div className="stat-value">{prayerStats.prayerStreak}</div>
                  <div className="stat-label">Day Streak</div>
                </div>
                <div className="stat-card">
                  <div className="stat-value">{prayerStats.totalPrayerSessions}</div>
                  <div className="stat-label">Sessions</div>
                </div>
                <div className="stat-card">
                  <div className="stat-value">
                    {formatDuration(prayerStats.averageSessionDuration)}
                  </div>
                  <div className="stat-label">Avg Session</div>
                </div>
              </div>

              {/* Category Breakdown */}
              <div className="category-stats">
                <h4 className="font-medium mb-md">Prayers by Category</h4>
                <div className="space-y-sm">
                  {Object.entries(prayerStats.prayersByCategory).map(([categoryName, count]) => {
                    const category = categories.find(c => c.name === categoryName);
                    return (
                      <div key={categoryName} className="category-stat">
                        <div className="flex items-center gap-sm">
                          <span>{category?.icon || '📖'}</span>
                          <span className="flex-1">{categoryName}</span>
                          <span className="font-medium">{count}</span>
                        </div>
                        <div
                          className="category-bar"
                          style={{
                            width: `${(Number(count) / prayerStats.totalPrayers) * 100}%`,
                            backgroundColor: category?.color || '#4ECDC4'
                          }}
                        />
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};