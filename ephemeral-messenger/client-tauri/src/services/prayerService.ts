/**
 * Prayer Service
 *
 * Handles prayer management with encrypted local storage
 * Provides daily verses, prayer tracking, and spiritual guidance
 */

import CryptoJS from 'crypto-js';

export interface Prayer {
  id: string;
  title: string;
  content: string;
  category: PrayerCategory;
  tags: string[];
  createdAt: Date;
  updatedAt: Date;
  isAnswered: boolean;
  answeredAt?: Date;
  answerDescription?: string;
  isPrivate: boolean;
  scriptureReferences: ScriptureReference[];
}

export interface PrayerCategory {
  id: string;
  name: string;
  description: string;
  color: string;
  icon: string;
}

export interface ScriptureReference {
  book: string;
  chapter: number;
  verse?: number;
  endVerse?: number;
}

export interface PrayerSession {
  id: string;
  startTime: Date;
  endTime?: Date;
  duration?: number; // seconds
  prayers: string[]; // prayer IDs
  scriptureReading?: ScriptureReference[];
  notes?: string;
  mood?: 'peaceful' | 'joyful' | 'troubled' | 'grateful' | 'seeking';
}

export interface DailyVerse {
  text: string;
  reference: string;
  translation: string;
  theme?: string;
}

class PrayerService {
  private readonly STORAGE_KEY = 'ephemeral_prayers_encrypted';
  private readonly SESSIONS_KEY = 'ephemeral_prayer_sessions_encrypted';
  private readonly SETTINGS_KEY = 'ephemeral_prayer_settings_encrypted';
  private encryptionKey: string;

  constructor() {
    // Generate or retrieve encryption key
    this.encryptionKey = this.getOrCreateEncryptionKey();
  }

  private getOrCreateEncryptionKey(): string {
    const keyStorageKey = 'ephemeral_prayer_key_hash';
    let keyHash = localStorage.getItem(keyStorageKey);

    if (!keyHash) {
      // Generate new encryption key
      const key = CryptoJS.lib.WordArray.random(256/8);
      keyHash = CryptoJS.SHA256(key.toString()).toString();
      localStorage.setItem(keyStorageKey, keyHash);
      return key.toString();
    }

    // In real implementation, would derive key from user authentication
    // For now, use the hash as a placeholder
    return keyHash;
  }

  private encrypt(data: any): string {
    const jsonString = JSON.stringify(data);
    return CryptoJS.AES.encrypt(jsonString, this.encryptionKey).toString();
  }

  private decrypt(encryptedData: string): any {
    try {
      const bytes = CryptoJS.AES.decrypt(encryptedData, this.encryptionKey);
      const decryptedString = bytes.toString(CryptoJS.enc.Utf8);
      return JSON.parse(decryptedString);
    } catch (error) {
      console.error('Failed to decrypt prayer data:', error);
      return null;
    }
  }

  // Prayer Management
  async createPrayer(prayer: Omit<Prayer, 'id' | 'createdAt' | 'updatedAt'>): Promise<Prayer> {
    const newPrayer: Prayer = {
      ...prayer,
      id: this.generateId(),
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const prayers = await this.getAllPrayers();
    prayers.push(newPrayer);
    await this.savePrayers(prayers);

    return newPrayer;
  }

  async updatePrayer(prayerId: string, updates: Partial<Prayer>): Promise<Prayer | null> {
    const prayers = await this.getAllPrayers();
    const prayerIndex = prayers.findIndex(p => p.id === prayerId);

    if (prayerIndex === -1) {
      return null;
    }

    prayers[prayerIndex] = {
      ...prayers[prayerIndex],
      ...updates,
      updatedAt: new Date()
    };

    await this.savePrayers(prayers);
    return prayers[prayerIndex];
  }

  async deletePrayer(prayerId: string): Promise<boolean> {
    const prayers = await this.getAllPrayers();
    const filteredPrayers = prayers.filter(p => p.id !== prayerId);

    if (filteredPrayers.length === prayers.length) {
      return false; // Prayer not found
    }

    await this.savePrayers(filteredPrayers);
    return true;
  }

  async getAllPrayers(): Promise<Prayer[]> {
    const encryptedData = localStorage.getItem(this.STORAGE_KEY);
    if (!encryptedData) {
      return [];
    }

    const decryptedData = this.decrypt(encryptedData);
    if (!decryptedData || !Array.isArray(decryptedData)) {
      return [];
    }

    // Convert date strings back to Date objects
    return decryptedData.map(prayer => ({
      ...prayer,
      createdAt: new Date(prayer.createdAt),
      updatedAt: new Date(prayer.updatedAt),
      answeredAt: prayer.answeredAt ? new Date(prayer.answeredAt) : undefined
    }));
  }

  async getPrayersByCategory(categoryId: string): Promise<Prayer[]> {
    const prayers = await this.getAllPrayers();
    return prayers.filter(p => p.category.id === categoryId);
  }

  async searchPrayers(query: string): Promise<Prayer[]> {
    const prayers = await this.getAllPrayers();
    const lowerQuery = query.toLowerCase();

    return prayers.filter(prayer =>
      prayer.title.toLowerCase().includes(lowerQuery) ||
      prayer.content.toLowerCase().includes(lowerQuery) ||
      prayer.tags.some(tag => tag.toLowerCase().includes(lowerQuery)) ||
      prayer.category.name.toLowerCase().includes(lowerQuery)
    );
  }

  private async savePrayers(prayers: Prayer[]): Promise<void> {
    const encryptedData = this.encrypt(prayers);
    localStorage.setItem(this.STORAGE_KEY, encryptedData);
  }

  // Prayer Sessions
  async startPrayerSession(): Promise<PrayerSession> {
    const session: PrayerSession = {
      id: this.generateId(),
      startTime: new Date(),
      prayers: [],
      mood: 'peaceful'
    };

    const sessions = await this.getAllSessions();
    sessions.push(session);
    await this.saveSessions(sessions);

    return session;
  }

  async endPrayerSession(sessionId: string, notes?: string): Promise<PrayerSession | null> {
    const sessions = await this.getAllSessions();
    const sessionIndex = sessions.findIndex(s => s.id === sessionId);

    if (sessionIndex === -1) {
      return null;
    }

    const endTime = new Date();
    const duration = Math.floor((endTime.getTime() - sessions[sessionIndex].startTime.getTime()) / 1000);

    sessions[sessionIndex] = {
      ...sessions[sessionIndex],
      endTime,
      duration,
      notes
    };

    await this.saveSessions(sessions);
    return sessions[sessionIndex];
  }

  async addPrayerToSession(sessionId: string, prayerId: string): Promise<boolean> {
    const sessions = await this.getAllSessions();
    const sessionIndex = sessions.findIndex(s => s.id === sessionId);

    if (sessionIndex === -1) {
      return false;
    }

    if (!sessions[sessionIndex].prayers.includes(prayerId)) {
      sessions[sessionIndex].prayers.push(prayerId);
      await this.saveSessions(sessions);
    }

    return true;
  }

  async getAllSessions(): Promise<PrayerSession[]> {
    const encryptedData = localStorage.getItem(this.SESSIONS_KEY);
    if (!encryptedData) {
      return [];
    }

    const decryptedData = this.decrypt(encryptedData);
    if (!decryptedData || !Array.isArray(decryptedData)) {
      return [];
    }

    return decryptedData.map(session => ({
      ...session,
      startTime: new Date(session.startTime),
      endTime: session.endTime ? new Date(session.endTime) : undefined
    }));
  }

  private async saveSessions(sessions: PrayerSession[]): Promise<void> {
    const encryptedData = this.encrypt(sessions);
    localStorage.setItem(this.SESSIONS_KEY, encryptedData);
  }

  // Categories
  getDefaultCategories(): PrayerCategory[] {
    return [
      {
        id: 'personal',
        name: 'Personal',
        description: 'Personal prayers and private requests',
        color: '#4ECDC4',
        icon: '🙏'
      },
      {
        id: 'family',
        name: 'Family',
        description: 'Prayers for family members and relationships',
        color: '#45B7D1',
        icon: '👨‍👩‍👧‍👦'
      },
      {
        id: 'ministry',
        name: 'Ministry',
        description: 'Prayers for ministry work and service',
        color: '#96CEB4',
        icon: '✝️'
      },
      {
        id: 'healing',
        name: 'Healing',
        description: 'Prayers for physical, emotional, and spiritual healing',
        color: '#FECA57',
        icon: '💚'
      },
      {
        id: 'guidance',
        name: 'Guidance',
        description: 'Prayers for wisdom and direction',
        color: '#FF6B6B',
        icon: '🧭'
      },
      {
        id: 'praise',
        name: 'Praise & Thanksgiving',
        description: 'Prayers of gratitude and worship',
        color: '#A8E6CF',
        icon: '🎵'
      },
      {
        id: 'world',
        name: 'World & Nations',
        description: 'Prayers for global issues and nations',
        color: '#88D8C0',
        icon: '🌍'
      },
      {
        id: 'protection',
        name: 'Protection',
        description: 'Prayers for safety and spiritual protection',
        color: '#74B9FF',
        icon: '🛡️'
      }
    ];
  }

  // Daily Verses and Spiritual Content
  async getDailyVerse(): Promise<DailyVerse> {
    // Use day of year to select consistent daily verse
    const now = new Date();
    const start = new Date(now.getFullYear(), 0, 0);
    const dayOfYear = Math.floor((now.getTime() - start.getTime()) / 86400000);

    const verses = this.getDailyVerses();
    const selectedVerse = verses[dayOfYear % verses.length];

    return selectedVerse;
  }

  private getDailyVerses(): DailyVerse[] {
    return [
      {
        text: "For I know the thoughts that I think toward you, saith the LORD, thoughts of peace, and not of evil, to give you an expected end.",
        reference: "Jeremiah 29:11",
        translation: "KJV",
        theme: "Hope"
      },
      {
        text: "Trust in the LORD with all thine heart; and lean not unto thine own understanding. In all thy ways acknowledge him, and he shall direct thy paths.",
        reference: "Proverbs 3:5-6",
        translation: "KJV",
        theme: "Trust"
      },
      {
        text: "And we know that all things work together for good to them that love God, to them who are the called according to his purpose.",
        reference: "Romans 8:28",
        translation: "KJV",
        theme: "Purpose"
      },
      {
        text: "Be not afraid nor dismayed by reason of this great multitude; for the battle is not yours, but God's.",
        reference: "2 Chronicles 20:15",
        translation: "KJV",
        theme: "Courage"
      },
      {
        text: "But they that wait upon the LORD shall renew their strength; they shall mount up with wings as eagles; they shall run, and not be weary; and they shall walk, and not faint.",
        reference: "Isaiah 40:31",
        translation: "KJV",
        theme: "Strength"
      },
      {
        text: "Be strong and of a good courage; be not afraid, neither be thou dismayed: for the LORD thy God is with thee whithersoever thou goest.",
        reference: "Joshua 1:9",
        translation: "KJV",
        theme: "Courage"
      },
      {
        text: "For by grace are ye saved through faith; and that not of yourselves: it is the gift of God.",
        reference: "Ephesians 2:8",
        translation: "KJV",
        theme: "Salvation"
      },
      {
        text: "I can do all things through Christ which strengtheneth me.",
        reference: "Philippians 4:13",
        translation: "KJV",
        theme: "Strength"
      },
      {
        text: "The LORD is my shepherd; I shall not want. He maketh me to lie down in green pastures: he leadeth me beside the still waters.",
        reference: "Psalm 23:1-2",
        translation: "KJV",
        theme: "Peace"
      },
      {
        text: "For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life.",
        reference: "John 3:16",
        translation: "KJV",
        theme: "Love"
      }
    ];
  }

  // Prayer Analytics and Insights
  async getPrayerStats(): Promise<{
    totalPrayers: number;
    answeredPrayers: number;
    activePrayers: number;
    prayersByCategory: Record<string, number>;
    totalPrayerSessions: number;
    averageSessionDuration: number;
    prayerStreak: number;
  }> {
    const prayers = await this.getAllPrayers();
    const sessions = await this.getAllSessions();

    const totalPrayers = prayers.length;
    const answeredPrayers = prayers.filter(p => p.isAnswered).length;
    const activePrayers = prayers.filter(p => !p.isAnswered).length;

    const prayersByCategory: Record<string, number> = {};
    prayers.forEach(prayer => {
      const categoryName = prayer.category.name;
      prayersByCategory[categoryName] = (prayersByCategory[categoryName] || 0) + 1;
    });

    const totalPrayerSessions = sessions.length;
    const completedSessions = sessions.filter(s => s.endTime);
    const averageSessionDuration = completedSessions.length > 0
      ? completedSessions.reduce((sum, s) => sum + (s.duration || 0), 0) / completedSessions.length
      : 0;

    // Calculate prayer streak (consecutive days with prayer sessions)
    const prayerStreak = this.calculatePrayerStreak(sessions);

    return {
      totalPrayers,
      answeredPrayers,
      activePrayers,
      prayersByCategory,
      totalPrayerSessions,
      averageSessionDuration,
      prayerStreak
    };
  }

  private calculatePrayerStreak(sessions: PrayerSession[]): number {
    if (sessions.length === 0) return 0;

    // Sort sessions by date
    const sortedSessions = sessions
      .filter(s => s.endTime) // Only completed sessions
      .sort((a, b) => b.startTime.getTime() - a.startTime.getTime());

    if (sortedSessions.length === 0) return 0;

    let streak = 0;
    let currentDate = new Date();
    currentDate.setHours(0, 0, 0, 0);

    for (let i = 0; i < sortedSessions.length; i++) {
      const sessionDate = new Date(sortedSessions[i].startTime);
      sessionDate.setHours(0, 0, 0, 0);

      // Check if this session is on the current date we're checking
      if (sessionDate.getTime() === currentDate.getTime()) {
        streak++;
        // Move to previous day
        currentDate.setDate(currentDate.getDate() - 1);
      } else if (sessionDate.getTime() < currentDate.getTime()) {
        // Gap in the streak
        break;
      }
    }

    return streak;
  }

  // Utility methods
  private generateId(): string {
    return CryptoJS.lib.WordArray.random(16).toString();
  }

  // Export/Import (for backup purposes)
  async exportPrayerData(): Promise<string> {
    const prayers = await this.getAllPrayers();
    const sessions = await this.getAllSessions();

    const exportData = {
      prayers,
      sessions,
      exportedAt: new Date(),
      version: '1.0'
    };

    return JSON.stringify(exportData, null, 2);
  }

  async importPrayerData(jsonData: string): Promise<boolean> {
    try {
      const importData = JSON.parse(jsonData);

      if (importData.prayers && Array.isArray(importData.prayers)) {
        await this.savePrayers(importData.prayers);
      }

      if (importData.sessions && Array.isArray(importData.sessions)) {
        await this.saveSessions(importData.sessions);
      }

      return true;
    } catch (error) {
      console.error('Failed to import prayer data:', error);
      return false;
    }
  }

  // Clear all data (for privacy)
  async clearAllPrayerData(): Promise<void> {
    localStorage.removeItem(this.STORAGE_KEY);
    localStorage.removeItem(this.SESSIONS_KEY);
    localStorage.removeItem(this.SETTINGS_KEY);
  }
}

export const prayerService = new PrayerService();