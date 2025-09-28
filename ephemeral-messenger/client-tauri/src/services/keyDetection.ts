/**
 * Hardware Key Detection Service for Ephemeral Messenger Client
 *
 * This service provides frontend integration with the hardware key detection system.
 * It communicates with the Tauri backend to monitor key presence and enforce
 * hardware key requirements.
 *
 * SECURITY NOTE: This module is read-only and performs no destructive operations.
 * It only detects and validates keyfiles - enforcement actions require separate authorization.
 */

import { invoke } from '@tauri-apps/api/tauri';
import { listen, UnlistenFn } from '@tauri-apps/api/event';

export interface KeyDetectionConfig {
  devicePaths: string[];
  keyDirName: string;
  keyFileName: string;
  gracePeriodSec: number;
  pollingIntervalSec: number;
  useFilesystemEvents: boolean;
  verboseLogging: boolean;
}

export interface ValidatedKey {
  deviceUuid: string;
  devicePath: string;
  keyFilePath: string;
  keyFile: {
    version: number;
    userId: string;
    pubIdentityEd: string;
    pubX25519: string;
    pubAge: string;
    deviceId?: string;
    createdAt: string;
    expiresAt: string;
    fingerprint: string;
    validatedAt: string;
    signatureValid: boolean;
    notExpired: boolean;
    structureValid: boolean;
  };
  detectedAt: string;
  lastSeen: string;
  accessCount: number;
}

export interface KeyEvent {
  type: KeyEventType;
  key?: ValidatedKey;
  timestamp: string;
  message: string;
  error?: string;
}

export type KeyEventType =
  | 'attached'
  | 'removed'
  | 'invalid'
  | 'expired'
  | 'grace_started'
  | 'grace_timeout'
  | 'grace_cancelled'
  | 'validated'
  | 'error';

export interface KeyDetectionStats {
  isRunning: boolean;
  currentKeyPresent: boolean;
  graceTimerActive: boolean;
  filesystemEvents: boolean;
  pollingIntervalSec: number;
  gracePeriodSec: number;
  watchedPaths: string[];
  currentKey?: {
    userId: string;
    fingerprint: string;
    detectedAt: string;
    lastSeen: string;
    accessCount: number;
    expiresAt: string;
  };
}

export type KeyEventCallback = (event: KeyEvent) => void;

class KeyDetectionService {
  private isInitialized = false;
  private eventListeners: KeyEventCallback[] = [];
  private unlistenFunctions: UnlistenFn[] = [];
  private currentConfig: KeyDetectionConfig | null = null;

  /**
   * Initialize the key detection service
   */
  async initialize(config?: Partial<KeyDetectionConfig>): Promise<void> {
    if (this.isInitialized) {
      console.warn('Key detection service already initialized');
      return;
    }

    try {
      // Get default configuration from backend
      const defaultConfig = await invoke<KeyDetectionConfig>('get_default_key_detection_config');

      // Merge with provided config
      this.currentConfig = {
        ...defaultConfig,
        ...config
      };

      // Initialize backend key detector
      await invoke('initialize_key_detector', { config: this.currentConfig });

      // Set up event listeners
      await this.setupEventListeners();

      // Start key detection
      await invoke('start_key_detection');

      this.isInitialized = true;
      console.log('Key detection service initialized successfully');

    } catch (error) {
      console.error('Failed to initialize key detection service:', error);
      throw error;
    }
  }

  /**
   * Shutdown the key detection service
   */
  async shutdown(): Promise<void> {
    if (!this.isInitialized) {
      return;
    }

    try {
      // Stop key detection
      await invoke('stop_key_detection');

      // Clean up event listeners
      for (const unlisten of this.unlistenFunctions) {
        unlisten();
      }
      this.unlistenFunctions = [];
      this.eventListeners = [];

      this.isInitialized = false;
      console.log('Key detection service shut down');

    } catch (error) {
      console.error('Error shutting down key detection service:', error);
      throw error;
    }
  }

  /**
   * Check if the service is initialized
   */
  isServiceInitialized(): boolean {
    return this.isInitialized;
  }

  /**
   * Get the current validated key, if any
   */
  async getCurrentKey(): Promise<ValidatedKey | null> {
    this.ensureInitialized();

    try {
      return await invoke<ValidatedKey | null>('get_current_key');
    } catch (error) {
      console.error('Failed to get current key:', error);
      return null;
    }
  }

  /**
   * Check if a valid key is currently present
   */
  async isKeyPresent(): Promise<boolean> {
    this.ensureInitialized();

    try {
      return await invoke<boolean>('is_key_present');
    } catch (error) {
      console.error('Failed to check key presence:', error);
      return false;
    }
  }

  /**
   * Get key detection statistics
   */
  async getDetectionStats(): Promise<KeyDetectionStats> {
    this.ensureInitialized();

    try {
      return await invoke<KeyDetectionStats>('get_key_detection_stats');
    } catch (error) {
      console.error('Failed to get detection stats:', error);
      throw error;
    }
  }

  /**
   * Manually trigger a key detection refresh
   */
  async refreshDetection(): Promise<void> {
    this.ensureInitialized();

    try {
      await invoke('refresh_key_detection');
    } catch (error) {
      console.error('Failed to refresh key detection:', error);
      throw error;
    }
  }

  /**
   * Set the grace period callback function
   */
  async setGracePeriodCallback(callback: () => void): Promise<void> {
    this.ensureInitialized();

    // Store callback for grace timeout events
    this.addEventListener((event) => {
      if (event.type === 'grace_timeout') {
        callback();
      }
    });
  }

  /**
   * Add an event listener for key events
   */
  addEventListener(callback: KeyEventCallback): void {
    this.eventListeners.push(callback);
  }

  /**
   * Remove an event listener
   */
  removeEventListener(callback: KeyEventCallback): void {
    const index = this.eventListeners.indexOf(callback);
    if (index > -1) {
      this.eventListeners.splice(index, 1);
    }
  }

  /**
   * Get the current configuration
   */
  getCurrentConfig(): KeyDetectionConfig | null {
    return this.currentConfig;
  }

  /**
   * Update the configuration (requires restart)
   */
  async updateConfig(config: Partial<KeyDetectionConfig>): Promise<void> {
    this.ensureInitialized();

    const newConfig = {
      ...this.currentConfig!,
      ...config
    };

    try {
      await invoke('update_key_detection_config', { config: newConfig });
      this.currentConfig = newConfig;
    } catch (error) {
      console.error('Failed to update key detection config:', error);
      throw error;
    }
  }

  /**
   * Validate a keyfile manually (for testing/debugging)
   */
  async validateKeyFile(keyFilePath: string): Promise<ValidatedKey | null> {
    try {
      return await invoke<ValidatedKey | null>('validate_key_file', { keyFilePath });
    } catch (error) {
      console.error('Failed to validate key file:', error);
      return null;
    }
  }

  /**
   * Scan for removable devices (for UI purposes)
   */
  async scanRemovableDevices(): Promise<RemovableDevice[]> {
    try {
      return await invoke<RemovableDevice[]>('scan_removable_devices');
    } catch (error) {
      console.error('Failed to scan removable devices:', error);
      return [];
    }
  }

  /**
   * Check if a specific device contains a valid keyfile
   */
  async checkDeviceForKey(devicePath: string): Promise<boolean> {
    try {
      return await invoke<boolean>('check_device_for_key', { devicePath });
    } catch (error) {
      console.error('Failed to check device for key:', error);
      return false;
    }
  }

  /**
   * Get human-readable status description
   */
  async getStatusDescription(): Promise<string> {
    const stats = await this.getDetectionStats();
    const currentKey = await this.getCurrentKey();

    if (currentKey) {
      const expiresAt = new Date(currentKey.keyFile.expiresAt);
      const timeUntilExpiry = expiresAt.getTime() - Date.now();
      const daysUntilExpiry = Math.floor(timeUntilExpiry / (1000 * 60 * 60 * 24));

      if (daysUntilExpiry <= 7) {
        return `Hardware key present (expires in ${daysUntilExpiry} days)`;
      } else {
        return `Hardware key present (user: ${currentKey.keyFile.userId})`;
      }
    }

    if (stats.graceTimerActive) {
      return `Hardware key removed - grace period active`;
    }

    return 'No hardware key detected';
  }

  /**
   * Set up event listeners for backend events
   */
  private async setupEventListeners(): Promise<void> {
    // Listen for key events from the backend
    const unlistenKeyEvents = await listen<KeyEvent>('key-event', (event) => {
      this.handleKeyEvent(event.payload);
    });
    this.unlistenFunctions.push(unlistenKeyEvents);

    // Listen for detection errors
    const unlistenErrors = await listen<{ error: string }>('key-detection-error', (event) => {
      console.error('Key detection error:', event.payload.error);

      const errorEvent: KeyEvent = {
        type: 'error',
        timestamp: new Date().toISOString(),
        message: 'Key detection error',
        error: event.payload.error
      };

      this.handleKeyEvent(errorEvent);
    });
    this.unlistenFunctions.push(unlistenErrors);
  }

  /**
   * Handle key events from the backend
   */
  private handleKeyEvent(event: KeyEvent): void {
    // Log the event
    console.log(`Key event: ${event.type} - ${event.message}`);

    // Notify all listeners
    for (const listener of this.eventListeners) {
      try {
        listener(event);
      } catch (error) {
        console.error('Error in key event listener:', error);
      }
    }
  }

  /**
   * Ensure the service is initialized
   */
  private ensureInitialized(): void {
    if (!this.isInitialized) {
      throw new Error('Key detection service not initialized. Call initialize() first.');
    }
  }
}

export interface RemovableDevice {
  uuid: string;
  name: string;
  path: string;
  mountPoint: string;
  size: number;
  available: boolean;
  filesystem?: string;
}

// Create and export singleton instance
export const keyDetectionService = new KeyDetectionService();

// Export default configuration for convenience
export const defaultKeyDetectionConfig: KeyDetectionConfig = {
  devicePaths: [
    '/media',
    '/run/media',
    '/mnt',
    '/run/user/1000',
    '/run/user/1001'
  ],
  keyDirName: 'KEYSTORE',
  keyFileName: 'secure_key.json',
  gracePeriodSec: 300, // 5 minutes
  pollingIntervalSec: 10, // 10 seconds
  useFilesystemEvents: true,
  verboseLogging: false
};

// Utility functions
export const keyDetectionUtils = {
  /**
   * Format a fingerprint for display
   */
  formatFingerprint(fingerprint: string): string {
    return fingerprint.replace(/(.{4})/g, '$1:').slice(0, -1);
  },

  /**
   * Check if a key is expiring soon (within 7 days)
   */
  isKeyExpiringSoon(key: ValidatedKey): boolean {
    const expiresAt = new Date(key.keyFile.expiresAt);
    const sevenDaysFromNow = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    return expiresAt <= sevenDaysFromNow;
  },

  /**
   * Get time until key expiration as a human-readable string
   */
  getTimeUntilExpiration(key: ValidatedKey): string {
    const expiresAt = new Date(key.keyFile.expiresAt);
    const now = new Date();
    const timeDiff = expiresAt.getTime() - now.getTime();

    if (timeDiff <= 0) {
      return 'Expired';
    }

    const days = Math.floor(timeDiff / (1000 * 60 * 60 * 24));
    const hours = Math.floor((timeDiff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));

    if (days > 0) {
      return `${days} day${days === 1 ? '' : 's'}`;
    } else {
      return `${hours} hour${hours === 1 ? '' : 's'}`;
    }
  },

  /**
   * Validate a user ID format (UUID)
   */
  isValidUserId(userId: string): boolean {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(userId);
  },

  /**
   * Get event type display name
   */
  getEventTypeDisplayName(eventType: KeyEventType): string {
    const displayNames: Record<KeyEventType, string> = {
      'attached': 'Key Attached',
      'removed': 'Key Removed',
      'invalid': 'Invalid Key',
      'expired': 'Key Expired',
      'grace_started': 'Grace Period Started',
      'grace_timeout': 'Grace Period Expired',
      'grace_cancelled': 'Grace Period Cancelled',
      'validated': 'Key Validated',
      'error': 'Detection Error'
    };
    return displayNames[eventType] || eventType;
  }
};

export default keyDetectionService;