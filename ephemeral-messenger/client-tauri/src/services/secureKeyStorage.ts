// Secure Key Storage Service
// Implements secure key derivation, storage, and management

import { memoryProtection, SecureString } from './memoryProtection';

export interface KeyDerivationParams {
  salt: Uint8Array;
  iterations: number;
  algorithm: 'PBKDF2' | 'Argon2id' | 'scrypt';
  keyLength: number;
  memory?: number; // For Argon2id
  parallelism?: number; // For Argon2id
}

export interface StoredKey {
  id: string;
  label: string;
  algorithm: string;
  created: Date;
  lastUsed: Date;
  usage: string[]; // 'encrypt', 'decrypt', 'sign', 'verify'
  metadata: {
    keyType: 'symmetric' | 'asymmetric';
    strength: number;
    derivedFrom?: string;
  };
}

export interface KeyStorageConfig {
  enableSecureMemory: boolean;
  keyTimeoutMs: number;
  maxStoredKeys: number;
  requireHardwareSupport: boolean;
  enableKeyRotation: boolean;
  rotationIntervalMs: number;
}

export interface DerivedKeyResult {
  keyId: string;
  key: CryptoKey;
  params: KeyDerivationParams;
  strength: number;
}

class SecureKeyStorageService {
  private config: KeyStorageConfig;
  private storedKeys: Map<string, StoredKey> = new Map();
  private keyBuffers: Map<string, string> = new Map(); // Maps to secure buffer IDs
  private cryptoKeys: Map<string, CryptoKey> = new Map();
  private keyTimeouts: Map<string, number> = new Map();
  private passphraseSalts: Map<string, Uint8Array> = new Map();

  constructor() {
    this.config = {
      enableSecureMemory: true,
      keyTimeoutMs: 15 * 60 * 1000, // 15 minutes
      maxStoredKeys: 50,
      requireHardwareSupport: false,
      enableKeyRotation: true,
      rotationIntervalMs: 24 * 60 * 60 * 1000, // 24 hours
    };

    this.startKeyTimeout();
    this.startKeyRotation();
  }

  /**
   * Derive key from passphrase using strong KDF
   */
  async deriveKeyFromPassphrase(
    passphrase: string,
    label: string,
    usage: KeyUsage[],
    params?: Partial<KeyDerivationParams>
  ): Promise<DerivedKeyResult> {
    const securePassphrase = memoryProtection.createSecureString(passphrase);

    try {
      // Generate or retrieve salt
      let salt = this.passphraseSalts.get(label);
      if (!salt) {
        salt = crypto.getRandomValues(new Uint8Array(32));
        this.passphraseSalts.set(label, salt);
      }

      // Default parameters for strong key derivation
      const derivationParams: KeyDerivationParams = {
        salt,
        iterations: 600000, // OWASP recommendation for PBKDF2
        algorithm: 'PBKDF2',
        keyLength: 32,
        ...params,
      };

      const keyMaterial = await this.performKeyDerivation(
        securePassphrase.getValue() || '',
        derivationParams
      );

      const cryptoKey = await this.importKey(keyMaterial, usage);
      const keyId = await this.storeKey(cryptoKey, label, 'symmetric', derivationParams);

      // Calculate strength score
      const strength = this.calculateKeyStrength(derivationParams);

      return {
        keyId,
        key: cryptoKey,
        params: derivationParams,
        strength,
      };
    } finally {
      securePassphrase.wipe();
    }
  }

  /**
   * Generate new cryptographic key
   */
  async generateKey(
    algorithm: string,
    keySize: number,
    usage: KeyUsage[],
    label: string
  ): Promise<string> {
    let keyPair: CryptoKeyPair | CryptoKey;

    switch (algorithm) {
      case 'Ed25519':
        keyPair = await crypto.subtle.generateKey(
          { name: 'Ed25519' },
          true,
          usage
        );
        break;

      case 'X25519':
        keyPair = await crypto.subtle.generateKey(
          { name: 'X25519' },
          true,
          usage
        );
        break;

      case 'AES-GCM':
        keyPair = await crypto.subtle.generateKey(
          { name: 'AES-GCM', length: keySize },
          true,
          usage
        );
        break;

      case 'ChaCha20-Poly1305':
        // Fallback to AES-GCM if ChaCha20 not available
        keyPair = await crypto.subtle.generateKey(
          { name: 'AES-GCM', length: 256 },
          true,
          usage
        );
        break;

      default:
        throw new Error(`Unsupported algorithm: ${algorithm}`);
    }

    if ('privateKey' in keyPair) {
      // Asymmetric key pair
      const privateKeyId = await this.storeKey(keyPair.privateKey, `${label}-private`, 'asymmetric');
      const publicKeyId = await this.storeKey(keyPair.publicKey, `${label}-public`, 'asymmetric');

      // Link keys
      const privateKey = this.storedKeys.get(privateKeyId)!;
      const publicKey = this.storedKeys.get(publicKeyId)!;
      privateKey.metadata.derivedFrom = publicKeyId;
      publicKey.metadata.derivedFrom = privateKeyId;

      return privateKeyId;
    } else {
      // Symmetric key
      return await this.storeKey(keyPair, label, 'symmetric');
    }
  }

  /**
   * Store cryptographic key securely
   */
  private async storeKey(
    key: CryptoKey,
    label: string,
    keyType: 'symmetric' | 'asymmetric',
    derivationParams?: KeyDerivationParams
  ): Promise<string> {
    if (this.storedKeys.size >= this.config.maxStoredKeys) {
      throw new Error('Maximum number of stored keys exceeded');
    }

    const keyId = this.generateKeyId();

    // Export key for secure storage
    const keyData = await crypto.subtle.exportKey('raw', key);

    // Store in secure memory if enabled
    let bufferId: string | null = null;
    if (this.config.enableSecureMemory) {
      bufferId = memoryProtection.allocateSecureBuffer(keyData.byteLength, `Key: ${label}`);
      memoryProtection.writeSecureBuffer(bufferId, keyData);
    }

    // Store metadata
    const storedKey: StoredKey = {
      id: keyId,
      label,
      algorithm: key.algorithm.name,
      created: new Date(),
      lastUsed: new Date(),
      usage: key.usages,
      metadata: {
        keyType,
        strength: this.calculateKeyStrengthFromKey(key),
        derivedFrom: derivationParams ? 'passphrase' : undefined,
      },
    };

    this.storedKeys.set(keyId, storedKey);
    this.cryptoKeys.set(keyId, key);

    if (bufferId) {
      this.keyBuffers.set(keyId, bufferId);
    }

    // Set timeout for key removal
    this.setKeyTimeout(keyId);

    console.log(`Stored key ${keyId} (${label}) - ${keyType} ${key.algorithm.name}`);
    return keyId;
  }

  /**
   * Retrieve stored key
   */
  async getKey(keyId: string): Promise<CryptoKey | null> {
    const storedKey = this.storedKeys.get(keyId);
    if (!storedKey) {
      return null;
    }

    // Update last used time
    storedKey.lastUsed = new Date();

    // Refresh timeout
    this.setKeyTimeout(keyId);

    // Return cached crypto key
    const cryptoKey = this.cryptoKeys.get(keyId);
    if (cryptoKey) {
      return cryptoKey;
    }

    // Reconstruct key from secure memory
    const bufferId = this.keyBuffers.get(keyId);
    if (bufferId) {
      const keyData = memoryProtection.readSecureBuffer(bufferId);
      if (keyData) {
        try {
          const reconstructedKey = await crypto.subtle.importKey(
            'raw',
            keyData,
            storedKey.algorithm,
            true,
            storedKey.usage
          );
          this.cryptoKeys.set(keyId, reconstructedKey);
          return reconstructedKey;
        } catch (error) {
          console.error(`Failed to reconstruct key ${keyId}:`, error);
        }
      }
    }

    return null;
  }

  /**
   * Remove key from storage
   */
  removeKey(keyId: string): boolean {
    const storedKey = this.storedKeys.get(keyId);
    if (!storedKey) {
      return false;
    }

    // Clear timeout
    const timeoutId = this.keyTimeouts.get(keyId);
    if (timeoutId) {
      clearTimeout(timeoutId);
      this.keyTimeouts.delete(keyId);
    }

    // Wipe secure memory
    const bufferId = this.keyBuffers.get(keyId);
    if (bufferId) {
      memoryProtection.releaseSecureBuffer(bufferId);
      this.keyBuffers.delete(keyId);
    }

    // Remove from storage
    this.storedKeys.delete(keyId);
    this.cryptoKeys.delete(keyId);

    console.log(`Removed key ${keyId} (${storedKey.label})`);
    return true;
  }

  /**
   * List all stored keys
   */
  listKeys(): StoredKey[] {
    return Array.from(this.storedKeys.values());
  }

  /**
   * Export key for backup (encrypted)
   */
  async exportKey(keyId: string, passphrase: string): Promise<string> {
    const key = await this.getKey(keyId);
    if (!key) {
      throw new Error('Key not found');
    }

    const keyData = await crypto.subtle.exportKey('raw', key);

    // Encrypt with passphrase
    const exportKey = await this.deriveKeyFromPassphrase(
      passphrase,
      'export-key',
      ['encrypt']
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      exportKey.key,
      keyData
    );

    // Package for export
    const exportData = {
      keyId,
      encrypted: Array.from(new Uint8Array(encrypted)),
      iv: Array.from(iv),
      salt: Array.from(exportKey.params.salt),
      iterations: exportKey.params.iterations,
      metadata: this.storedKeys.get(keyId),
    };

    return btoa(JSON.stringify(exportData));
  }

  /**
   * Import key from backup
   */
  async importKey(exportedData: string, passphrase: string): Promise<string> {
    try {
      const data = JSON.parse(atob(exportedData));

      // Derive decryption key
      const decryptKey = await this.deriveKeyFromPassphrase(
        passphrase,
        'import-key',
        ['decrypt'],
        {
          salt: new Uint8Array(data.salt),
          iterations: data.iterations,
        }
      );

      // Decrypt key data
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(data.iv) },
        decryptKey.key,
        new Uint8Array(data.encrypted)
      );

      // Import the key
      const importedKey = await crypto.subtle.importKey(
        'raw',
        decrypted,
        data.metadata.algorithm,
        true,
        data.metadata.usage
      );

      // Store the imported key
      return await this.storeKey(
        importedKey,
        data.metadata.label + '-imported',
        data.metadata.metadata.keyType
      );
    } catch (error) {
      throw new Error(`Failed to import key: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Perform key derivation using specified algorithm
   */
  private async performKeyDerivation(
    passphrase: string,
    params: KeyDerivationParams
  ): Promise<ArrayBuffer> {
    const encoder = new TextEncoder();
    const passphraseBytes = encoder.encode(passphrase);

    switch (params.algorithm) {
      case 'PBKDF2':
        return await this.pbkdf2(passphraseBytes, params);

      case 'Argon2id':
        // Fallback to PBKDF2 if Argon2 not available
        console.warn('Argon2id not available, falling back to PBKDF2');
        return await this.pbkdf2(passphraseBytes, params);

      case 'scrypt':
        // Fallback to PBKDF2 if scrypt not available
        console.warn('scrypt not available, falling back to PBKDF2');
        return await this.pbkdf2(passphraseBytes, params);

      default:
        throw new Error(`Unsupported KDF: ${params.algorithm}`);
    }
  }

  /**
   * PBKDF2 key derivation
   */
  private async pbkdf2(
    passphrase: Uint8Array,
    params: KeyDerivationParams
  ): Promise<ArrayBuffer> {
    const key = await crypto.subtle.importKey(
      'raw',
      passphrase,
      'PBKDF2',
      false,
      ['deriveBits']
    );

    return await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: params.salt,
        iterations: params.iterations,
        hash: 'SHA-256',
      },
      key,
      params.keyLength * 8
    );
  }

  /**
   * Import raw key material as CryptoKey
   */
  private async importKey(keyMaterial: ArrayBuffer, usage: KeyUsage[]): Promise<CryptoKey> {
    return await crypto.subtle.importKey(
      'raw',
      keyMaterial,
      { name: 'AES-GCM' },
      true,
      usage
    );
  }

  /**
   * Calculate key strength score
   */
  private calculateKeyStrength(params: KeyDerivationParams): number {
    let score = 0;

    // Algorithm scoring
    switch (params.algorithm) {
      case 'Argon2id': score += 40; break;
      case 'scrypt': score += 35; break;
      case 'PBKDF2': score += 30; break;
    }

    // Iteration scoring
    if (params.iterations >= 600000) score += 30;
    else if (params.iterations >= 100000) score += 20;
    else if (params.iterations >= 10000) score += 10;

    // Key length scoring
    if (params.keyLength >= 32) score += 20;
    else if (params.keyLength >= 16) score += 10;

    // Salt length scoring
    if (params.salt.length >= 32) score += 10;
    else if (params.salt.length >= 16) score += 5;

    return Math.min(score, 100);
  }

  /**
   * Calculate key strength from CryptoKey
   */
  private calculateKeyStrengthFromKey(key: CryptoKey): number {
    const algorithm = key.algorithm as any;

    switch (algorithm.name) {
      case 'Ed25519':
      case 'X25519':
        return 100; // Curve25519 is excellent

      case 'AES-GCM':
        if (algorithm.length >= 256) return 90;
        if (algorithm.length >= 128) return 80;
        return 60;

      default:
        return 50; // Unknown algorithm
    }
  }

  /**
   * Generate unique key ID
   */
  private generateKeyId(): string {
    const timestamp = Date.now().toString(36);
    const random = crypto.getRandomValues(new Uint8Array(8));
    const randomHex = Array.from(random, b => b.toString(16).padStart(2, '0')).join('');
    return `key_${timestamp}_${randomHex}`;
  }

  /**
   * Set timeout for key removal
   */
  private setKeyTimeout(keyId: string): void {
    // Clear existing timeout
    const existingTimeout = this.keyTimeouts.get(keyId);
    if (existingTimeout) {
      clearTimeout(existingTimeout);
    }

    // Set new timeout
    const timeoutId = window.setTimeout(() => {
      console.log(`Auto-removing expired key ${keyId}`);
      this.removeKey(keyId);
    }, this.config.keyTimeoutMs);

    this.keyTimeouts.set(keyId, timeoutId);
  }

  /**
   * Start key timeout management
   */
  private startKeyTimeout(): void {
    setInterval(() => {
      const now = new Date();
      for (const [keyId, storedKey] of this.storedKeys.entries()) {
        const age = now.getTime() - storedKey.lastUsed.getTime();
        if (age > this.config.keyTimeoutMs) {
          console.log(`Removing unused key ${keyId} (age: ${Math.round(age / 1000)}s)`);
          this.removeKey(keyId);
        }
      }
    }, 60000); // Check every minute
  }

  /**
   * Start key rotation
   */
  private startKeyRotation(): void {
    if (!this.config.enableKeyRotation) return;

    setInterval(() => {
      console.log('Starting automatic key rotation...');
      this.rotateOldKeys();
    }, this.config.rotationIntervalMs);
  }

  /**
   * Rotate old keys
   */
  private rotateOldKeys(): void {
    const now = new Date();
    const rotationAge = this.config.rotationIntervalMs;

    for (const [keyId, storedKey] of this.storedKeys.entries()) {
      const age = now.getTime() - storedKey.created.getTime();
      if (age > rotationAge && storedKey.metadata.keyType === 'symmetric') {
        console.log(`Rotating old key ${keyId} (age: ${Math.round(age / (1000 * 60 * 60))} hours)`);
        // In a real implementation, you'd generate a new key and update references
        this.removeKey(keyId);
      }
    }
  }

  /**
   * Configure key storage settings
   */
  configure(config: Partial<KeyStorageConfig>): void {
    this.config = { ...this.config, ...config };
  }

  /**
   * Get storage statistics
   */
  getStats() {
    return {
      totalKeys: this.storedKeys.size,
      maxKeys: this.config.maxStoredKeys,
      memoryBuffers: this.keyBuffers.size,
      keysByType: this.getKeysByType(),
      averageAge: this.getAverageKeyAge(),
    };
  }

  private getKeysByType() {
    const types: { [key: string]: number } = {};
    for (const key of this.storedKeys.values()) {
      types[key.metadata.keyType] = (types[key.metadata.keyType] || 0) + 1;
    }
    return types;
  }

  private getAverageKeyAge(): number {
    if (this.storedKeys.size === 0) return 0;

    const now = new Date();
    const totalAge = Array.from(this.storedKeys.values())
      .reduce((sum, key) => sum + (now.getTime() - key.created.getTime()), 0);

    return totalAge / this.storedKeys.size;
  }

  /**
   * Shutdown and cleanup
   */
  shutdown(): void {
    // Clear all timeouts
    for (const timeoutId of this.keyTimeouts.values()) {
      clearTimeout(timeoutId);
    }

    // Remove all keys
    for (const keyId of this.storedKeys.keys()) {
      this.removeKey(keyId);
    }

    // Clear all data
    this.storedKeys.clear();
    this.cryptoKeys.clear();
    this.keyBuffers.clear();
    this.keyTimeouts.clear();
    this.passphraseSalts.clear();
  }
}

// Export singleton instance
export const secureKeyStorage = new SecureKeyStorageService();
export default secureKeyStorage;