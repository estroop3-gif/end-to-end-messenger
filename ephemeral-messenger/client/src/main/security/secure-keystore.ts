import * as sodium from 'libsodium-wrappers';
import * as argon2 from 'argon2';
import { execSync } from 'child_process';

export interface SecureKeystore {
  storeKey(keyId: string, keyData: Uint8Array, passphrase?: string): Promise<boolean>;
  retrieveKey(keyId: string, passphrase?: string): Promise<Uint8Array | null>;
  deleteKey(keyId: string): Promise<boolean>;
  wipeAllKeys(): Promise<void>;
}

export interface KeystoreEntry {
  encrypted: string;
  salt: string;
  nonce: string;
  algorithm: string;
  timestamp: number;
}

// Hardware-backed secure keystore
export class HardwareSecureKeystore implements SecureKeystore {
  private readonly keystorePath: string;

  constructor(keystorePath: string = '.secure_keystore') {
    this.keystorePath = keystorePath;
  }

  async storeKey(keyId: string, keyData: Uint8Array, passphrase?: string): Promise<boolean> {
    try {
      await sodium.ready;

      let encryptionKey: Uint8Array;

      // Try hardware token first
      const hardwareKey = await this.getHardwareKey();
      if (hardwareKey) {
        encryptionKey = hardwareKey;
      } else if (passphrase) {
        encryptionKey = await this.deriveKeyFromPassphrase(passphrase);
      } else {
        throw new Error('No encryption method available (hardware token or passphrase)');
      }

      const salt = sodium.randombytes_buf(32);
      const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);

      // Encrypt the key data
      const encrypted = sodium.crypto_secretbox_easy(keyData, nonce, encryptionKey);

      const entry: KeystoreEntry = {
        encrypted: sodium.to_base64(encrypted),
        salt: sodium.to_base64(salt),
        nonce: sodium.to_base64(nonce),
        algorithm: 'xsalsa20poly1305',
        timestamp: Date.now(),
      };

      // Store encrypted entry
      await this.writeKeystoreEntry(keyId, entry);

      // Secure wipe encryption key
      sodium.memzero(encryptionKey);

      return true;
    } catch (error) {
      console.error('Failed to store key:', error);
      return false;
    }
  }

  async retrieveKey(keyId: string, passphrase?: string): Promise<Uint8Array | null> {
    try {
      await sodium.ready;

      const entry = await this.readKeystoreEntry(keyId);
      if (!entry) return null;

      let encryptionKey: Uint8Array;

      // Try hardware token first
      const hardwareKey = await this.getHardwareKey();
      if (hardwareKey) {
        encryptionKey = hardwareKey;
      } else if (passphrase) {
        encryptionKey = await this.deriveKeyFromPassphrase(passphrase, sodium.from_base64(entry.salt));
      } else {
        throw new Error('No decryption method available');
      }

      const encrypted = sodium.from_base64(entry.encrypted);
      const nonce = sodium.from_base64(entry.nonce);

      // Decrypt the key data
      const keyData = sodium.crypto_secretbox_open_easy(encrypted, nonce, encryptionKey);

      // Secure wipe encryption key
      sodium.memzero(encryptionKey);

      return keyData;
    } catch (error) {
      console.error('Failed to retrieve key:', error);
      return null;
    }
  }

  async deleteKey(keyId: string): Promise<boolean> {
    try {
      // TODO: Securely delete the keystore entry
      return true;
    } catch (error) {
      console.error('Failed to delete key:', error);
      return false;
    }
  }

  async wipeAllKeys(): Promise<void> {
    // TODO: Implement secure wipe of entire keystore
    console.log('Wiping all keys from secure keystore...');
  }

  private async getHardwareKey(): Promise<Uint8Array | null> {
    try {
      // Try to get key from YubiKey
      const yubiKey = await this.getYubiKeySecret();
      if (yubiKey) return yubiKey;

      // Try to get key from OpenPGP card
      const pgpKey = await this.getOpenPGPCardSecret();
      if (pgpKey) return pgpKey;

      return null;
    } catch (error) {
      console.error('Hardware key retrieval failed:', error);
      return null;
    }
  }

  private async getYubiKeySecret(): Promise<Uint8Array | null> {
    try {
      // Use YubiKey HMAC-SHA1 challenge-response
      // This requires ykman or similar tool
      const challenge = sodium.randombytes_buf(32);
      const challengeHex = sodium.to_hex(challenge);

      const response = execSync(`ykman oath accounts code -s "keystore-secret"`, {
        encoding: 'utf8',
        timeout: 10000,
      }).trim();

      // Hash the response to get a consistent key
      await sodium.ready;
      return sodium.crypto_generichash(32, sodium.from_string(response));
    } catch (error) {
      console.debug('YubiKey not available or failed:', error);
      return null;
    }
  }

  private async getOpenPGPCardSecret(): Promise<Uint8Array | null> {
    try {
      // Use OpenPGP card for key derivation
      // This is a simplified implementation
      const cardInfo = execSync('gpg --card-status', {
        encoding: 'utf8',
        timeout: 10000,
      });

      if (!cardInfo.includes('OpenPGP card')) {
        return null;
      }

      // Extract serial number or similar unique identifier
      const serialMatch = cardInfo.match(/Serial number.*?:\s*(\w+)/);
      if (!serialMatch) return null;

      const serial = serialMatch[1];

      // Derive key from card serial (this should be replaced with proper card operations)
      await sodium.ready;
      return sodium.crypto_generichash(32, sodium.from_string(serial));
    } catch (error) {
      console.debug('OpenPGP card not available or failed:', error);
      return null;
    }
  }

  private async deriveKeyFromPassphrase(passphrase: string, salt?: Uint8Array): Promise<Uint8Array> {
    if (!salt) {
      salt = sodium.randombytes_buf(32);
    }

    // Use Argon2id for secure key derivation
    const derived = await argon2.hash(passphrase, {
      type: argon2.argon2id,
      memory: 65536, // 64 MiB
      time: 3,
      parallelism: 1,
      hashLength: 32,
      salt: Buffer.from(salt),
      raw: true,
    });

    return new Uint8Array(derived);
  }

  private async writeKeystoreEntry(keyId: string, entry: KeystoreEntry): Promise<void> {
    // TODO: Implement secure storage to filesystem
    // This should use platform-specific secure storage when available
    console.log(`Storing keystore entry for: ${keyId}`);
  }

  private async readKeystoreEntry(keyId: string): Promise<KeystoreEntry | null> {
    // TODO: Implement secure retrieval from filesystem
    console.log(`Reading keystore entry for: ${keyId}`);
    return null;
  }
}

// Memory-only keystore for high-security scenarios
export class EphemeralKeystore implements SecureKeystore {
  private keys: Map<string, Uint8Array> = new Map();

  async storeKey(keyId: string, keyData: Uint8Array): Promise<boolean> {
    // Clone the key data to avoid external modification
    const keyCopy = new Uint8Array(keyData);
    this.keys.set(keyId, keyCopy);
    return true;
  }

  async retrieveKey(keyId: string): Promise<Uint8Array | null> {
    const keyData = this.keys.get(keyId);
    if (!keyData) return null;

    // Return a copy to avoid external modification
    return new Uint8Array(keyData);
  }

  async deleteKey(keyId: string): Promise<boolean> {
    const keyData = this.keys.get(keyId);
    if (keyData) {
      // Secure wipe before deletion
      await sodium.ready;
      sodium.memzero(keyData);
      this.keys.delete(keyId);
      return true;
    }
    return false;
  }

  async wipeAllKeys(): Promise<void> {
    await sodium.ready;

    // Secure wipe all keys
    for (const [keyId, keyData] of this.keys) {
      sodium.memzero(keyData);
    }

    this.keys.clear();
    console.log('All ephemeral keys wiped from memory');
  }
}