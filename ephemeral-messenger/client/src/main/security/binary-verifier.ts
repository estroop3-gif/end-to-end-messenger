import * as crypto from 'crypto';
import * as fs from 'fs/promises';
import * as sodium from 'libsodium-wrappers';

export interface BinarySignature {
  signature: string;
  publicKey: string;
  algorithm: string;
  timestamp: number;
}

export class BinaryVerifier {
  private trustedPublicKeys: Set<string> = new Set();

  constructor() {
    this.initializeTrustedKeys();
  }

  private initializeTrustedKeys(): void {
    // TODO: Load these from a secure, immutable source
    // These should be the official signing keys for the application
    const officialSigningKeys = [
      // Ed25519 public key for official builds (placeholder)
      'ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    ];

    officialSigningKeys.forEach(key => this.trustedPublicKeys.add(key));
  }

  async verifyBinarySignature(binaryPath: string): Promise<boolean> {
    try {
      // Calculate binary hash
      const binaryHash = await this.calculateSecureHash(binaryPath);

      // Look for signature file
      const signaturePath = `${binaryPath}.sig`;

      try {
        const signatureData = await fs.readFile(signaturePath, 'utf8');
        const signature: BinarySignature = JSON.parse(signatureData);

        return await this.verifySingleSignature(binaryHash, signature);
      } catch (error) {
        console.warn('No signature file found or invalid format:', error);

        // Fall back to embedded signature check
        return await this.verifyEmbeddedSignature(binaryPath);
      }
    } catch (error) {
      console.error('Binary verification failed:', error);
      return false;
    }
  }

  private async verifySingleSignature(hash: string, signature: BinarySignature): Promise<boolean> {
    // Check if we trust this public key
    if (!this.trustedPublicKeys.has(signature.publicKey)) {
      console.error('Signature from untrusted key:', signature.publicKey);
      return false;
    }

    // Check signature timestamp (prevent replay of old signatures)
    const now = Date.now();
    const maxAge = 365 * 24 * 60 * 60 * 1000; // 1 year
    if (now - signature.timestamp > maxAge) {
      console.error('Signature too old');
      return false;
    }

    try {
      await sodium.ready;

      const publicKeyBytes = sodium.from_base64(signature.publicKey.split(':')[1]);
      const signatureBytes = sodium.from_base64(signature.signature);
      const hashBytes = sodium.from_hex(hash);

      return sodium.crypto_sign_verify_detached(signatureBytes, hashBytes, publicKeyBytes);
    } catch (error) {
      console.error('Signature verification failed:', error);
      return false;
    }
  }

  private async verifyEmbeddedSignature(binaryPath: string): Promise<boolean> {
    // TODO: Check for code signing certificates on the binary
    // This is platform-specific implementation

    if (process.platform === 'win32') {
      return await this.verifyWindowsSignature(binaryPath);
    } else if (process.platform === 'darwin') {
      return await this.verifyMacOSSignature(binaryPath);
    } else {
      // Linux - check for detached signature or GPG signature
      return await this.verifyLinuxSignature(binaryPath);
    }
  }

  private async verifyWindowsSignature(binaryPath: string): Promise<boolean> {
    // TODO: Use Windows API to verify Authenticode signature
    console.warn('Windows signature verification not implemented');
    return false;
  }

  private async verifyMacOSSignature(binaryPath: string): Promise<boolean> {
    // TODO: Use codesign to verify signature
    console.warn('macOS signature verification not implemented');
    return false;
  }

  private async verifyLinuxSignature(binaryPath: string): Promise<boolean> {
    // TODO: Check for GPG signature or use Linux signing infrastructure
    console.warn('Linux signature verification not implemented');
    return false;
  }

  private async calculateSecureHash(filePath: string): Promise<string> {
    const fileBuffer = await fs.readFile(filePath);

    // Use BLAKE2b for cryptographic hash (stronger than SHA256)
    await sodium.ready;
    const hash = sodium.crypto_generichash(32, fileBuffer);

    return sodium.to_hex(hash);
  }

  addTrustedKey(publicKey: string): void {
    if (this.isValidPublicKey(publicKey)) {
      this.trustedPublicKeys.add(publicKey);
      console.log('Added trusted public key:', publicKey.substring(0, 20) + '...');
    } else {
      throw new Error('Invalid public key format');
    }
  }

  private isValidPublicKey(publicKey: string): boolean {
    const parts = publicKey.split(':');
    if (parts.length !== 2) return false;

    const [algorithm, keyData] = parts;
    if (algorithm !== 'ed25519') return false;

    try {
      const keyBytes = sodium.from_base64(keyData);
      return keyBytes.length === sodium.crypto_sign_PUBLICKEYBYTES;
    } catch {
      return false;
    }
  }

  // Create a signature for a binary (development/testing only)
  async createSignature(binaryPath: string, privateKey: string): Promise<BinarySignature> {
    await sodium.ready;

    const hash = await this.calculateSecureHash(binaryPath);
    const privateKeyBytes = sodium.from_base64(privateKey);
    const hashBytes = sodium.from_hex(hash);

    const signature = sodium.crypto_sign_detached(hashBytes, privateKeyBytes);

    return {
      signature: sodium.to_base64(signature),
      publicKey: `ed25519:${sodium.to_base64(sodium.crypto_sign_PUBLICKEYBYTES)}`,
      algorithm: 'ed25519',
      timestamp: Date.now(),
    };
  }
}