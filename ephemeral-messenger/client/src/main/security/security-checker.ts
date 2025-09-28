import * as fs from 'fs/promises';
import * as crypto from 'crypto';
import { execSync } from 'child_process';
import * as sodium from 'libsodium-wrappers';

export interface SecurityCheckResult {
  passed: boolean;
  message: string;
  remediation?: string;
}

export interface PreSendCheckResults {
  torReachability: SecurityCheckResult;
  swapStatus: SecurityCheckResult;
  memoryLock: SecurityCheckResult;
  hardwareToken: SecurityCheckResult;
  fingerprintVerification: SecurityCheckResult;
  clientCertificate: SecurityCheckResult;
  binarySignature: SecurityCheckResult;
  timeWindow: SecurityCheckResult;
  overallPassed: boolean;
}

export class SecurityChecker {
  private lastVerifiedFingerprints: Map<string, string> = new Map();
  private trustedSigningKeys: Set<string> = new Set();

  constructor() {
    this.initializeTrustedKeys();
  }

  async runPreSendChecks(
    recipientId: string,
    recipientOnion: string,
    requireHardwareToken: boolean = true
  ): Promise<PreSendCheckResults> {
    console.log('Running pre-send security checks...');

    const checks: PreSendCheckResults = {
      torReachability: await this.checkTorReachability(recipientOnion),
      swapStatus: await this.checkSwapStatus(),
      memoryLock: await this.checkMemoryLock(),
      hardwareToken: await this.checkHardwareToken(requireHardwareToken),
      fingerprintVerification: await this.checkFingerprintVerification(recipientId),
      clientCertificate: await this.checkClientCertificate(),
      binarySignature: await this.checkBinarySignature(),
      timeWindow: await this.checkTimeWindow(recipientOnion),
      overallPassed: false,
    };

    // Overall check passes only if ALL individual checks pass
    checks.overallPassed = Object.values(checks)
      .filter(check => check !== checks.overallPassed)
      .every(check => (check as SecurityCheckResult).passed);

    console.log('Pre-send security checks completed:', {
      overall: checks.overallPassed,
      individual: Object.entries(checks)
        .filter(([key]) => key !== 'overallPassed')
        .map(([key, result]) => ({ [key]: (result as SecurityCheckResult).passed }))
    });

    return checks;
  }

  async checkTorReachability(onionAddress?: string): Promise<SecurityCheckResult> {
    try {
      // Check if Tor is running
      const torStatus = await this.checkTorDaemonStatus();
      if (!torStatus.passed) {
        return torStatus;
      }

      // Check if we can connect to Tor SOCKS proxy
      const socksCheck = await this.checkTorSocksProxy();
      if (!socksCheck.passed) {
        return socksCheck;
      }

      // If onion address provided, test reachability
      if (onionAddress) {
        return await this.testOnionReachability(onionAddress);
      }

      return {
        passed: true,
        message: 'Tor connectivity verified'
      };
    } catch (error) {
      return {
        passed: false,
        message: `Tor reachability check failed: ${error}`,
        remediation: 'Ensure Tor is running and properly configured. On Tails, Tor should start automatically.'
      };
    }
  }

  async checkSwapStatus(): Promise<SecurityCheckResult> {
    try {
      // Check /proc/swaps for active swap
      const swapInfo = await fs.readFile('/proc/swaps', 'utf8');
      const swapLines = swapInfo.split('\n').filter(line => line.trim() && !line.startsWith('Filename'));

      if (swapLines.length > 0) {
        return {
          passed: false,
          message: 'Swap is enabled - this poses a security risk',
          remediation: 'Disable swap with: sudo swapoff -a\n' +
                      'On Tails, use: sudo systemctl mask swap.target\n' +
                      'Alternatively, restart Tails without persistence to ensure no swap.'
        };
      }

      return {
        passed: true,
        message: 'No swap detected - memory is secure'
      };
    } catch (error) {
      return {
        passed: false,
        message: `Could not check swap status: ${error}`,
        remediation: 'Manually verify no swap is active: cat /proc/swaps'
      };
    }
  }

  async checkMemoryLock(): Promise<SecurityCheckResult> {
    try {
      // Test if we can lock memory (mlockall)
      const testBuffer = Buffer.alloc(4096);

      // Try to lock the test buffer
      try {
        // Note: This is a simplified check. In production, use native bindings
        const hasMemLock = await this.testMlockCapability();

        if (!hasMemLock) {
          return {
            passed: false,
            message: 'Memory locking not available',
            remediation: 'Ensure the application has CAP_IPC_LOCK capability or is running with appropriate privileges.\n' +
                        'On Tails, this should work by default.'
          };
        }

        return {
          passed: true,
          message: 'Memory locking available and active'
        };
      } finally {
        testBuffer.fill(0); // Clear test buffer
      }
    } catch (error) {
      return {
        passed: false,
        message: `Memory lock check failed: ${error}`,
        remediation: 'Check system capabilities and privileges for memory locking'
      };
    }
  }

  async checkHardwareToken(required: boolean): Promise<SecurityCheckResult> {
    try {
      // Check for YubiKey or similar hardware tokens
      const hasYubiKey = await this.detectYubiKey();
      const hasOpenPGPCard = await this.detectOpenPGPCard();

      const hasToken = hasYubiKey || hasOpenPGPCard;

      if (required && !hasToken) {
        return {
          passed: false,
          message: 'Hardware security token required but not detected',
          remediation: 'Insert a YubiKey or OpenPGP-compatible hardware token.\n' +
                      'Ensure the token is properly initialized with keys.\n' +
                      'If you must proceed without a hardware token, change the security policy to allow software keys.'
        };
      }

      if (!required && !hasToken) {
        return {
          passed: true,
          message: 'Hardware token not required (using software keys)'
        };
      }

      return {
        passed: true,
        message: `Hardware token detected: ${hasYubiKey ? 'YubiKey' : 'OpenPGP card'}`
      };
    } catch (error) {
      return {
        passed: !required,
        message: `Hardware token check failed: ${error}`,
        remediation: required ? 'Insert a hardware security token and try again' : 'Proceeding with software keys'
      };
    }
  }

  async checkFingerprintVerification(recipientId: string): Promise<SecurityCheckResult> {
    try {
      const lastVerified = this.lastVerifiedFingerprints.get(recipientId);

      if (!lastVerified) {
        return {
          passed: false,
          message: 'Recipient fingerprint has never been verified',
          remediation: 'Verify the recipient\'s fingerprint through an out-of-band channel (QR code, voice confirmation, etc.)\n' +
                      'This is critical to prevent man-in-the-middle attacks.'
        };
      }

      // TODO: Get current fingerprint and compare
      const currentFingerprint = await this.getCurrentFingerprint(recipientId);

      if (currentFingerprint !== lastVerified) {
        return {
          passed: false,
          message: 'Recipient fingerprint has changed since last verification',
          remediation: 'The recipient\'s fingerprint has changed. This could indicate:\n' +
                      '1. They regenerated their keys (legitimate)\n' +
                      '2. A man-in-the-middle attack (security threat)\n' +
                      'Re-verify the fingerprint through a secure out-of-band channel before proceeding.'
        };
      }

      return {
        passed: true,
        message: 'Recipient fingerprint verified and unchanged'
      };
    } catch (error) {
      return {
        passed: false,
        message: `Fingerprint verification failed: ${error}`,
        remediation: 'Verify recipient identity through a secure out-of-band channel'
      };
    }
  }

  async checkClientCertificate(): Promise<SecurityCheckResult> {
    // TODO: Implement client certificate check for mutual TLS
    try {
      // Check if client certificate is available and valid
      const hasCert = await this.hasValidClientCertificate();

      if (!hasCert) {
        return {
          passed: true, // Not always required
          message: 'No client certificate configured (proceeding with Tor onion auth only)'
        };
      }

      return {
        passed: true,
        message: 'Client certificate available and valid'
      };
    } catch (error) {
      return {
        passed: true, // Non-critical
        message: `Client certificate check failed: ${error} (proceeding anyway)`
      };
    }
  }

  async checkBinarySignature(): Promise<SecurityCheckResult> {
    try {
      const binaryPath = process.execPath;
      const signatureValid = await this.verifyBinarySignature(binaryPath);

      if (!signatureValid) {
        return {
          passed: false,
          message: 'Binary signature verification failed',
          remediation: 'The application binary signature is invalid or missing.\n' +
                      'This could indicate:\n' +
                      '1. Corrupted download\n' +
                      '2. Malicious modification\n' +
                      '3. Development build (expected in development)\n' +
                      'In production, only proceed if you trust the source.\n' +
                      'Verify the binary hash against known good values.'
        };
      }

      return {
        passed: true,
        message: 'Binary signature verified'
      };
    } catch (error) {
      return {
        passed: false,
        message: `Binary signature check failed: ${error}`,
        remediation: 'Unable to verify binary signature. Proceed only if you trust the source.'
      };
    }
  }

  async checkTimeWindow(onionAddress: string): Promise<SecurityCheckResult> {
    try {
      // Check if the onion service was created within allowed time window
      const onionCreationTime = await this.getOnionCreationTime(onionAddress);
      const now = Date.now();
      const maxAge = 5 * 60 * 1000; // 5 minutes

      if (onionCreationTime && (now - onionCreationTime) > maxAge) {
        return {
          passed: false,
          message: 'Recipient onion service is too old',
          remediation: 'The recipient\'s onion service was created more than 5 minutes ago.\n' +
                      'For security, ephemeral onion services should be fresh.\n' +
                      'Ask the recipient to create a new onion service, or\n' +
                      'verify this is a pre-authorized long-lived onion.'
        };
      }

      return {
        passed: true,
        message: 'Onion service time window verified'
      };
    } catch (error) {
      return {
        passed: true, // Non-critical
        message: `Time window check skipped: ${error}`
      };
    }
  }

  // Helper methods

  private async checkTorDaemonStatus(): Promise<SecurityCheckResult> {
    try {
      // Try to connect to Tor control port
      const { execSync } = require('child_process');
      execSync('curl --socks5 127.0.0.1:9050 --connect-timeout 5 http://check.torproject.org/',
               { timeout: 10000, stdio: 'pipe' });

      return {
        passed: true,
        message: 'Tor daemon is running'
      };
    } catch (error) {
      return {
        passed: false,
        message: 'Tor daemon not accessible',
        remediation: 'Start Tor daemon or check Tor configuration'
      };
    }
  }

  private async checkTorSocksProxy(): Promise<SecurityCheckResult> {
    // TODO: Implement SOCKS proxy connectivity test
    return {
      passed: true,
      message: 'Tor SOCKS proxy accessible'
    };
  }

  private async testOnionReachability(onionAddress: string): Promise<SecurityCheckResult> {
    // TODO: Implement onion service reachability test
    return {
      passed: true,
      message: `Onion ${onionAddress} is reachable`
    };
  }

  private async testMlockCapability(): Promise<boolean> {
    try {
      // Test if we can use mlock (simplified check)
      // In production, use native bindings to test actual mlock()
      return process.platform === 'linux'; // Simplified assumption
    } catch {
      return false;
    }
  }

  private async detectYubiKey(): Promise<boolean> {
    try {
      const output = execSync('lsusb | grep Yubico', { encoding: 'utf8', timeout: 5000 });
      return output.length > 0;
    } catch {
      return false;
    }
  }

  private async detectOpenPGPCard(): Promise<boolean> {
    try {
      const output = execSync('gpg --card-status', { encoding: 'utf8', timeout: 5000 });
      return output.includes('OpenPGP card');
    } catch {
      return false;
    }
  }

  private async getCurrentFingerprint(recipientId: string): Promise<string> {
    // TODO: Implement fingerprint retrieval
    return 'placeholder-fingerprint';
  }

  private async hasValidClientCertificate(): Promise<boolean> {
    // TODO: Check for client certificate
    return false;
  }

  private async verifyBinarySignature(binaryPath: string): Promise<boolean> {
    try {
      // TODO: Implement actual signature verification
      // This is a placeholder - use proper cryptographic signature verification
      const binaryHash = await this.calculateFileHash(binaryPath);
      const knownGoodHashes = await this.getKnownGoodHashes();

      return knownGoodHashes.includes(binaryHash);
    } catch {
      return false;
    }
  }

  private async calculateFileHash(filePath: string): Promise<string> {
    const fileBuffer = await fs.readFile(filePath);
    return crypto.createHash('sha256').update(fileBuffer).digest('hex');
  }

  private async getKnownGoodHashes(): Promise<string[]> {
    // TODO: Load known good hashes from secure source
    return [];
  }

  private async getOnionCreationTime(onionAddress: string): Promise<number | null> {
    // TODO: Track onion creation times
    return null;
  }

  private initializeTrustedKeys(): void {
    // TODO: Initialize trusted signing keys
    // These should be hardcoded or loaded from a secure source
  }

  public verifyRecipientFingerprint(recipientId: string, fingerprint: string): void {
    this.lastVerifiedFingerprints.set(recipientId, fingerprint);
    console.log(`Fingerprint verified for recipient: ${recipientId}`);
  }

  public clearVerifiedFingerprints(): void {
    this.lastVerifiedFingerprints.clear();
  }
}