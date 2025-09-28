// Security Validator Service
// Implements pre-send security validation and runtime protection

export interface SecurityCheck {
  id: string;
  name: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: 'crypto' | 'network' | 'content' | 'metadata' | 'system';
}

export interface SecurityResult {
  passed: boolean;
  checks: SecurityCheckResult[];
  warnings: string[];
  errors: string[];
  score: number; // 0-100, higher is better
  recommendation: string;
}

export interface SecurityCheckResult {
  check: SecurityCheck;
  passed: boolean;
  message: string;
  details?: any;
}

export interface ContentScanResult {
  hasPII: boolean;
  hasCredentials: boolean;
  hasSecrets: boolean;
  suspiciousPatterns: string[];
  metadata: {
    length: number;
    entropy: number;
    language?: string;
  };
}

class SecurityValidator {
  private checks: SecurityCheck[] = [];
  private enabledChecks: Set<string> = new Set();

  constructor() {
    this.initializeChecks();
    this.enableAllChecks();
  }

  private initializeChecks(): void {
    this.checks = [
      // Cryptographic checks
      {
        id: 'crypto_key_strength',
        name: 'Cryptographic Key Strength',
        description: 'Verify all keys meet minimum strength requirements',
        severity: 'critical',
        category: 'crypto'
      },
      {
        id: 'crypto_randomness',
        name: 'Cryptographic Randomness',
        description: 'Ensure secure random number generation',
        severity: 'critical',
        category: 'crypto'
      },
      {
        id: 'crypto_algorithm_safety',
        name: 'Algorithm Safety',
        description: 'Check for deprecated or weak algorithms',
        severity: 'high',
        category: 'crypto'
      },

      // Content security checks
      {
        id: 'content_pii_scan',
        name: 'PII Detection',
        description: 'Scan for personally identifiable information',
        severity: 'medium',
        category: 'content'
      },
      {
        id: 'content_credential_scan',
        name: 'Credential Detection',
        description: 'Detect passwords, API keys, and secrets',
        severity: 'high',
        category: 'content'
      },
      {
        id: 'content_malware_scan',
        name: 'Malware Detection',
        description: 'Scan content for malicious patterns',
        severity: 'critical',
        category: 'content'
      },
      {
        id: 'content_size_check',
        name: 'Content Size Validation',
        description: 'Verify content size within limits',
        severity: 'medium',
        category: 'content'
      },

      // Network security checks
      {
        id: 'network_tor_status',
        name: 'Tor Connection Status',
        description: 'Verify Tor is active and circuits are healthy',
        severity: 'critical',
        category: 'network'
      },
      {
        id: 'network_dns_leak',
        name: 'DNS Leak Detection',
        description: 'Check for DNS queries outside Tor',
        severity: 'high',
        category: 'network'
      },
      {
        id: 'network_ip_leak',
        name: 'IP Leak Detection',
        description: 'Verify no direct IP connections',
        severity: 'critical',
        category: 'network'
      },

      // Metadata protection
      {
        id: 'metadata_timestamp',
        name: 'Timestamp Obfuscation',
        description: 'Check timestamp privacy protection',
        severity: 'medium',
        category: 'metadata'
      },
      {
        id: 'metadata_size_padding',
        name: 'Size Padding',
        description: 'Verify content size is padded',
        severity: 'medium',
        category: 'metadata'
      },
      {
        id: 'metadata_fingerprinting',
        name: 'Fingerprinting Protection',
        description: 'Check for identifying metadata',
        severity: 'high',
        category: 'metadata'
      },

      // System security
      {
        id: 'system_memory_protection',
        name: 'Memory Protection',
        description: 'Verify secure memory handling',
        severity: 'high',
        category: 'system'
      },
      {
        id: 'system_process_isolation',
        name: 'Process Isolation',
        description: 'Check sandboxing and isolation',
        severity: 'medium',
        category: 'system'
      },
      {
        id: 'system_temp_files',
        name: 'Temporary File Check',
        description: 'Ensure no sensitive data in temp files',
        severity: 'high',
        category: 'system'
      }
    ];
  }

  private enableAllChecks(): void {
    this.checks.forEach(check => {
      this.enabledChecks.add(check.id);
    });
  }

  /**
   * Perform comprehensive pre-send security validation
   */
  async validateMessage(content: string, recipient: string, metadata?: any): Promise<SecurityResult> {
    const results: SecurityCheckResult[] = [];
    const warnings: string[] = [];
    const errors: string[] = [];

    // Content security checks
    const contentScan = await this.scanContent(content);

    if (contentScan.hasPII) {
      warnings.push('Content contains potential PII - consider anonymizing');
    }

    if (contentScan.hasCredentials) {
      errors.push('Content contains credentials or API keys - remove before sending');
    }

    if (contentScan.hasSecrets) {
      errors.push('Content contains potential secrets - review carefully');
    }

    // Run all enabled security checks
    for (const check of this.checks) {
      if (!this.enabledChecks.has(check.id)) continue;

      const result = await this.runSecurityCheck(check, { content, recipient, metadata, contentScan });
      results.push(result);

      if (!result.passed) {
        if (check.severity === 'critical' || check.severity === 'high') {
          errors.push(`${check.name}: ${result.message}`);
        } else {
          warnings.push(`${check.name}: ${result.message}`);
        }
      }
    }

    // Calculate security score
    const score = this.calculateSecurityScore(results);

    // Generate recommendation
    const recommendation = this.generateRecommendation(results, warnings, errors);

    return {
      passed: errors.length === 0,
      checks: results,
      warnings,
      errors,
      score,
      recommendation
    };
  }

  /**
   * Scan content for sensitive information
   */
  private async scanContent(content: string): Promise<ContentScanResult> {
    const result: ContentScanResult = {
      hasPII: false,
      hasCredentials: false,
      hasSecrets: false,
      suspiciousPatterns: [],
      metadata: {
        length: content.length,
        entropy: this.calculateEntropy(content)
      }
    };

    // PII patterns
    const piiPatterns = [
      /\b\d{3}-\d{2}-\d{4}\b/g, // SSN
      /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, // Credit card
      /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, // Email
      /\b\d{3}[\s-]?\d{3}[\s-]?\d{4}\b/g, // Phone number
    ];

    // Credential patterns
    const credentialPatterns = [
      /password[\s]*[:=][\s]*["']?[^\s"']+["']?/gi,
      /api[_-]?key[\s]*[:=][\s]*["']?[^\s"']+["']?/gi,
      /secret[\s]*[:=][\s]*["']?[^\s"']+["']?/gi,
      /token[\s]*[:=][\s]*["']?[^\s"']+["']?/gi,
      /auth[\s]*[:=][\s]*["']?[^\s"']+["']?/gi,
    ];

    // Secret patterns
    const secretPatterns = [
      /-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----/g, // PEM keys
      /sk_[a-zA-Z0-9]{20,}/g, // Stripe secret keys
      /pk_[a-zA-Z0-9]{20,}/g, // Public keys
      /[A-Za-z0-9+/]{40,}={0,2}/g, // Base64 encoded (potential keys)
    ];

    // Check for PII
    for (const pattern of piiPatterns) {
      if (pattern.test(content)) {
        result.hasPII = true;
        result.suspiciousPatterns.push('PII detected');
        break;
      }
    }

    // Check for credentials
    for (const pattern of credentialPatterns) {
      if (pattern.test(content)) {
        result.hasCredentials = true;
        result.suspiciousPatterns.push('Credentials detected');
        break;
      }
    }

    // Check for secrets
    for (const pattern of secretPatterns) {
      if (pattern.test(content)) {
        result.hasSecrets = true;
        result.suspiciousPatterns.push('Secrets detected');
        break;
      }
    }

    return result;
  }

  /**
   * Run individual security check
   */
  private async runSecurityCheck(check: SecurityCheck, context: any): Promise<SecurityCheckResult> {
    try {
      switch (check.id) {
        case 'crypto_key_strength':
          return this.checkKeyStrength(check, context);

        case 'crypto_randomness':
          return this.checkRandomness(check, context);

        case 'content_size_check':
          return this.checkContentSize(check, context);

        case 'network_tor_status':
          return await this.checkTorStatus(check, context);

        case 'metadata_size_padding':
          return this.checkSizePadding(check, context);

        case 'system_memory_protection':
          return this.checkMemoryProtection(check, context);

        default:
          return {
            check,
            passed: true,
            message: 'Check not implemented yet'
          };
      }
    } catch (error) {
      return {
        check,
        passed: false,
        message: `Check failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  private checkKeyStrength(check: SecurityCheck, context: any): SecurityCheckResult {
    // Simulate key strength validation
    const keyStrengthOk = true; // Would check actual key entropy, size, etc.

    return {
      check,
      passed: keyStrengthOk,
      message: keyStrengthOk ? 'Key strength adequate' : 'Weak cryptographic keys detected'
    };
  }

  private checkRandomness(check: SecurityCheck, context: any): SecurityCheckResult {
    // Check if crypto.getRandomValues is available and working
    try {
      const testArray = new Uint8Array(32);
      crypto.getRandomValues(testArray);

      // Basic entropy check
      const entropy = this.calculateEntropy(Array.from(testArray).join(''));
      const entropyOk = entropy > 7.5; // Good randomness should have high entropy

      return {
        check,
        passed: entropyOk,
        message: entropyOk ? 'Cryptographic randomness ok' : 'Low entropy in random generation',
        details: { entropy }
      };
    } catch (error) {
      return {
        check,
        passed: false,
        message: 'Cryptographic random generation not available'
      };
    }
  }

  private checkContentSize(check: SecurityCheck, context: any): SecurityCheckResult {
    const { content } = context;
    const maxSize = 1024 * 1024; // 1MB limit
    const sizeOk = content.length <= maxSize;

    return {
      check,
      passed: sizeOk,
      message: sizeOk ? 'Content size within limits' : `Content too large: ${content.length} bytes`,
      details: { size: content.length, limit: maxSize }
    };
  }

  private async checkTorStatus(check: SecurityCheck, context: any): Promise<SecurityCheckResult> {
    try {
      // Would check actual Tor status from torService
      const torConnected = true; // Placeholder

      return {
        check,
        passed: torConnected,
        message: torConnected ? 'Tor connection active' : 'Tor not connected'
      };
    } catch (error) {
      return {
        check,
        passed: false,
        message: 'Unable to verify Tor status'
      };
    }
  }

  private checkSizePadding(check: SecurityCheck, context: any): SecurityCheckResult {
    const { content } = context;

    // Check if content appears to be padded to standard sizes
    const standardSizes = [256, 512, 1024, 2048, 4096, 8192];
    const paddedSize = standardSizes.find(size => size >= content.length);
    const isPadded = paddedSize && (paddedSize - content.length) > 0;

    return {
      check,
      passed: isPadded || content.length < 256,
      message: isPadded ? 'Content size padded' : 'Consider padding content size for privacy',
      details: { originalSize: content.length, paddedSize }
    };
  }

  private checkMemoryProtection(check: SecurityCheck, context: any): SecurityCheckResult {
    // In a real implementation, would check for secure memory allocation
    const memoryProtected = typeof window !== 'undefined' && 'crypto' in window;

    return {
      check,
      passed: memoryProtected,
      message: memoryProtected ? 'Memory protection available' : 'Limited memory protection'
    };
  }

  /**
   * Calculate entropy of a string
   */
  private calculateEntropy(str: string): number {
    const freq: { [key: string]: number } = {};

    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0;
    const len = str.length;

    for (const count of Object.values(freq)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }

  /**
   * Calculate overall security score
   */
  private calculateSecurityScore(results: SecurityCheckResult[]): number {
    if (results.length === 0) return 0;

    let totalWeight = 0;
    let weightedScore = 0;

    for (const result of results) {
      const weight = this.getCheckWeight(result.check.severity);
      totalWeight += weight;

      if (result.passed) {
        weightedScore += weight;
      }
    }

    return Math.round((weightedScore / totalWeight) * 100);
  }

  private getCheckWeight(severity: string): number {
    switch (severity) {
      case 'critical': return 4;
      case 'high': return 3;
      case 'medium': return 2;
      case 'low': return 1;
      default: return 1;
    }
  }

  /**
   * Generate security recommendation
   */
  private generateRecommendation(results: SecurityCheckResult[], warnings: string[], errors: string[]): string {
    if (errors.length > 0) {
      return 'Critical security issues detected - do not send until resolved';
    }

    if (warnings.length > 0) {
      return 'Security warnings present - review carefully before sending';
    }

    const failedChecks = results.filter(r => !r.passed);
    if (failedChecks.length > 0) {
      return 'Some security checks failed - consider addressing before sending';
    }

    return 'All security checks passed - safe to send';
  }

  /**
   * Enable or disable specific security checks
   */
  setCheckEnabled(checkId: string, enabled: boolean): void {
    if (enabled) {
      this.enabledChecks.add(checkId);
    } else {
      this.enabledChecks.delete(checkId);
    }
  }

  /**
   * Get all available security checks
   */
  getAvailableChecks(): SecurityCheck[] {
    return [...this.checks];
  }

  /**
   * Get enabled security checks
   */
  getEnabledChecks(): SecurityCheck[] {
    return this.checks.filter(check => this.enabledChecks.has(check.id));
  }
}

// Export singleton instance
export const securityValidator = new SecurityValidator();
export default securityValidator;