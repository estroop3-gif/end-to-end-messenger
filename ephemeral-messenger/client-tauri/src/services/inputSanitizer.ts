// Input Sanitization Service
// Provides comprehensive input validation and sanitization

export interface SanitizationConfig {
  maxStringLength: number;
  maxDocumentSize: number;
  allowedFileTypes: string[];
  stripHTML: boolean;
  preventXSS: boolean;
  validateUnicode: boolean;
}

export interface SanitizationResult {
  original: string;
  sanitized: string;
  issues: string[];
  safe: boolean;
  modified: boolean;
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  sanitized?: any;
}

class InputSanitizer {
  private config: SanitizationConfig;

  constructor() {
    this.config = {
      maxStringLength: 100000, // 100KB
      maxDocumentSize: 10 * 1024 * 1024, // 10MB
      allowedFileTypes: ['.txt', '.md', '.pdf', '.docx', '.securedoc'],
      stripHTML: true,
      preventXSS: true,
      validateUnicode: true,
    };
  }

  /**
   * Sanitize text input with comprehensive security checks
   */
  sanitizeText(input: string): SanitizationResult {
    const issues: string[] = [];
    let sanitized = input;
    let safe = true;

    // Length check
    if (input.length > this.config.maxStringLength) {
      issues.push(`Text too long: ${input.length} chars (max: ${this.config.maxStringLength})`);
      sanitized = input.substring(0, this.config.maxStringLength);
      safe = false;
    }

    // Unicode validation
    if (this.config.validateUnicode) {
      const unicodeIssues = this.validateUnicode(sanitized);
      if (unicodeIssues.length > 0) {
        issues.push(...unicodeIssues);
        sanitized = this.removeInvalidUnicode(sanitized);
        safe = false;
      }
    }

    // XSS prevention
    if (this.config.preventXSS) {
      const xssResult = this.preventXSS(sanitized);
      if (xssResult.detected) {
        issues.push('Potential XSS detected');
        sanitized = xssResult.cleaned;
        safe = false;
      }
    }

    // HTML stripping
    if (this.config.stripHTML) {
      const htmlStripped = this.stripHTML(sanitized);
      if (htmlStripped !== sanitized) {
        issues.push('HTML tags removed');
        sanitized = htmlStripped;
      }
    }

    // Control character removal
    const controlCleaned = this.removeControlCharacters(sanitized);
    if (controlCleaned !== sanitized) {
      issues.push('Control characters removed');
      sanitized = controlCleaned;
    }

    // Null byte removal
    const nullCleaned = this.removeNullBytes(sanitized);
    if (nullCleaned !== sanitized) {
      issues.push('Null bytes removed');
      sanitized = nullCleaned;
      safe = false;
    }

    return {
      original: input,
      sanitized,
      issues,
      safe,
      modified: sanitized !== input,
    };
  }

  /**
   * Validate and sanitize JSON input
   */
  sanitizeJSON(input: string): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      // Basic validation
      if (input.length > this.config.maxStringLength) {
        errors.push(`JSON too large: ${input.length} bytes`);
        return { valid: false, errors, warnings };
      }

      // Parse JSON
      const parsed = JSON.parse(input);

      // Deep sanitize object
      const sanitized = this.deepSanitizeObject(parsed);

      // Check for dangerous patterns
      const dangerousPatterns = this.checkDangerousPatterns(JSON.stringify(sanitized));
      if (dangerousPatterns.length > 0) {
        warnings.push(...dangerousPatterns);
      }

      return {
        valid: true,
        errors,
        warnings,
        sanitized,
      };
    } catch (error) {
      errors.push(`Invalid JSON: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return { valid: false, errors, warnings };
    }
  }

  /**
   * Validate file uploads
   */
  validateFile(file: File): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Size check
    if (file.size > this.config.maxDocumentSize) {
      errors.push(`File too large: ${file.size} bytes (max: ${this.config.maxDocumentSize})`);
    }

    // Type check
    const extension = '.' + file.name.split('.').pop()?.toLowerCase();
    if (!this.config.allowedFileTypes.includes(extension)) {
      errors.push(`File type not allowed: ${extension}`);
    }

    // Name validation
    if (!this.validateFilename(file.name)) {
      errors.push('Invalid filename');
    }

    // Check for suspicious patterns in filename
    if (this.hasSuspiciousFilename(file.name)) {
      warnings.push('Suspicious filename pattern detected');
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Validate cryptographic identifiers
   */
  validateCryptoID(id: string, type: 'fingerprint' | 'messageId' | 'sessionId'): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    switch (type) {
      case 'fingerprint':
        if (!/^[0-9a-fA-F]{64}$/.test(id)) {
          errors.push('Invalid fingerprint format (must be 64 hex characters)');
        }
        break;

      case 'messageId':
        if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(id)) {
          errors.push('Invalid message ID format (must be UUID)');
        }
        break;

      case 'sessionId':
        if (!/^[0-9a-fA-F]{32}$/.test(id)) {
          errors.push('Invalid session ID format (must be 32 hex characters)');
        }
        break;
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Sanitize and validate URLs
   */
  sanitizeURL(url: string): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      const parsed = new URL(url);

      // Protocol validation
      const allowedProtocols = ['http:', 'https:', 'ws:', 'wss:'];
      if (!allowedProtocols.includes(parsed.protocol)) {
        errors.push(`Unsupported protocol: ${parsed.protocol}`);
      }

      // Check for suspicious patterns
      if (this.hasSuspiciousURLPatterns(url)) {
        warnings.push('Suspicious URL patterns detected');
      }

      // Onion address validation
      if (parsed.hostname.endsWith('.onion')) {
        if (!this.validateOnionAddress(parsed.hostname)) {
          errors.push('Invalid onion address format');
        }
      }

      return {
        valid: errors.length === 0,
        errors,
        warnings,
        sanitized: parsed.toString(),
      };
    } catch (error) {
      errors.push('Invalid URL format');
      return { valid: false, errors, warnings };
    }
  }

  /**
   * Validate onion address format
   */
  private validateOnionAddress(hostname: string): boolean {
    // v3 onion address: 56 characters + .onion
    const v3Pattern = /^[a-z2-7]{56}\.onion$/;
    return v3Pattern.test(hostname);
  }

  /**
   * Check for suspicious URL patterns
   */
  private hasSuspiciousURLPatterns(url: string): boolean {
    const suspiciousPatterns = [
      /\.\./,                    // Directory traversal
      /%2e%2e/i,                // Encoded directory traversal
      /%00/,                    // Null byte
      /javascript:/i,           // JavaScript protocol
      /vbscript:/i,            // VBScript protocol
      /data:/i,                // Data protocol
      /file:/i,                // File protocol
      /<script/i,              // Script tags
      /onclick|onload|onerror/i, // Event handlers
    ];

    return suspiciousPatterns.some(pattern => pattern.test(url));
  }

  /**
   * Deep sanitize object recursively
   */
  private deepSanitizeObject(obj: any): any {
    if (typeof obj === 'string') {
      return this.sanitizeText(obj).sanitized;
    }

    if (Array.isArray(obj)) {
      return obj.map(item => this.deepSanitizeObject(item));
    }

    if (obj !== null && typeof obj === 'object') {
      const sanitized: any = {};
      for (const [key, value] of Object.entries(obj)) {
        const sanitizedKey = this.sanitizeText(key).sanitized;
        sanitized[sanitizedKey] = this.deepSanitizeObject(value);
      }
      return sanitized;
    }

    return obj;
  }

  /**
   * Check for dangerous patterns in data
   */
  private checkDangerousPatterns(data: string): string[] {
    const patterns: { pattern: RegExp; message: string }[] = [
      { pattern: /password|secret|key|token/i, message: 'Contains potential credentials' },
      { pattern: /\b\d{3}-\d{2}-\d{4}\b/, message: 'Contains potential SSN' },
      { pattern: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/, message: 'Contains potential credit card' },
      { pattern: /-----BEGIN [A-Z ]+-----/, message: 'Contains potential private key' },
      { pattern: /<script|javascript:/i, message: 'Contains potential XSS' },
      { pattern: /eval\s*\(|setTimeout\s*\(|setInterval\s*\(/i, message: 'Contains potential code injection' },
    ];

    return patterns
      .filter(({ pattern }) => pattern.test(data))
      .map(({ message }) => message);
  }

  /**
   * Validate Unicode characters
   */
  private validateUnicode(text: string): string[] {
    const issues: string[] = [];

    for (let i = 0; i < text.length; i++) {
      const char = text.charAt(i);
      const code = text.charCodeAt(i);

      // Check for control characters (except newline, tab, carriage return)
      if (code < 32 && code !== 9 && code !== 10 && code !== 13) {
        issues.push(`Control character at position ${i}: U+${code.toString(16).padStart(4, '0')}`);
      }

      // Check for surrogate pairs
      if (code >= 0xD800 && code <= 0xDFFF) {
        if (code >= 0xD800 && code <= 0xDBFF) {
          // High surrogate
          if (i + 1 >= text.length || text.charCodeAt(i + 1) < 0xDC00 || text.charCodeAt(i + 1) > 0xDFFF) {
            issues.push(`Invalid high surrogate at position ${i}`);
          }
        } else {
          // Low surrogate
          if (i === 0 || text.charCodeAt(i - 1) < 0xD800 || text.charCodeAt(i - 1) > 0xDBFF) {
            issues.push(`Invalid low surrogate at position ${i}`);
          }
        }
      }
    }

    return issues;
  }

  /**
   * Remove invalid Unicode characters
   */
  private removeInvalidUnicode(text: string): string {
    return text.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
  }

  /**
   * Prevent XSS attacks
   */
  private preventXSS(text: string): { cleaned: string; detected: boolean } {
    const xssPatterns = [
      /<script[^>]*>.*?<\/script>/gi,
      /javascript:/gi,
      /vbscript:/gi,
      /onload\s*=/gi,
      /onerror\s*=/gi,
      /onclick\s*=/gi,
      /onmouseover\s*=/gi,
      /<iframe[^>]*>/gi,
      /<object[^>]*>/gi,
      /<embed[^>]*>/gi,
    ];

    let cleaned = text;
    let detected = false;

    for (const pattern of xssPatterns) {
      if (pattern.test(cleaned)) {
        detected = true;
        cleaned = cleaned.replace(pattern, '');
      }
    }

    return { cleaned, detected };
  }

  /**
   * Strip HTML tags
   */
  private stripHTML(text: string): string {
    return text.replace(/<[^>]*>/g, '');
  }

  /**
   * Remove control characters
   */
  private removeControlCharacters(text: string): string {
    return text.replace(/[\x00-\x1F\x7F]/g, '');
  }

  /**
   * Remove null bytes
   */
  private removeNullBytes(text: string): string {
    return text.replace(/\x00/g, '');
  }

  /**
   * Validate filename
   */
  private validateFilename(filename: string): boolean {
    // Check for valid characters
    const validPattern = /^[a-zA-Z0-9._-]+$/;
    if (!validPattern.test(filename)) {
      return false;
    }

    // Check length
    if (filename.length > 255) {
      return false;
    }

    // Check for reserved names (Windows)
    const reservedNames = [
      'CON', 'PRN', 'AUX', 'NUL',
      'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
      'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
    ];

    const nameWithoutExt = filename.split('.')[0].toUpperCase();
    if (reservedNames.includes(nameWithoutExt)) {
      return false;
    }

    return true;
  }

  /**
   * Check for suspicious filename patterns
   */
  private hasSuspiciousFilename(filename: string): boolean {
    const suspiciousPatterns = [
      /\.(exe|bat|cmd|com|pif|scr|vbs|js|jar|ps1)$/i, // Executable files
      /^\./,                                          // Hidden files
      /[<>:"/\\|?*]/,                                // Invalid characters
      /\.{2,}/,                                      // Multiple dots
      /\s{2,}/,                                      // Multiple spaces
    ];

    return suspiciousPatterns.some(pattern => pattern.test(filename));
  }

  /**
   * Configure sanitization settings
   */
  configure(config: Partial<SanitizationConfig>): void {
    this.config = { ...this.config, ...config };
  }

  /**
   * Get current configuration
   */
  getConfig(): SanitizationConfig {
    return { ...this.config };
  }
}

// Export singleton instance
export const inputSanitizer = new InputSanitizer();
export default inputSanitizer;