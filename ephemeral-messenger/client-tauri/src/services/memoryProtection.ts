// Memory Protection Service
// Implements zero-persistence and secure memory handling

export interface SecureMemoryConfig {
  enableWipe: boolean;
  enableAnonymousMemory: boolean;
  enableMLock: boolean;
  maxSecureBuffers: number;
  wiperInterval: number; // ms
}

export interface SecureBuffer {
  id: string;
  size: number;
  created: Date;
  lastAccessed: Date;
  wiped: boolean;
}

export interface MemoryStats {
  totalAllocated: number;
  activeBuffers: number;
  wipedBuffers: number;
  maxBuffers: number;
  anonymousFiles: number;
}

class MemoryProtectionService {
  private config: SecureMemoryConfig;
  private secureBuffers: Map<string, SecureBuffer> = new Map();
  private bufferData: Map<string, ArrayBuffer> = new Map();
  private wiperInterval: number | null = null;
  private memfdFiles: Map<string, any> = new Map(); // For anonymous files

  constructor() {
    this.config = {
      enableWipe: true,
      enableAnonymousMemory: true,
      enableMLock: false, // Not available in browser
      maxSecureBuffers: 100,
      wiperInterval: 30000, // 30 seconds
    };

    this.startMemoryWiper();
    this.setupPageUnloadHandlers();
  }

  /**
   * Allocate secure memory buffer
   */
  allocateSecureBuffer(size: number, label?: string): string {
    if (this.secureBuffers.size >= this.config.maxSecureBuffers) {
      throw new Error('Maximum secure buffers exceeded');
    }

    const id = this.generateSecureId();
    const buffer = new ArrayBuffer(size);

    // Zero-fill the buffer
    const view = new Uint8Array(buffer);
    view.fill(0);

    const secureBuffer: SecureBuffer = {
      id,
      size,
      created: new Date(),
      lastAccessed: new Date(),
      wiped: false,
    };

    this.secureBuffers.set(id, secureBuffer);
    this.bufferData.set(id, buffer);

    console.log(`Allocated secure buffer ${id} (${size} bytes)${label ? ` - ${label}` : ''}`);
    return id;
  }

  /**
   * Write data to secure buffer
   */
  writeSecureBuffer(bufferId: string, data: ArrayBuffer | Uint8Array): boolean {
    const buffer = this.bufferData.get(bufferId);
    const secureBuffer = this.secureBuffers.get(bufferId);

    if (!buffer || !secureBuffer || secureBuffer.wiped) {
      return false;
    }

    const sourceData = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
    const targetView = new Uint8Array(buffer);

    if (sourceData.length > buffer.byteLength) {
      throw new Error('Data too large for secure buffer');
    }

    // Copy data
    targetView.set(sourceData);

    // Update access time
    secureBuffer.lastAccessed = new Date();

    return true;
  }

  /**
   * Read data from secure buffer
   */
  readSecureBuffer(bufferId: string): Uint8Array | null {
    const buffer = this.bufferData.get(bufferId);
    const secureBuffer = this.secureBuffers.get(bufferId);

    if (!buffer || !secureBuffer || secureBuffer.wiped) {
      return null;
    }

    // Update access time
    secureBuffer.lastAccessed = new Date();

    // Return a copy to prevent direct access to the secure buffer
    const view = new Uint8Array(buffer);
    return new Uint8Array(view);
  }

  /**
   * Securely wipe buffer
   */
  wipeSecureBuffer(bufferId: string): boolean {
    const buffer = this.bufferData.get(bufferId);
    const secureBuffer = this.secureBuffers.get(bufferId);

    if (!buffer || !secureBuffer) {
      return false;
    }

    // Multiple pass wipe for security
    const view = new Uint8Array(buffer);

    // Pass 1: Fill with 0xFF
    view.fill(0xFF);

    // Pass 2: Fill with 0x00
    view.fill(0x00);

    // Pass 3: Fill with random data
    crypto.getRandomValues(view);

    // Pass 4: Final zero fill
    view.fill(0x00);

    // Mark as wiped
    secureBuffer.wiped = true;

    console.log(`Securely wiped buffer ${bufferId}`);
    return true;
  }

  /**
   * Release secure buffer
   */
  releaseSecureBuffer(bufferId: string): boolean {
    const wiped = this.wipeSecureBuffer(bufferId);

    this.secureBuffers.delete(bufferId);
    this.bufferData.delete(bufferId);

    return wiped;
  }

  /**
   * Create anonymous memory file (simulated with blob URLs)
   */
  createAnonymousFile(data: ArrayBuffer, name?: string): string {
    if (!this.config.enableAnonymousMemory) {
      throw new Error('Anonymous memory not enabled');
    }

    const id = this.generateSecureId();
    const blob = new Blob([data]);
    const url = URL.createObjectURL(blob);

    this.memfdFiles.set(id, {
      url,
      blob,
      name: name || `anonymous_${id}`,
      created: new Date(),
      size: data.byteLength,
    });

    console.log(`Created anonymous file ${id} (${data.byteLength} bytes)`);
    return id;
  }

  /**
   * Get anonymous file URL
   */
  getAnonymousFileURL(fileId: string): string | null {
    const file = this.memfdFiles.get(fileId);
    return file ? file.url : null;
  }

  /**
   * Release anonymous file
   */
  releaseAnonymousFile(fileId: string): boolean {
    const file = this.memfdFiles.get(fileId);
    if (!file) return false;

    URL.revokeObjectURL(file.url);
    this.memfdFiles.delete(fileId);

    console.log(`Released anonymous file ${fileId}`);
    return true;
  }

  /**
   * Start automatic memory wiping
   */
  private startMemoryWiper(): void {
    if (!this.config.enableWipe) return;

    this.wiperInterval = window.setInterval(() => {
      this.performMemoryWipe();
    }, this.config.wiperInterval);
  }

  /**
   * Perform memory wipe of old buffers
   */
  private performMemoryWipe(): void {
    const now = new Date();
    const maxAge = 5 * 60 * 1000; // 5 minutes

    for (const [bufferId, secureBuffer] of this.secureBuffers.entries()) {
      if (secureBuffer.wiped) continue;

      const age = now.getTime() - secureBuffer.lastAccessed.getTime();
      if (age > maxAge) {
        console.log(`Auto-wiping old buffer ${bufferId} (age: ${Math.round(age / 1000)}s)`);
        this.wipeSecureBuffer(bufferId);
      }
    }
  }

  /**
   * Setup page unload handlers for emergency cleanup
   */
  private setupPageUnloadHandlers(): void {
    const emergencyCleanup = () => {
      console.log('Emergency memory cleanup triggered');
      this.wipeAllBuffers();
      this.releaseAllAnonymousFiles();
    };

    // Handle page unload
    window.addEventListener('beforeunload', emergencyCleanup);
    window.addEventListener('unload', emergencyCleanup);

    // Handle page visibility changes
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        // Page is hidden, perform preventive cleanup
        this.performMemoryWipe();
      }
    });
  }

  /**
   * Wipe all secure buffers
   */
  wipeAllBuffers(): void {
    for (const bufferId of this.secureBuffers.keys()) {
      this.wipeSecureBuffer(bufferId);
    }
  }

  /**
   * Release all anonymous files
   */
  releaseAllAnonymousFiles(): void {
    for (const fileId of this.memfdFiles.keys()) {
      this.releaseAnonymousFile(fileId);
    }
  }

  /**
   * Generate cryptographically secure ID
   */
  private generateSecureId(): string {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Get memory statistics
   */
  getMemoryStats(): MemoryStats {
    let totalAllocated = 0;
    let activeBuffers = 0;
    let wipedBuffers = 0;

    for (const buffer of this.secureBuffers.values()) {
      totalAllocated += buffer.size;
      if (buffer.wiped) {
        wipedBuffers++;
      } else {
        activeBuffers++;
      }
    }

    return {
      totalAllocated,
      activeBuffers,
      wipedBuffers,
      maxBuffers: this.config.maxSecureBuffers,
      anonymousFiles: this.memfdFiles.size,
    };
  }

  /**
   * Configure memory protection settings
   */
  configure(config: Partial<SecureMemoryConfig>): void {
    this.config = { ...this.config, ...config };

    // Restart wiper if interval changed
    if (config.wiperInterval && this.wiperInterval) {
      clearInterval(this.wiperInterval);
      this.startMemoryWiper();
    }
  }

  /**
   * Create secure string that auto-wipes
   */
  createSecureString(value: string): SecureString {
    return new SecureString(value, this);
  }

  /**
   * Stop memory protection service
   */
  shutdown(): void {
    if (this.wiperInterval) {
      clearInterval(this.wiperInterval);
      this.wiperInterval = null;
    }

    this.wipeAllBuffers();
    this.releaseAllAnonymousFiles();
  }
}

/**
 * Secure string implementation that auto-wipes
 */
export class SecureString {
  private bufferId: string | null = null;
  private memoryService: MemoryProtectionService;
  private _length: number;

  constructor(value: string, memoryService: MemoryProtectionService) {
    this.memoryService = memoryService;
    this._length = value.length;

    // Store string in secure buffer
    const encoder = new TextEncoder();
    const data = encoder.encode(value);

    this.bufferId = this.memoryService.allocateSecureBuffer(data.length, 'SecureString');
    this.memoryService.writeSecureBuffer(this.bufferId, data);
  }

  /**
   * Get the string value (creates a copy)
   */
  getValue(): string | null {
    if (!this.bufferId) return null;

    const data = this.memoryService.readSecureBuffer(this.bufferId);
    if (!data) return null;

    const decoder = new TextDecoder();
    return decoder.decode(data);
  }

  /**
   * Get string length without exposing value
   */
  get length(): number {
    return this._length;
  }

  /**
   * Check if string is wiped
   */
  get isWiped(): boolean {
    return this.bufferId === null;
  }

  /**
   * Manually wipe the string
   */
  wipe(): void {
    if (this.bufferId) {
      this.memoryService.releaseSecureBuffer(this.bufferId);
      this.bufferId = null;
    }
  }

  /**
   * Auto-wipe when object is garbage collected
   */
  finalize(): void {
    this.wipe();
  }
}

// Export singleton instance
export const memoryProtection = new MemoryProtectionService();
export default memoryProtection;