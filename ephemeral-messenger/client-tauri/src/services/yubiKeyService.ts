// YubiKey OpenPGP Service
// Specialized service for YubiKey OpenPGP card functionality

export interface YubiKeyCard {
  serialNumber: string;
  version: string;
  manufacturer: string;
  applicationId: string;
  capabilities: YubiKeyCapability[];
  slots: {
    signature: YubiKeySlot;
    encryption: YubiKeySlot;
    authentication: YubiKeySlot;
  };
  pinRetryCounter: number;
  adminPinRetryCounter: number;
  touchRequired: boolean;
  pinRequired: boolean;
}

export interface YubiKeySlot {
  occupied: boolean;
  keyId?: string;
  fingerprint?: string;
  created?: Date;
  algorithm?: 'RSA-2048' | 'RSA-4096' | 'ECC-P256' | 'ECC-P384' | 'Ed25519' | 'X25519';
}

export type YubiKeyCapability =
  | 'sign'
  | 'encrypt'
  | 'authenticate'
  | 'certify'
  | 'touch_required'
  | 'pin_required';

export interface YubiKeyChallenge {
  challenge: Uint8Array;
  slot: 'signature' | 'encryption' | 'authentication';
  requireTouch: boolean;
  requirePin: boolean;
}

export interface YubiKeyResponse {
  success: boolean;
  signature?: Uint8Array;
  publicKey?: Uint8Array;
  error?: string;
  requiresPin?: boolean;
  requiresTouch?: boolean;
}

export interface YubiKeyPGPKey {
  keyId: string;
  fingerprint: string;
  algorithm: string;
  keySize: number;
  created: Date;
  usage: string[];
  publicKey: ArrayBuffer;
}

class YubiKeyService {
  private connectedCards: Map<string, YubiKeyCard> = new Map();
  private hidDevice: HIDDevice | null = null;
  private isConnected: boolean = false;

  /**
   * Initialize YubiKey service
   */
  async initialize(): Promise<boolean> {
    if (!navigator.hid) {
      console.error('WebHID not supported');
      return false;
    }

    try {
      // Check for already granted devices
      const grantedDevices = await navigator.hid.getDevices();
      const yubiKeys = grantedDevices.filter(device =>
        device.vendorId === 0x1050 // Yubico vendor ID
      );

      if (yubiKeys.length > 0) {
        await this.connectToDevice(yubiKeys[0]);
        return true;
      }

      return false;
    } catch (error) {
      console.error('Failed to initialize YubiKey service:', error);
      return false;
    }
  }

  /**
   * Request access to YubiKey device
   */
  async requestDevice(): Promise<boolean> {
    if (!navigator.hid) {
      throw new Error('WebHID not supported');
    }

    try {
      const devices = await navigator.hid.requestDevice({
        filters: [
          { vendorId: 0x1050, usagePage: 0xFF00 }, // YubiKey FIDO
          { vendorId: 0x1050, usagePage: 0xF1D0 }, // YubiKey Smart Card
        ]
      });

      if (devices.length > 0) {
        await this.connectToDevice(devices[0]);
        return true;
      }

      return false;
    } catch (error) {
      console.error('YubiKey device request failed:', error);
      return false;
    }
  }

  /**
   * Connect to YubiKey device
   */
  private async connectToDevice(device: HIDDevice): Promise<void> {
    try {
      if (!device.opened) {
        await device.open();
      }

      this.hidDevice = device;
      this.isConnected = true;

      // Set up event listeners
      device.addEventListener('inputreport', this.handleInputReport.bind(this));

      // Query card information
      const cardInfo = await this.queryCardInfo();
      if (cardInfo) {
        this.connectedCards.set(cardInfo.serialNumber, cardInfo);
      }

      console.log('Connected to YubiKey:', cardInfo?.serialNumber);
    } catch (error) {
      console.error('Failed to connect to YubiKey:', error);
      throw error;
    }
  }

  /**
   * Query YubiKey card information
   */
  private async queryCardInfo(): Promise<YubiKeyCard | null> {
    if (!this.hidDevice) return null;

    try {
      // Send OpenPGP GET DATA command for card info
      const getDataCommand = this.buildAPDU(0x00, 0xCA, 0x00, 0x6E, []);
      const response = await this.sendCommand(getDataCommand);

      if (!response || response.length < 2) {
        throw new Error('Invalid response from card');
      }

      // Parse response (simplified - real implementation would parse TLV data)
      const cardInfo: YubiKeyCard = {
        serialNumber: this.extractSerialNumber(response),
        version: this.extractVersion(response),
        manufacturer: 'Yubico',
        applicationId: 'OpenPGP',
        capabilities: ['sign', 'encrypt', 'authenticate'],
        slots: {
          signature: { occupied: false },
          encryption: { occupied: false },
          authentication: { occupied: false },
        },
        pinRetryCounter: 3,
        adminPinRetryCounter: 3,
        touchRequired: true,
        pinRequired: true,
      };

      // Query each slot for key information
      await this.querySlotInfo(cardInfo, 'signature', 0xC1);
      await this.querySlotInfo(cardInfo, 'encryption', 0xC2);
      await this.querySlotInfo(cardInfo, 'authentication', 0xC3);

      return cardInfo;
    } catch (error) {
      console.error('Failed to query card info:', error);
      return null;
    }
  }

  /**
   * Query information for a specific key slot
   */
  private async querySlotInfo(
    card: YubiKeyCard,
    slotName: keyof YubiKeyCard['slots'],
    slotId: number
  ): Promise<void> {
    try {
      // Get public key data for slot
      const getKeyCommand = this.buildAPDU(0x00, 0x47, 0x81, slotId, []);
      const response = await this.sendCommand(getKeyCommand);

      if (response && response.length > 2) {
        card.slots[slotName] = {
          occupied: true,
          keyId: this.extractKeyId(response),
          fingerprint: this.extractFingerprint(response),
          created: new Date(),
          algorithm: this.extractAlgorithm(response),
        };
      }
    } catch (error) {
      // Slot might be empty, which is normal
      console.debug(`Slot ${slotName} appears to be empty or inaccessible`);
    }
  }

  /**
   * Sign data using YubiKey
   */
  async sign(
    data: ArrayBuffer,
    slot: 'signature' | 'encryption' | 'authentication' = 'signature',
    pin?: string
  ): Promise<YubiKeyResponse> {
    if (!this.isConnected || !this.hidDevice) {
      return { success: false, error: 'YubiKey not connected' };
    }

    try {
      // Get connected card
      const card = Array.from(this.connectedCards.values())[0];
      if (!card) {
        return { success: false, error: 'No card information available' };
      }

      // Check if slot has a key
      if (!card.slots[slot].occupied) {
        return { success: false, error: `No key in ${slot} slot` };
      }

      // Verify PIN if required
      if (card.pinRequired && pin) {
        const pinVerified = await this.verifyPin(pin);
        if (!pinVerified) {
          return { success: false, error: 'PIN verification failed', requiresPin: true };
        }
      }

      // Prepare data for signing (hash if necessary)
      const hashToSign = await this.prepareDataForSigning(data);

      // Send sign command
      const slotIds = { signature: 0x9E, encryption: 0x9C, authentication: 0x9A };
      const signCommand = this.buildSignCommand(slotIds[slot], hashToSign);

      const response = await this.sendCommand(signCommand);

      if (!response || response.length < 2) {
        return { success: false, error: 'Invalid signature response' };
      }

      // Check for touch requirement
      if (card.touchRequired && this.isUserPresenceRequired(response)) {
        return {
          success: false,
          error: 'Touch required',
          requiresTouch: true
        };
      }

      const signature = response.slice(0, response.length - 2);
      const statusCode = response.slice(-2);

      if (statusCode[0] === 0x90 && statusCode[1] === 0x00) {
        return {
          success: true,
          signature: signature,
        };
      } else {
        return {
          success: false,
          error: `Sign operation failed: ${statusCode[0].toString(16)}${statusCode[1].toString(16)}`,
        };
      }
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Get public key from YubiKey slot
   */
  async getPublicKey(slot: 'signature' | 'encryption' | 'authentication'): Promise<YubiKeyPGPKey | null> {
    if (!this.isConnected || !this.hidDevice) {
      throw new Error('YubiKey not connected');
    }

    try {
      const slotIds = { signature: 0xC1, encryption: 0xC2, authentication: 0xC3 };
      const getKeyCommand = this.buildAPDU(0x00, 0x47, 0x81, slotIds[slot], []);

      const response = await this.sendCommand(getKeyCommand);

      if (!response || response.length < 2) {
        return null;
      }

      return {
        keyId: this.extractKeyId(response),
        fingerprint: this.extractFingerprint(response),
        algorithm: this.extractAlgorithm(response),
        keySize: this.extractKeySize(response),
        created: new Date(),
        usage: [slot],
        publicKey: response.slice(0, response.length - 2),
      };
    } catch (error) {
      console.error('Failed to get public key:', error);
      return null;
    }
  }

  /**
   * Generate new key pair on YubiKey
   */
  async generateKeyPair(
    slot: 'signature' | 'encryption' | 'authentication',
    algorithm: 'RSA-2048' | 'RSA-4096' | 'ECC-P256' | 'Ed25519' = 'Ed25519',
    adminPin: string
  ): Promise<YubiKeyPGPKey | null> {
    if (!this.isConnected || !this.hidDevice) {
      throw new Error('YubiKey not connected');
    }

    try {
      // Verify admin PIN
      const adminPinVerified = await this.verifyAdminPin(adminPin);
      if (!adminPinVerified) {
        throw new Error('Admin PIN verification failed');
      }

      // Build generate key command
      const slotIds = { signature: 0x9E, encryption: 0x9C, authentication: 0x9A };
      const algorithmBytes = this.getAlgorithmBytes(algorithm);

      const generateCommand = this.buildAPDU(
        0x00, 0x47, 0x80, slotIds[slot],
        [...algorithmBytes]
      );

      const response = await this.sendCommand(generateCommand);

      if (!response || response.length < 2) {
        throw new Error('Key generation failed');
      }

      const statusCode = response.slice(-2);
      if (statusCode[0] !== 0x90 || statusCode[1] !== 0x00) {
        throw new Error(`Key generation failed: ${statusCode[0].toString(16)}${statusCode[1].toString(16)}`);
      }

      // Refresh card info to update slot status
      await this.queryCardInfo();

      // Return the generated public key
      return await this.getPublicKey(slot);
    } catch (error) {
      console.error('Key generation failed:', error);
      throw error;
    }
  }

  /**
   * Verify user PIN
   */
  private async verifyPin(pin: string): Promise<boolean> {
    try {
      const pinBytes = new TextEncoder().encode(pin);
      const verifyCommand = this.buildAPDU(0x00, 0x20, 0x00, 0x82, Array.from(pinBytes));

      const response = await this.sendCommand(verifyCommand);

      if (!response || response.length < 2) {
        return false;
      }

      const statusCode = response.slice(-2);
      return statusCode[0] === 0x90 && statusCode[1] === 0x00;
    } catch (error) {
      console.error('PIN verification failed:', error);
      return false;
    }
  }

  /**
   * Verify admin PIN
   */
  private async verifyAdminPin(adminPin: string): Promise<boolean> {
    try {
      const pinBytes = new TextEncoder().encode(adminPin);
      const verifyCommand = this.buildAPDU(0x00, 0x20, 0x00, 0x83, Array.from(pinBytes));

      const response = await this.sendCommand(verifyCommand);

      if (!response || response.length < 2) {
        return false;
      }

      const statusCode = response.slice(-2);
      return statusCode[0] === 0x90 && statusCode[1] === 0x00;
    } catch (error) {
      console.error('Admin PIN verification failed:', error);
      return false;
    }
  }

  /**
   * Send APDU command to YubiKey
   */
  private async sendCommand(apdu: Uint8Array): Promise<Uint8Array | null> {
    if (!this.hidDevice) {
      throw new Error('No HID device connected');
    }

    try {
      // Convert APDU to HID packet format
      const hidPacket = this.apduToHidPacket(apdu);

      // Send command
      await this.hidDevice.sendReport(0, hidPacket);

      // Wait for response
      const response = await this.waitForResponse();

      return response;
    } catch (error) {
      console.error('Command send failed:', error);
      return null;
    }
  }

  /**
   * Build APDU command
   */
  private buildAPDU(cla: number, ins: number, p1: number, p2: number, data: number[]): Uint8Array {
    const apdu = [cla, ins, p1, p2];

    if (data.length > 0) {
      apdu.push(data.length);
      apdu.push(...data);
    }

    return new Uint8Array(apdu);
  }

  /**
   * Build sign command APDU
   */
  private buildSignCommand(slotId: number, data: Uint8Array): Uint8Array {
    return this.buildAPDU(0x00, 0x2A, 0x9E, slotId, Array.from(data));
  }

  /**
   * Convert APDU to HID packet format
   */
  private apduToHidPacket(apdu: Uint8Array): Uint8Array {
    // Simplified HID packet format for YubiKey
    const packet = new Uint8Array(64);
    packet[0] = 0x00; // Report ID
    packet.set(apdu, 1);
    return packet;
  }

  /**
   * Wait for HID response
   */
  private async waitForResponse(timeout: number = 5000): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        reject(new Error('Response timeout'));
      }, timeout);

      const handleInputReport = (event: HIDInputReportEvent) => {
        clearTimeout(timeoutId);
        const response = new Uint8Array(event.data.buffer);
        resolve(response);
      };

      this.hidDevice!.addEventListener('inputreport', handleInputReport, { once: true });
    });
  }

  /**
   * Handle HID input reports
   */
  private handleInputReport(event: HIDInputReportEvent): void {
    // Process incoming data from YubiKey
    console.debug('Received HID input report:', new Uint8Array(event.data.buffer));
  }

  /**
   * Prepare data for signing (hash if necessary)
   */
  private async prepareDataForSigning(data: ArrayBuffer): Promise<Uint8Array> {
    // For most cases, we need to hash the data before signing
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(hashBuffer);
  }

  /**
   * Check if user presence is required
   */
  private isUserPresenceRequired(response: Uint8Array): boolean {
    const statusCode = response.slice(-2);
    return statusCode[0] === 0x69 && statusCode[1] === 0x85; // Conditions not satisfied
  }

  /**
   * Get algorithm bytes for key generation
   */
  private getAlgorithmBytes(algorithm: string): number[] {
    switch (algorithm) {
      case 'RSA-2048': return [0x01, 0x08, 0x00]; // RSA 2048
      case 'RSA-4096': return [0x01, 0x10, 0x00]; // RSA 4096
      case 'ECC-P256': return [0x13]; // NIST P-256
      case 'Ed25519': return [0x16]; // Ed25519
      default: return [0x16]; // Default to Ed25519
    }
  }

  // Helper methods for parsing card responses
  private extractSerialNumber(response: Uint8Array): string {
    // Simplified extraction - real implementation would parse TLV
    return Math.random().toString(36).substr(2, 8);
  }

  private extractVersion(response: Uint8Array): string {
    return '3.4.0'; // Default version
  }

  private extractKeyId(response: Uint8Array): string {
    return Array.from(response.slice(0, 8), b => b.toString(16).padStart(2, '0')).join('');
  }

  private extractFingerprint(response: Uint8Array): string {
    return Array.from(response.slice(0, 20), b => b.toString(16).padStart(2, '0')).join('');
  }

  private extractAlgorithm(response: Uint8Array): string {
    return 'Ed25519'; // Default algorithm
  }

  private extractKeySize(response: Uint8Array): number {
    return 256; // Default key size
  }

  /**
   * Get connected cards
   */
  getConnectedCards(): YubiKeyCard[] {
    return Array.from(this.connectedCards.values());
  }

  /**
   * Check if YubiKey is connected
   */
  isYubiKeyConnected(): boolean {
    return this.isConnected;
  }

  /**
   * Disconnect from YubiKey
   */
  async disconnect(): Promise<void> {
    if (this.hidDevice && this.hidDevice.opened) {
      await this.hidDevice.close();
    }

    this.hidDevice = null;
    this.isConnected = false;
    this.connectedCards.clear();
  }
}

// Export singleton instance
export const yubiKeyService = new YubiKeyService();
export default yubiKeyService;