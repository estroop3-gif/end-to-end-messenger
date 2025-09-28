// Hardware Token Service
// Implements WebAuthn/FIDO2 and YubiKey OpenPGP integration

export interface HardwareToken {
  id: string;
  name: string;
  type: 'webauthn' | 'yubikey' | 'openpgp';
  credentialId?: ArrayBuffer;
  publicKey?: ArrayBuffer;
  capabilities: TokenCapability[];
  metadata: {
    manufacturer?: string;
    model?: string;
    firmware?: string;
    serialNumber?: string;
    aaguid?: string;
  };
  enrolled: Date;
  lastUsed: Date;
  status: 'active' | 'inactive' | 'revoked';
}

export type TokenCapability =
  | 'authenticate'
  | 'sign'
  | 'encrypt'
  | 'decrypt'
  | 'derive_key'
  | 'resident_key'
  | 'user_verification';

export interface TokenChallenge {
  challenge: ArrayBuffer;
  timeout: number;
  userVerification: 'required' | 'preferred' | 'discouraged';
  authenticatorSelection?: AuthenticatorSelectionCriteria;
}

export interface TokenAuthResult {
  success: boolean;
  credentialId?: ArrayBuffer;
  signature?: ArrayBuffer;
  userHandle?: ArrayBuffer;
  clientDataJSON?: ArrayBuffer;
  authenticatorData?: ArrayBuffer;
  error?: string;
}

export interface TokenEnrollmentResult {
  success: boolean;
  token?: HardwareToken;
  error?: string;
}

export interface YubiKeyInfo {
  version: string;
  serialNumber: number;
  pgpVersion: string;
  capabilities: string[];
  touchRequired: boolean;
  pinRequired: boolean;
}

class HardwareTokenService {
  private enrolledTokens: Map<string, HardwareToken> = new Map();
  private webAuthnSupported: boolean = false;
  private yubiKeySupported: boolean = false;

  constructor() {
    this.initializeCapabilities();
  }

  /**
   * Initialize hardware token capabilities
   */
  private async initializeCapabilities(): Promise<void> {
    // Check WebAuthn support
    this.webAuthnSupported = !!(
      window.navigator?.credentials?.create &&
      window.navigator?.credentials?.get &&
      window.PublicKeyCredential
    );

    // Check for YubiKey support (requires USB HID access)
    this.yubiKeySupported = !!(
      navigator.hid ||
      navigator.usb ||
      window.navigator?.credentials // WebAuthn can work with YubiKeys
    );

    console.log('Hardware token capabilities:', {
      webAuthn: this.webAuthnSupported,
      yubiKey: this.yubiKeySupported,
    });
  }

  /**
   * Check if hardware tokens are supported
   */
  isSupported(): boolean {
    return this.webAuthnSupported || this.yubiKeySupported;
  }

  /**
   * Get available token types
   */
  getSupportedTypes(): string[] {
    const types: string[] = [];
    if (this.webAuthnSupported) types.push('webauthn');
    if (this.yubiKeySupported) types.push('yubikey');
    return types;
  }

  /**
   * Enroll a new hardware token using WebAuthn
   */
  async enrollWebAuthnToken(
    username: string,
    displayName: string,
    challenge?: ArrayBuffer
  ): Promise<TokenEnrollmentResult> {
    if (!this.webAuthnSupported) {
      return {
        success: false,
        error: 'WebAuthn not supported on this device',
      };
    }

    try {
      const challengeBuffer = challenge || crypto.getRandomValues(new Uint8Array(32));

      const createOptions: PublicKeyCredentialCreationOptions = {
        challenge: challengeBuffer,
        rp: {
          name: 'Ephemeral Messenger',
          id: window.location.hostname,
        },
        user: {
          id: crypto.getRandomValues(new Uint8Array(32)),
          name: username,
          displayName: displayName,
        },
        pubKeyCredParams: [
          { alg: -7, type: 'public-key' }, // ES256
          { alg: -257, type: 'public-key' }, // RS256
          { alg: -8, type: 'public-key' }, // EdDSA
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'cross-platform',
          requireResidentKey: true,
          residentKey: 'required',
          userVerification: 'required',
        },
        timeout: 60000,
        attestation: 'direct',
      };

      const credential = await navigator.credentials.create({
        publicKey: createOptions,
      }) as PublicKeyCredential;

      if (!credential) {
        return {
          success: false,
          error: 'Failed to create credential',
        };
      }

      const response = credential.response as AuthenticatorAttestationResponse;

      // Parse authenticator data to get capabilities
      const capabilities = this.parseAuthenticatorCapabilities(response.authenticatorData);

      // Create token record
      const token: HardwareToken = {
        id: this.generateTokenId(),
        name: `${displayName} Token`,
        type: 'webauthn',
        credentialId: credential.rawId,
        publicKey: response.publicKey,
        capabilities,
        metadata: {
          aaguid: this.extractAAGUID(response.authenticatorData),
        },
        enrolled: new Date(),
        lastUsed: new Date(),
        status: 'active',
      };

      this.enrolledTokens.set(token.id, token);

      return {
        success: true,
        token,
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error during enrollment',
      };
    }
  }

  /**
   * Authenticate using WebAuthn token
   */
  async authenticateWithWebAuthn(
    tokenId?: string,
    challenge?: ArrayBuffer
  ): Promise<TokenAuthResult> {
    if (!this.webAuthnSupported) {
      return {
        success: false,
        error: 'WebAuthn not supported',
      };
    }

    try {
      const challengeBuffer = challenge || crypto.getRandomValues(new Uint8Array(32));

      // Get allowed credentials
      const allowCredentials = tokenId
        ? [{ id: this.enrolledTokens.get(tokenId)?.credentialId!, type: 'public-key' as const }]
        : Array.from(this.enrolledTokens.values())
            .filter(token => token.type === 'webauthn' && token.status === 'active')
            .map(token => ({ id: token.credentialId!, type: 'public-key' as const }));

      const getOptions: PublicKeyCredentialRequestOptions = {
        challenge: challengeBuffer,
        allowCredentials,
        timeout: 60000,
        userVerification: 'required',
      };

      const credential = await navigator.credentials.get({
        publicKey: getOptions,
      }) as PublicKeyCredential;

      if (!credential) {
        return {
          success: false,
          error: 'Authentication failed',
        };
      }

      const response = credential.response as AuthenticatorAssertionResponse;

      // Update last used time
      const token = Array.from(this.enrolledTokens.values())
        .find(t => this.arrayBuffersEqual(t.credentialId!, credential.rawId));

      if (token) {
        token.lastUsed = new Date();
      }

      return {
        success: true,
        credentialId: credential.rawId,
        signature: response.signature,
        userHandle: response.userHandle,
        clientDataJSON: response.clientDataJSON,
        authenticatorData: response.authenticatorData,
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Authentication failed',
      };
    }
  }

  /**
   * Detect connected YubiKeys
   */
  async detectYubiKeys(): Promise<YubiKeyInfo[]> {
    const yubiKeys: YubiKeyInfo[] = [];

    try {
      // Try WebAuthn detection first
      if (this.webAuthnSupported) {
        // WebAuthn can detect some YubiKey capabilities
        const webAuthnKeys = await this.detectWebAuthnYubiKeys();
        yubiKeys.push(...webAuthnKeys);
      }

      // Try USB HID detection if available
      if (navigator.hid) {
        const hidKeys = await this.detectHIDYubiKeys();
        yubiKeys.push(...hidKeys);
      }

      // Try USB detection if available
      if (navigator.usb) {
        const usbKeys = await this.detectUSBYubiKeys();
        yubiKeys.push(...usbKeys);
      }
    } catch (error) {
      console.error('Error detecting YubiKeys:', error);
    }

    return yubiKeys;
  }

  /**
   * Detect YubiKeys via WebAuthn
   */
  private async detectWebAuthnYubiKeys(): Promise<YubiKeyInfo[]> {
    // This is a simplified detection - real implementation would use
    // WebAuthn's authenticatorMakeCredential with Yubico-specific parameters
    return [];
  }

  /**
   * Detect YubiKeys via USB HID
   */
  private async detectHIDYubiKeys(): Promise<YubiKeyInfo[]> {
    if (!navigator.hid) return [];

    try {
      const devices = await navigator.hid.getDevices();
      const yubiKeys: YubiKeyInfo[] = [];

      for (const device of devices) {
        if (this.isYubiKeyDevice(device.vendorId, device.productId)) {
          const info = await this.getYubiKeyInfo(device);
          if (info) {
            yubiKeys.push(info);
          }
        }
      }

      return yubiKeys;
    } catch (error) {
      console.error('HID detection failed:', error);
      return [];
    }
  }

  /**
   * Detect YubiKeys via USB
   */
  private async detectUSBYubiKeys(): Promise<YubiKeyInfo[]> {
    if (!navigator.usb) return [];

    try {
      const devices = await navigator.usb.getDevices();
      const yubiKeys: YubiKeyInfo[] = [];

      for (const device of devices) {
        if (this.isYubiKeyDevice(device.vendorId, device.productId)) {
          const info = await this.getYubiKeyInfoUSB(device);
          if (info) {
            yubiKeys.push(info);
          }
        }
      }

      return yubiKeys;
    } catch (error) {
      console.error('USB detection failed:', error);
      return [];
    }
  }

  /**
   * Check if device is a YubiKey
   */
  private isYubiKeyDevice(vendorId: number, productId: number): boolean {
    const YUBICO_VENDOR_ID = 0x1050;
    return vendorId === YUBICO_VENDOR_ID;
  }

  /**
   * Get YubiKey information from HID device
   */
  private async getYubiKeyInfo(device: HIDDevice): Promise<YubiKeyInfo | null> {
    try {
      // This is a simplified implementation
      // Real implementation would communicate with YubiKey using HID protocol
      return {
        version: 'Unknown',
        serialNumber: 0,
        pgpVersion: 'Unknown',
        capabilities: ['webauthn', 'openpgp'],
        touchRequired: true,
        pinRequired: false,
      };
    } catch (error) {
      console.error('Failed to get YubiKey info:', error);
      return null;
    }
  }

  /**
   * Get YubiKey information from USB device
   */
  private async getYubiKeyInfoUSB(device: USBDevice): Promise<YubiKeyInfo | null> {
    try {
      // This is a simplified implementation
      // Real implementation would use USB control transfers
      return {
        version: 'Unknown',
        serialNumber: 0,
        pgpVersion: 'Unknown',
        capabilities: ['webauthn', 'openpgp'],
        touchRequired: true,
        pinRequired: false,
      };
    } catch (error) {
      console.error('Failed to get YubiKey info via USB:', error);
      return null;
    }
  }

  /**
   * Sign data using hardware token
   */
  async signWithToken(
    tokenId: string,
    data: ArrayBuffer,
    algorithm: 'ES256' | 'RS256' | 'EdDSA' = 'ES256'
  ): Promise<ArrayBuffer | null> {
    const token = this.enrolledTokens.get(tokenId);
    if (!token || token.status !== 'active') {
      throw new Error('Token not found or inactive');
    }

    if (!token.capabilities.includes('sign')) {
      throw new Error('Token does not support signing');
    }

    try {
      // Create a challenge that includes the data to sign
      const challenge = new Uint8Array(data);

      const authResult = await this.authenticateWithWebAuthn(tokenId, challenge);
      if (!authResult.success) {
        throw new Error(authResult.error || 'Authentication failed');
      }

      // Update last used time
      token.lastUsed = new Date();

      return authResult.signature || null;
    } catch (error) {
      console.error('Token signing failed:', error);
      throw error;
    }
  }

  /**
   * Derive key using hardware token
   */
  async deriveKeyWithToken(
    tokenId: string,
    salt: ArrayBuffer,
    info: string,
    keyLength: number = 32
  ): Promise<ArrayBuffer | null> {
    const token = this.enrolledTokens.get(tokenId);
    if (!token || token.status !== 'active') {
      throw new Error('Token not found or inactive');
    }

    if (!token.capabilities.includes('derive_key')) {
      // Fallback: use token for authentication then derive key locally
      const authData = new TextEncoder().encode(info);
      const authResult = await this.authenticateWithWebAuthn(tokenId, authData);

      if (!authResult.success) {
        throw new Error('Token authentication failed');
      }

      // Use token's credential ID and signature as key material
      const keyMaterial = new Uint8Array([
        ...new Uint8Array(token.credentialId!),
        ...new Uint8Array(authResult.signature!),
        ...new Uint8Array(salt),
      ]);

      // Derive key using Web Crypto API
      const importedKey = await crypto.subtle.importKey(
        'raw',
        keyMaterial,
        'PBKDF2',
        false,
        ['deriveBits']
      );

      const derivedBits = await crypto.subtle.deriveBits(
        {
          name: 'PBKDF2',
          salt: salt,
          iterations: 100000,
          hash: 'SHA-256',
        },
        importedKey,
        keyLength * 8
      );

      token.lastUsed = new Date();
      return derivedBits;
    }

    // If token supports native key derivation, use that
    // This would require vendor-specific implementation
    throw new Error('Native key derivation not implemented');
  }

  /**
   * Get enrolled tokens
   */
  getEnrolledTokens(): HardwareToken[] {
    return Array.from(this.enrolledTokens.values());
  }

  /**
   * Get active tokens
   */
  getActiveTokens(): HardwareToken[] {
    return Array.from(this.enrolledTokens.values())
      .filter(token => token.status === 'active');
  }

  /**
   * Revoke a token
   */
  revokeToken(tokenId: string): boolean {
    const token = this.enrolledTokens.get(tokenId);
    if (!token) {
      return false;
    }

    token.status = 'revoked';
    return true;
  }

  /**
   * Remove a token
   */
  removeToken(tokenId: string): boolean {
    return this.enrolledTokens.delete(tokenId);
  }

  /**
   * Parse authenticator capabilities from authenticator data
   */
  private parseAuthenticatorCapabilities(authenticatorData: ArrayBuffer): TokenCapability[] {
    const capabilities: TokenCapability[] = ['authenticate'];

    try {
      const dataView = new DataView(authenticatorData);
      const flags = dataView.getUint8(32); // Flags are at byte 32

      // Bit 0: User Present (UP)
      if (flags & 0x01) {
        capabilities.push('user_verification');
      }

      // Bit 2: User Verified (UV)
      if (flags & 0x04) {
        capabilities.push('user_verification');
      }

      // Bit 6: Attested credential data included (AT)
      if (flags & 0x40) {
        capabilities.push('resident_key');
      }

      // Assume signing capability for WebAuthn tokens
      capabilities.push('sign');
    } catch (error) {
      console.error('Failed to parse authenticator capabilities:', error);
    }

    return capabilities;
  }

  /**
   * Extract AAGUID from authenticator data
   */
  private extractAAGUID(authenticatorData: ArrayBuffer): string {
    try {
      const dataView = new DataView(authenticatorData);
      const aaguidBytes = new Uint8Array(authenticatorData, 37, 16);
      return Array.from(aaguidBytes, b => b.toString(16).padStart(2, '0')).join('');
    } catch (error) {
      console.error('Failed to extract AAGUID:', error);
      return '';
    }
  }

  /**
   * Generate unique token ID
   */
  private generateTokenId(): string {
    return `token_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Compare ArrayBuffers for equality
   */
  private arrayBuffersEqual(a: ArrayBuffer, b: ArrayBuffer): boolean {
    if (a.byteLength !== b.byteLength) return false;
    const viewA = new Uint8Array(a);
    const viewB = new Uint8Array(b);
    for (let i = 0; i < viewA.length; i++) {
      if (viewA[i] !== viewB[i]) return false;
    }
    return true;
  }

  /**
   * Request HID device access
   */
  async requestHIDAccess(): Promise<boolean> {
    if (!navigator.hid) {
      console.error('WebHID not supported');
      return false;
    }

    try {
      const devices = await navigator.hid.requestDevice({
        filters: [{ vendorId: 0x1050 }] // Yubico vendor ID
      });
      return devices.length > 0;
    } catch (error) {
      console.error('HID access request failed:', error);
      return false;
    }
  }

  /**
   * Request USB device access
   */
  async requestUSBAccess(): Promise<boolean> {
    if (!navigator.usb) {
      console.error('WebUSB not supported');
      return false;
    }

    try {
      const device = await navigator.usb.requestDevice({
        filters: [{ vendorId: 0x1050 }] // Yubico vendor ID
      });
      return !!device;
    } catch (error) {
      console.error('USB access request failed:', error);
      return false;
    }
  }
}

// Export singleton instance
export const hardwareTokenService = new HardwareTokenService();
export default hardwareTokenService;