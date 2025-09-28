// Challenge-Response Authentication Service
// Implements secure challenge-response authentication with hardware tokens

import { hardwareTokenService, HardwareToken } from './hardwareTokenService';
import { yubiKeyService } from './yubiKeyService';
import { secureKeyStorage } from './secureKeyStorage';
import { memoryProtection } from './memoryProtection';

export interface Challenge {
  id: string;
  challenge: ArrayBuffer;
  timestamp: Date;
  expiresAt: Date;
  tokenId?: string;
  type: 'authentication' | 'signing' | 'key_derivation';
  metadata: {
    purpose: string;
    requester: string;
    context?: any;
  };
}

export interface ChallengeResponse {
  challengeId: string;
  signature: ArrayBuffer;
  publicKey?: ArrayBuffer;
  tokenId: string;
  timestamp: Date;
  clientData: {
    type: string;
    challenge: string;
    origin: string;
    crossOrigin: boolean;
  };
}

export interface AuthenticationSession {
  sessionId: string;
  tokenId: string;
  created: Date;
  lastActivity: Date;
  expiresAt: Date;
  challenges: Challenge[];
  authenticated: boolean;
  metadata: {
    purpose: string;
    requiredCapabilities: string[];
    multiFactorRequired: boolean;
  };
}

export interface ChallengeConfig {
  challengeSize: number;
  expirationTime: number; // milliseconds
  maxConcurrentChallenges: number;
  requireUserPresence: boolean;
  requireUserVerification: boolean;
  allowMultipleSessions: boolean;
}

class ChallengeResponseAuthService {
  private activeChallenges: Map<string, Challenge> = new Map();
  private activeSessions: Map<string, AuthenticationSession> = new Map();
  private config: ChallengeConfig;

  constructor() {
    this.config = {
      challengeSize: 32,
      expirationTime: 5 * 60 * 1000, // 5 minutes
      maxConcurrentChallenges: 10,
      requireUserPresence: true,
      requireUserVerification: true,
      allowMultipleSessions: false,
    };

    this.startCleanupTimer();
  }

  /**
   * Create a new authentication challenge
   */
  createChallenge(
    type: 'authentication' | 'signing' | 'key_derivation',
    purpose: string,
    requester: string,
    tokenId?: string,
    context?: any
  ): Challenge {
    // Check limits
    if (this.activeChallenges.size >= this.config.maxConcurrentChallenges) {
      throw new Error('Maximum concurrent challenges exceeded');
    }

    // Generate cryptographically secure challenge
    const challenge = crypto.getRandomValues(new Uint8Array(this.config.challengeSize));

    const challengeObj: Challenge = {
      id: this.generateChallengeId(),
      challenge: challenge.buffer,
      timestamp: new Date(),
      expiresAt: new Date(Date.now() + this.config.expirationTime),
      tokenId,
      type,
      metadata: {
        purpose,
        requester,
        context,
      },
    };

    this.activeChallenges.set(challengeObj.id, challengeObj);

    console.log(`Created ${type} challenge ${challengeObj.id} for ${purpose}`);
    return challengeObj;
  }

  /**
   * Respond to a challenge using hardware token
   */
  async respondToChallenge(
    challengeId: string,
    tokenId: string,
    pin?: string
  ): Promise<ChallengeResponse> {
    const challenge = this.activeChallenges.get(challengeId);
    if (!challenge) {
      throw new Error('Challenge not found or expired');
    }

    if (challenge.expiresAt < new Date()) {
      this.activeChallenges.delete(challengeId);
      throw new Error('Challenge expired');
    }

    // Verify token is enrolled and active
    const tokens = hardwareTokenService.getEnrolledTokens();
    const token = tokens.find(t => t.id === tokenId && t.status === 'active');
    if (!token) {
      throw new Error('Token not found or inactive');
    }

    // Check if challenge is for specific token
    if (challenge.tokenId && challenge.tokenId !== tokenId) {
      throw new Error('Challenge is for a different token');
    }

    try {
      let signature: ArrayBuffer;
      let publicKey: ArrayBuffer | undefined;

      if (token.type === 'webauthn') {
        const authResult = await hardwareTokenService.authenticateWithWebAuthn(
          tokenId,
          challenge.challenge
        );

        if (!authResult.success) {
          throw new Error(authResult.error || 'Authentication failed');
        }

        signature = authResult.signature!;
        publicKey = token.publicKey;
      } else if (token.type === 'yubikey') {
        const yubiKeyResult = await yubiKeyService.sign(
          challenge.challenge,
          'signature',
          pin
        );

        if (!yubiKeyResult.success) {
          throw new Error(yubiKeyResult.error || 'YubiKey signing failed');
        }

        signature = yubiKeyResult.signature!;
        const yubiKeyPublicKey = await yubiKeyService.getPublicKey('signature');
        publicKey = yubiKeyPublicKey?.publicKey;
      } else {
        throw new Error('Unsupported token type');
      }

      // Create client data
      const clientData = {
        type: challenge.type,
        challenge: this.arrayBufferToBase64(challenge.challenge),
        origin: window.location.origin,
        crossOrigin: false,
      };

      const response: ChallengeResponse = {
        challengeId,
        signature,
        publicKey,
        tokenId,
        timestamp: new Date(),
        clientData,
      };

      // Remove challenge after successful response
      this.activeChallenges.delete(challengeId);

      console.log(`Challenge ${challengeId} responded successfully`);
      return response;
    } catch (error) {
      console.error('Challenge response failed:', error);
      throw error;
    }
  }

  /**
   * Verify a challenge response
   */
  async verifyChallengeResponse(
    originalChallenge: Challenge,
    response: ChallengeResponse
  ): Promise<boolean> {
    try {
      // Verify basic properties
      if (response.challengeId !== originalChallenge.id) {
        console.error('Challenge ID mismatch');
        return false;
      }

      // Verify timestamp (response should be after challenge)
      if (response.timestamp < originalChallenge.timestamp) {
        console.error('Invalid response timestamp');
        return false;
      }

      // Verify client data challenge matches
      const challengeBase64 = this.arrayBufferToBase64(originalChallenge.challenge);
      if (response.clientData.challenge !== challengeBase64) {
        console.error('Client data challenge mismatch');
        return false;
      }

      // Get token for verification
      const tokens = hardwareTokenService.getEnrolledTokens();
      const token = tokens.find(t => t.id === response.tokenId);
      if (!token || !token.publicKey) {
        console.error('Token not found or no public key');
        return false;
      }

      // Create verification data (combines challenge and client data)
      const clientDataJSON = JSON.stringify(response.clientData);
      const clientDataBuffer = new TextEncoder().encode(clientDataJSON);

      const verificationData = new Uint8Array([
        ...new Uint8Array(originalChallenge.challenge),
        ...new Uint8Array(clientDataBuffer),
      ]);

      // Verify signature using Web Crypto API
      const publicKey = await crypto.subtle.importKey(
        'raw',
        token.publicKey,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify']
      );

      const isValid = await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        publicKey,
        response.signature,
        verificationData
      );

      if (isValid) {
        console.log('Challenge response verified successfully');
      } else {
        console.error('Signature verification failed');
      }

      return isValid;
    } catch (error) {
      console.error('Challenge verification error:', error);
      return false;
    }
  }

  /**
   * Create an authentication session
   */
  createAuthenticationSession(
    tokenId: string,
    purpose: string,
    requiredCapabilities: string[] = ['authenticate'],
    multiFactorRequired: boolean = false
  ): AuthenticationSession {
    // Check if multiple sessions are allowed
    if (!this.config.allowMultipleSessions) {
      const existingSessions = Array.from(this.activeSessions.values())
        .filter(s => s.tokenId === tokenId && !this.isSessionExpired(s));

      if (existingSessions.length > 0) {
        throw new Error('Active session already exists for this token');
      }
    }

    const sessionId = this.generateSessionId();
    const session: AuthenticationSession = {
      sessionId,
      tokenId,
      created: new Date(),
      lastActivity: new Date(),
      expiresAt: new Date(Date.now() + 30 * 60 * 1000), // 30 minutes
      challenges: [],
      authenticated: false,
      metadata: {
        purpose,
        requiredCapabilities,
        multiFactorRequired,
      },
    };

    this.activeSessions.set(sessionId, session);

    console.log(`Created authentication session ${sessionId} for token ${tokenId}`);
    return session;
  }

  /**
   * Authenticate a session using challenge-response
   */
  async authenticateSession(
    sessionId: string,
    pin?: string
  ): Promise<boolean> {
    const session = this.activeSessions.get(sessionId);
    if (!session) {
      throw new Error('Session not found');
    }

    if (this.isSessionExpired(session)) {
      this.activeSessions.delete(sessionId);
      throw new Error('Session expired');
    }

    try {
      // Create authentication challenge
      const challenge = this.createChallenge(
        'authentication',
        session.metadata.purpose,
        'session_auth',
        session.tokenId,
        { sessionId }
      );

      session.challenges.push(challenge);

      // Respond to challenge
      const response = await this.respondToChallenge(
        challenge.id,
        session.tokenId,
        pin
      );

      // Verify response
      const isValid = await this.verifyChallengeResponse(challenge, response);

      if (isValid) {
        session.authenticated = true;
        session.lastActivity = new Date();
        console.log(`Session ${sessionId} authenticated successfully`);
        return true;
      } else {
        console.error(`Session ${sessionId} authentication failed`);
        return false;
      }
    } catch (error) {
      console.error('Session authentication error:', error);
      throw error;
    }
  }

  /**
   * Sign data using authenticated session
   */
  async signWithSession(
    sessionId: string,
    data: ArrayBuffer,
    purpose: string,
    pin?: string
  ): Promise<ArrayBuffer> {
    const session = this.activeSessions.get(sessionId);
    if (!session) {
      throw new Error('Session not found');
    }

    if (!session.authenticated) {
      throw new Error('Session not authenticated');
    }

    if (this.isSessionExpired(session)) {
      this.activeSessions.delete(sessionId);
      throw new Error('Session expired');
    }

    // Check if token supports signing
    const tokens = hardwareTokenService.getEnrolledTokens();
    const token = tokens.find(t => t.id === session.tokenId);
    if (!token || !token.capabilities.includes('sign')) {
      throw new Error('Token does not support signing');
    }

    try {
      // Create signing challenge with the data to sign
      const challenge = this.createChallenge(
        'signing',
        purpose,
        'session_sign',
        session.tokenId,
        { sessionId, dataHash: await this.hashData(data) }
      );

      session.challenges.push(challenge);

      // Use the actual data as the challenge for signing
      challenge.challenge = data;

      // Respond to challenge
      const response = await this.respondToChallenge(
        challenge.id,
        session.tokenId,
        pin
      );

      session.lastActivity = new Date();

      return response.signature;
    } catch (error) {
      console.error('Session signing error:', error);
      throw error;
    }
  }

  /**
   * Derive key using authenticated session
   */
  async deriveKeyWithSession(
    sessionId: string,
    salt: ArrayBuffer,
    info: string,
    keyLength: number = 32,
    pin?: string
  ): Promise<ArrayBuffer> {
    const session = this.activeSessions.get(sessionId);
    if (!session) {
      throw new Error('Session not found');
    }

    if (!session.authenticated) {
      throw new Error('Session not authenticated');
    }

    if (this.isSessionExpired(session)) {
      this.activeSessions.delete(sessionId);
      throw new Error('Session expired');
    }

    try {
      // Use hardware token for key derivation
      const derivedKey = await hardwareTokenService.deriveKeyWithToken(
        session.tokenId,
        salt,
        info,
        keyLength
      );

      if (!derivedKey) {
        throw new Error('Key derivation failed');
      }

      session.lastActivity = new Date();

      return derivedKey;
    } catch (error) {
      console.error('Session key derivation error:', error);
      throw error;
    }
  }

  /**
   * Get active challenges
   */
  getActiveChallenges(): Challenge[] {
    return Array.from(this.activeChallenges.values());
  }

  /**
   * Get active sessions
   */
  getActiveSessions(): AuthenticationSession[] {
    return Array.from(this.activeSessions.values());
  }

  /**
   * Invalidate a session
   */
  invalidateSession(sessionId: string): boolean {
    const session = this.activeSessions.get(sessionId);
    if (!session) {
      return false;
    }

    // Clean up any active challenges for this session
    for (const challenge of session.challenges) {
      this.activeChallenges.delete(challenge.id);
    }

    this.activeSessions.delete(sessionId);
    console.log(`Session ${sessionId} invalidated`);
    return true;
  }

  /**
   * Invalidate all sessions for a token
   */
  invalidateTokenSessions(tokenId: string): number {
    let invalidated = 0;

    for (const session of this.activeSessions.values()) {
      if (session.tokenId === tokenId) {
        this.invalidateSession(session.sessionId);
        invalidated++;
      }
    }

    return invalidated;
  }

  /**
   * Check if session is expired
   */
  private isSessionExpired(session: AuthenticationSession): boolean {
    return session.expiresAt < new Date();
  }

  /**
   * Hash data for integrity checking
   */
  private async hashData(data: ArrayBuffer): Promise<string> {
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return this.arrayBufferToBase64(hashBuffer);
  }

  /**
   * Convert ArrayBuffer to base64
   */
  private arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    const binary = Array.from(bytes, byte => String.fromCharCode(byte)).join('');
    return btoa(binary);
  }

  /**
   * Generate unique challenge ID
   */
  private generateChallengeId(): string {
    const timestamp = Date.now().toString(36);
    const random = crypto.getRandomValues(new Uint8Array(8));
    const randomHex = Array.from(random, b => b.toString(16).padStart(2, '0')).join('');
    return `challenge_${timestamp}_${randomHex}`;
  }

  /**
   * Generate unique session ID
   */
  private generateSessionId(): string {
    const timestamp = Date.now().toString(36);
    const random = crypto.getRandomValues(new Uint8Array(16));
    const randomHex = Array.from(random, b => b.toString(16).padStart(2, '0')).join('');
    return `session_${timestamp}_${randomHex}`;
  }

  /**
   * Start cleanup timer for expired challenges and sessions
   */
  private startCleanupTimer(): void {
    setInterval(() => {
      this.cleanupExpired();
    }, 60000); // Run every minute
  }

  /**
   * Clean up expired challenges and sessions
   */
  private cleanupExpired(): void {
    const now = new Date();
    let cleanedChallenges = 0;
    let cleanedSessions = 0;

    // Clean up expired challenges
    for (const [id, challenge] of this.activeChallenges.entries()) {
      if (challenge.expiresAt < now) {
        this.activeChallenges.delete(id);
        cleanedChallenges++;
      }
    }

    // Clean up expired sessions
    for (const [id, session] of this.activeSessions.entries()) {
      if (this.isSessionExpired(session)) {
        this.invalidateSession(id);
        cleanedSessions++;
      }
    }

    if (cleanedChallenges > 0 || cleanedSessions > 0) {
      console.log(`Cleaned up ${cleanedChallenges} challenges and ${cleanedSessions} sessions`);
    }
  }

  /**
   * Configure challenge-response settings
   */
  configure(config: Partial<ChallengeConfig>): void {
    this.config = { ...this.config, ...config };
  }

  /**
   * Get service statistics
   */
  getStats() {
    return {
      activeChallenges: this.activeChallenges.size,
      activeSessions: this.activeSessions.size,
      maxConcurrentChallenges: this.config.maxConcurrentChallenges,
      challengeExpirationTime: this.config.expirationTime,
      sessionsByToken: this.getSessionsByToken(),
    };
  }

  private getSessionsByToken() {
    const sessionsByToken: { [tokenId: string]: number } = {};
    for (const session of this.activeSessions.values()) {
      sessionsByToken[session.tokenId] = (sessionsByToken[session.tokenId] || 0) + 1;
    }
    return sessionsByToken;
  }
}

// Export singleton instance
export const challengeResponseAuth = new ChallengeResponseAuthService();
export default challengeResponseAuth;