/**
 * PKCE (Proof Key for Code Exchange) Service
 * 
 * Implements RFC 7636 PKCE extension to OAuth 2.0 for public clients.
 * PKCE prevents authorization code interception attacks by requiring
 * the client to prove they initiated the original authorization request.
 * 
 * Key concepts:
 * - code_verifier: Cryptographically random string (43-128 chars)
 * - code_challenge: SHA256 hash of code_verifier, base64url encoded
 * - code_challenge_method: Only "S256" supported (most secure)
 * 
 * Security benefits:
 * - Prevents code interception attacks on mobile/SPA clients
 * - No client secret required for public clients
 * - Dynamic secret per authorization request
 */

import { createHash } from 'crypto';
import { debugLog } from '../config';

/**
 * PKCE Validation Result
 */
export interface PKCEValidationResult {
  isValid: boolean;
  error?: string;
  errorDescription?: string;
}

/**
 * PKCE Challenge Validation Result
 */
export interface PKCEChallengeValidationResult {
  isValid: boolean;
  codeChallenge?: string;
  error?: string;
  errorDescription?: string;
}

/**
 * PKCE Service Class
 * 
 * Handles PKCE parameter validation according to RFC 7636.
 * Ensures code_verifier/code_challenge pairs are cryptographically valid.
 */
export class PKCEService {

  /**
   * Validate PKCE code challenge parameters
   * 
   * Validates code_challenge and code_challenge_method according to RFC 7636.
   * Only S256 method is supported for maximum security.
   * 
   * @param codeChallenge Base64url encoded SHA256 hash of code_verifier
   * @param codeChallengeMethod Challenge method (must be "S256")
   * @returns PKCE challenge validation result
   */
  validateChallenge(codeChallenge: string, codeChallengeMethod: string): PKCEChallengeValidationResult {
    debugLog('PKCE', `Validating challenge: method=${codeChallengeMethod}, challenge=${codeChallenge.substring(0, 8)}...`);

    // Validate challenge method
    if (codeChallengeMethod !== 'S256') {
      debugLog('PKCE', `Invalid challenge method: ${codeChallengeMethod}`);
      return {
        isValid: false,
        error: 'invalid_request',
        errorDescription: 'code_challenge_method must be S256'
      };
    }

    // Validate challenge format (base64url encoded SHA256 hash)
    if (!this.isValidBase64Url(codeChallenge)) {
      debugLog('PKCE', 'Invalid code_challenge format');
      return {
        isValid: false,
        error: 'invalid_request',
        errorDescription: 'code_challenge must be base64url encoded'
      };
    }

    // SHA256 hash is 32 bytes = 256 bits
    // Base64url encoding: 4 chars per 3 bytes, so 32 bytes = ~43 chars
    if (codeChallenge.length !== 43) {
      debugLog('PKCE', `Invalid code_challenge length: ${codeChallenge.length}`);
      return {
        isValid: false,
        error: 'invalid_request',
        errorDescription: 'code_challenge has invalid length for SHA256 hash'
      };
    }

    debugLog('PKCE', 'Challenge validation successful');
    return {
      isValid: true,
      codeChallenge
    };
  }

  /**
   * Validate PKCE code verifier
   * 
   * Validates code_verifier length and format according to RFC 7636.
   * Must be 43-128 characters using unreserved characters.
   * 
   * @param codeVerifier Original random string from client
   * @returns PKCE validation result
   */
  validateVerifier(codeVerifier: string): PKCEValidationResult {
    debugLog('PKCE', `Validating verifier: length=${codeVerifier.length}, value=${codeVerifier.substring(0, 8)}...`);

    // Validate length (RFC 7636 section 4.1)
    if (codeVerifier.length < 43 || codeVerifier.length > 128) {
      debugLog('PKCE', `Invalid verifier length: ${codeVerifier.length}`);
      return {
        isValid: false,
        error: 'invalid_grant',
        errorDescription: 'code_verifier length must be 43-128 characters'
      };
    }

    // Validate character set (RFC 7636: unreserved characters only)
    // unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
    const validPattern = /^[A-Za-z0-9\-._~]+$/;
    if (!validPattern.test(codeVerifier)) {
      debugLog('PKCE', 'Invalid verifier character set');
      return {
        isValid: false,
        error: 'invalid_grant',
        errorDescription: 'code_verifier contains invalid characters'
      };
    }

    debugLog('PKCE', 'Verifier validation successful');
    return {
      isValid: true
    };
  }

  /**
   * Verify PKCE challenge/verifier pair
   * 
   * Core PKCE validation: verify that code_challenge matches
   * the SHA256 hash of code_verifier. This proves the client
   * that is exchanging the code is the same one that initiated
   * the authorization request.
   * 
   * @param codeVerifier Original random string from token request
   * @param storedCodeChallenge Stored challenge from authorization request
   * @param codeChallengeMethod Challenge method (should be "S256")
   * @returns PKCE validation result
   */
  verifyChallenge(
    codeVerifier: string, 
    storedCodeChallenge: string, 
    codeChallengeMethod: string = 'S256'
  ): PKCEValidationResult {
    debugLog('PKCE', 'Starting PKCE challenge verification');
    debugLog('PKCE', `Verifier: ${codeVerifier.substring(0, 8)}... (length: ${codeVerifier.length})`);
    debugLog('PKCE', `Stored challenge: ${storedCodeChallenge.substring(0, 8)}...`);
    debugLog('PKCE', `Method: ${codeChallengeMethod}`);

    // Step 1: Validate code verifier
    const verifierValidation = this.validateVerifier(codeVerifier);
    if (!verifierValidation.isValid) {
      return verifierValidation;
    }

    // Step 2: Validate challenge method
    if (codeChallengeMethod !== 'S256') {
      debugLog('PKCE', `Unsupported challenge method: ${codeChallengeMethod}`);
      return {
        isValid: false,
        error: 'invalid_grant',
        errorDescription: 'Unsupported code_challenge_method'
      };
    }

    // Step 3: Generate challenge from verifier and compare
    try {
      const computedChallenge = this.generateChallengeFromVerifier(codeVerifier);
      
      debugLog('PKCE', `Computed challenge: ${computedChallenge.substring(0, 8)}...`);
      
      // Perform constant-time comparison to prevent timing attacks
      if (!this.constantTimeEquals(computedChallenge, storedCodeChallenge)) {
        debugLog('PKCE', 'PKCE verification failed: challenge mismatch');
        return {
          isValid: false,
          error: 'invalid_grant',
          errorDescription: 'PKCE verification failed'
        };
      }

      debugLog('PKCE', 'PKCE verification successful');
      return {
        isValid: true
      };

    } catch (error) {
      debugLog('PKCE', `PKCE verification error: ${error}`);
      return {
        isValid: false,
        error: 'server_error',
        errorDescription: 'PKCE verification failed due to server error'
      };
    }
  }

  /**
   * Generate code challenge from verifier
   * 
   * Implements the S256 transform: BASE64URL(SHA256(code_verifier))
   * 
   * @param codeVerifier Original random string
   * @returns Base64url encoded SHA256 hash
   */
  private generateChallengeFromVerifier(codeVerifier: string): string {
    // Create SHA256 hash
    const hash = createHash('sha256');
    hash.update(codeVerifier, 'ascii');
    const digest = hash.digest();

    // Convert to base64url encoding
    return this.base64UrlEncode(digest);
  }

  /**
   * Base64url encode buffer
   * 
   * Base64url is base64 with URL-safe characters:
   * - Replace + with -
   * - Replace / with _
   * - Remove padding =
   * 
   * @param buffer Buffer to encode
   * @returns Base64url encoded string
   */
  private base64UrlEncode(buffer: Buffer): string {
    return buffer
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Validate base64url format
   * 
   * @param value String to validate
   * @returns True if valid base64url
   */
  private isValidBase64Url(value: string): boolean {
    // Base64url uses A-Z, a-z, 0-9, -, _ (no padding)
    const base64UrlPattern = /^[A-Za-z0-9\-_]+$/;
    return base64UrlPattern.test(value);
  }

  /**
   * Constant-time string comparison
   * 
   * Prevents timing attacks by ensuring comparison time
   * doesn't depend on where strings first differ.
   * 
   * @param a First string
   * @param b Second string
   * @returns True if strings are equal
   */
  private constantTimeEquals(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false;
    }

    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }

    return result === 0;
  }

  /**
   * Generate example PKCE parameters for testing/documentation
   * 
   * @returns Example PKCE parameters
   */
  generateExampleParams(): { codeVerifier: string; codeChallenge: string; codeChallengeMethod: string } {
    // Generate a random code verifier for demonstration
    const codeVerifier = this.generateRandomVerifier();
    const codeChallenge = this.generateChallengeFromVerifier(codeVerifier);
    
    return {
      codeVerifier,
      codeChallenge,
      codeChallengeMethod: 'S256'
    };
  }

  /**
   * Generate cryptographically secure code verifier
   * 
   * @returns Random code verifier string
   */
  private generateRandomVerifier(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
    const length = 128; // Maximum length for best entropy
    
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    
    return result;
  }
}

// Export singleton instance
export const pkceService = new PKCEService();
export default pkceService;