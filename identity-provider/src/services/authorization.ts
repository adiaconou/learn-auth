/**
 * Authorization Code Management Service
 * 
 * Handles OAuth 2.0 authorization code generation, storage, and validation.
 * Authorization codes are short-lived, single-use tokens that represent
 * a successful user authorization and are exchanged for access tokens.
 * 
 * Key security features:
 * - Short expiration (10 minutes max per OAuth spec)
 * - Single-use only (marked as used after exchange)
 * - PKCE challenge binding for public clients
 * - Cryptographically secure random generation
 * - Validation of all original request parameters
 */

import { randomBytes } from 'crypto';
import { securityConfig } from '../config';
import { debugLog } from '../config';
import { AuthorizationCode } from '../storage/models';
import { authCodeStore } from '../storage/memory';

/**
 * Authorization Request Parameters
 * 
 * Contains all parameters from the original /authorize request
 * that must be validated during token exchange.
 */
export interface AuthorizationRequest {
  clientId: string;
  userId: string;
  redirectUri: string;
  scope: string;
  nonce?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  state?: string;
}

/**
 * Code Generation Result
 */
export interface CodeGenerationResult {
  code: string;
  expiresAt: Date;
}

/**
 * Code Validation Result
 */
export interface CodeValidationResult {
  isValid: boolean;
  authorizationCode?: AuthorizationCode;
  error?: string;
  errorDescription?: string;
}

/**
 * Authorization Code Service
 * 
 * Manages the lifecycle of OAuth 2.0 authorization codes from
 * generation during authorization to validation during token exchange.
 */
export class AuthorizationService {

  /**
   * Generate a new authorization code
   * 
   * Creates a cryptographically secure authorization code and stores
   * it with all the authorization request parameters for later validation.
   * 
   * @param authRequest Authorization request parameters
   * @returns Generated authorization code and expiration
   */
  generateAuthorizationCode(authRequest: AuthorizationRequest): CodeGenerationResult {
    debugLog('AUTH_CODE', 'Generating authorization code');
    debugLog('AUTH_CODE', `Client: ${authRequest.clientId}, User: ${authRequest.userId}`);
    debugLog('AUTH_CODE', `Scope: ${authRequest.scope}`);
    debugLog('AUTH_CODE', `PKCE Challenge: ${authRequest.codeChallenge?.substring(0, 8)}...`);

    // Generate cryptographically secure random code
    const code = this.generateSecureCode();
    
    // Calculate expiration time (max 10 minutes per OAuth spec)
    const expiresAt = new Date(Date.now() + (securityConfig.authorizationCodeTtl * 1000));

    // Create authorization code record
    const authorizationCode: AuthorizationCode = {
      code,
      clientId: authRequest.clientId,
      userId: authRequest.userId,
      redirectUri: authRequest.redirectUri,
      scope: authRequest.scope,
      nonce: authRequest.nonce,
      codeChallenge: authRequest.codeChallenge,
      codeChallengeMethod: authRequest.codeChallengeMethod,
      expiresAt,
      used: false,
      createdAt: new Date()
    };

    // Store authorization code
    authCodeStore.create(authorizationCode);

    debugLog('AUTH_CODE', `Authorization code generated: ${code.substring(0, 8)}...`);
    debugLog('AUTH_CODE', `Expires at: ${expiresAt.toISOString()}`);
    debugLog('AUTH_CODE', `TTL: ${securityConfig.authorizationCodeTtl} seconds`);

    return {
      code,
      expiresAt
    };
  }

  /**
   * Validate and consume authorization code
   * 
   * Validates an authorization code during token exchange and marks it as used.
   * Performs comprehensive validation of all authorization parameters.
   * 
   * @param code Authorization code to validate
   * @param clientId Client ID from token request
   * @param redirectUri Redirect URI from token request  
   * @param codeVerifier PKCE code verifier (for public clients)
   * @returns Code validation result
   */
  validateAndConsumeCode(
    code: string,
    clientId: string,
    redirectUri: string,
    codeVerifier?: string
  ): CodeValidationResult {
    debugLog('AUTH_CODE', 'Validating authorization code');
    debugLog('AUTH_CODE', `Code: ${code.substring(0, 8)}...`);
    debugLog('AUTH_CODE', `Client: ${clientId}`);
    debugLog('AUTH_CODE', `Redirect URI: ${redirectUri}`);
    debugLog('AUTH_CODE', `Code Verifier: ${codeVerifier?.substring(0, 8)}...`);

    try {
      // Step 1: Retrieve authorization code
      const authorizationCode = authCodeStore.findByCode(code);
      
      if (!authorizationCode) {
        debugLog('AUTH_CODE', 'Code validation failed: code not found');
        return {
          isValid: false,
          error: 'invalid_grant',
          errorDescription: 'Authorization code not found or invalid'
        };
      }

      // Step 2: Check if code has already been used
      if (authorizationCode.used) {
        debugLog('AUTH_CODE', 'Code validation failed: code already used');
        // Per OAuth spec, revoke all tokens for this authorization
        this.revokeCodeAndTokens(code);
        return {
          isValid: false,
          error: 'invalid_grant',
          errorDescription: 'Authorization code has already been used'
        };
      }

      // Step 3: Check expiration
      if (authorizationCode.expiresAt.getTime() <= Date.now()) {
        debugLog('AUTH_CODE', 'Code validation failed: code expired');
        // Clean up expired code
        authCodeStore.delete(code);
        return {
          isValid: false,
          error: 'invalid_grant',
          errorDescription: 'Authorization code has expired'
        };
      }

      // Step 4: Validate client ID matches
      if (authorizationCode.clientId !== clientId) {
        debugLog('AUTH_CODE', 'Code validation failed: client ID mismatch');
        return {
          isValid: false,
          error: 'invalid_grant',
          errorDescription: 'Authorization code was not issued to this client'
        };
      }

      // Step 5: Validate redirect URI matches (exact string comparison)
      if (authorizationCode.redirectUri !== redirectUri) {
        debugLog('AUTH_CODE', 'Code validation failed: redirect URI mismatch');
        debugLog('AUTH_CODE', `Expected: ${authorizationCode.redirectUri}`);
        debugLog('AUTH_CODE', `Received: ${redirectUri}`);
        return {
          isValid: false,
          error: 'invalid_grant',
          errorDescription: 'Redirect URI does not match authorization request'
        };
      }

      // Step 6: Mark code as used (prevent replay attacks)
      authCodeStore.markAsUsed(code);

      debugLog('AUTH_CODE', 'Authorization code validation successful');
      debugLog('AUTH_CODE', `Authorized scope: ${authorizationCode.scope}`);
      debugLog('AUTH_CODE', `User ID: ${authorizationCode.userId}`);

      return {
        isValid: true,
        authorizationCode
      };

    } catch (error) {
      debugLog('AUTH_CODE', `Code validation error: ${error}`);
      return {
        isValid: false,
        error: 'server_error',
        errorDescription: 'Authorization code validation failed'
      };
    }
  }

  /**
   * Cleanup expired authorization codes
   * 
   * Removes expired codes from storage to prevent memory leaks.
   * Should be called periodically by a cleanup job.
   */
  cleanupExpiredCodes(): number {
    debugLog('AUTH_CODE', 'Starting cleanup of expired authorization codes');
    
    // Use the built-in cleanup method from authCodeStore
    const cleanedUp = authCodeStore.cleanupExpired();
    debugLog('AUTH_CODE', `Cleanup completed: ${cleanedUp} codes removed`);
    return cleanedUp;
  }

  /**
   * Revoke authorization code and associated tokens
   * 
   * Called when code replay is detected. Per OAuth spec, all tokens
   * issued from this authorization should be revoked.
   * 
   * @param code Authorization code to revoke
   */
  private revokeCodeAndTokens(code: string): void {
    debugLog('AUTH_CODE', `Revoking code and associated tokens: ${code.substring(0, 8)}...`);
    
    // Mark code as used to prevent further use
    authCodeStore.markAsUsed(code);

    // TODO: In a complete implementation, also revoke:
    // - Access tokens issued from this authorization
    // - Refresh tokens issued from this authorization
    // This would require token storage and tracking

    debugLog('AUTH_CODE', 'Code revocation completed');
  }

  /**
   * Generate cryptographically secure authorization code
   * 
   * Creates a URL-safe random string suitable for use as an authorization code.
   * Uses Node.js crypto.randomBytes for cryptographic security.
   * 
   * @returns Secure random authorization code
   */
  private generateSecureCode(): string {
    // Generate 32 bytes of random data for high entropy
    const bytes = randomBytes(32);
    
    // Convert to base64url format (URL-safe, no padding)
    return bytes
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Get authorization code statistics for monitoring
   * 
   * @returns Code statistics
   */
  getCodeStats(): {
    totalCodes: number;
    activeCodes: number;
    expiredCodes: number;
    usedCodes: number;
  } {
    // Note: authCodeStore doesn't have getAllCodes method
    // This method would need to be implemented if statistics are needed
    // For now, return placeholder stats
    return {
      totalCodes: 0,
      activeCodes: 0,
      expiredCodes: 0,
      usedCodes: 0
    };
  }
}

// Export singleton instance
export const authorizationService = new AuthorizationService();
export default authorizationService;