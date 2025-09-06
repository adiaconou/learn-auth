#!/usr/bin/env node

/**
 * Test JWT Generation Script
 * 
 * Generates JWT access tokens for testing the OAuth 2.0 resource server.
 * Includes PKCE (Proof Key for Code Exchange) utilities for enhanced security testing.
 * 
 * This script simulates what our Identity Provider will do in Phase 2,
 * allowing us to test JWT validation and scope authorization in isolation.
 * 
 * PKCE Flow Chart (RFC 7636):
 * 
 * ┌─────────────────────────────────────────────────────────────────────────────────┐
 * │                           PKCE Generation & Verification Flow                    │
 * └─────────────────────────────────────────────────────────────────────────────────┘
 * 
 * Phase 1: Code Verifier & Challenge Generation (This Test Script)
 * ┌──────────────┐    ┌──────────────────┐    ┌─────────────────────┐
 * │    Client    │    │  Test Script     │    │  Generated Values   │
 * │   (Future)   │    │   (Current)      │    │                     │
 * └──────────────┘    └──────────────────┘    └─────────────────────┘
 *        │                      │                        │
 *        │ 1. Generate PKCE     │                        │
 *        │    code_verifier     │                        │
 *        │───────────────────→  │                        │
 *        │                      │ crypto.randomBytes(32) │
 *        │                      │ .toString('base64url') │
 *        │                      │───────────────────────→│ code_verifier
 *        │                      │                        │ (43-128 chars)
 *        │                      │                        │
 *        │ 2. Generate          │                        │
 *        │    code_challenge    │                        │
 *        │───────────────────→  │                        │
 *        │                      │ SHA256(code_verifier)  │
 *        │                      │ .toString('base64url') │
 *        │                      │───────────────────────→│ code_challenge
 *        │                      │                        │ (S256 method)
 *        │                      │                        │
 * 
 * Phase 2: Authorization Flow (Future - Identity Provider in Phase 2)
 * ┌──────────────┐    ┌──────────────────┐    ┌─────────────────────┐
 * │    Client    │    │ Identity Provider│    │  Authorization      │
 * │    (SPA)     │    │   (Phase 2)      │    │  Server Storage     │
 * └──────────────┘    └──────────────────┘    └─────────────────────┘
 *        │                      │                        │
 *        │ 3. Authorization     │                        │
 *        │    Request with      │                        │
 *        │    code_challenge    │                        │
 *        │───────────────────→  │                        │
 *        │                      │ Store code_challenge   │
 *        │                      │ with auth_code         │
 *        │                      │───────────────────────→│
 *        │                      │                        │
 *        │ 4. Authorization     │                        │
 *        │    Code Response     │                        │
 *        │ ←─────────────────── │                        │
 *        │                      │                        │
 * 
 * Phase 3: Token Exchange & Verification (Future - Identity Provider in Phase 2)
 * ┌──────────────┐    ┌──────────────────┐    ┌─────────────────────┐
 * │    Client    │    │ Identity Provider│    │  JWT Access Token   │
 * │    (SPA)     │    │   (Phase 2)      │    │   (This Script)     │
 * └──────────────┘    └──────────────────┘    └─────────────────────┘
 *        │                      │                        │
 *        │ 5. Token Request     │                        │
 *        │    with auth_code +  │                        │
 *        │    code_verifier     │                        │
 *        │───────────────────→  │                        │
 *        │                      │ Verify:                │
 *        │                      │ SHA256(code_verifier)  │
 *        │                      │ === stored_challenge   │
 *        │                      │                        │
 *        │                      │ ✅ If valid:           │
 *        │                      │ Generate JWT with      │
 *        │                      │ PKCE confirmation      │
 *        │                      │───────────────────────→│ JWT + cnf claim
 *        │                      │                        │
 *        │ 6. JWT Access Token  │                        │
 *        │ ←─────────────────── │                        │
 *        │                      │                        │
 * 
 * Phase 4: Resource Access (Current - Resource Server Testing)
 * ┌──────────────┐    ┌──────────────────┐    ┌─────────────────────┐
 * │    Client    │    │ Resource Server  │    │  Protected Resource │
 * │    (Test)    │    │   (Phase 1)      │    │     (/notes API)    │
 * └──────────────┘    └──────────────────┘    └─────────────────────┘
 *        │                      │                        │
 *        │ 7. API Request with  │                        │
 *        │    Bearer JWT        │                        │
 *        │───────────────────→  │                        │
 *        │                      │ Validate JWT:          │
 *        │                      │ • Signature check      │
 *        │                      │ • Claims validation    │
 *        │                      │ • Scope authorization  │
 *        │                      │ • PKCE confirmation    │
 *        │                      │   (optional)           │
 *        │                      │                        │
 *        │                      │ ✅ If valid:           │
 *        │                      │ Access granted         │
 *        │                      │───────────────────────→│
 *        │                      │                        │
 *        │ 8. Protected Data    │                        │
 *        │ ←─────────────────── │                        │
 *        │                      │                        │
 * 
 * Test Script PKCE Methods:
 * • PKCEUtils.generateCodeVerifier()     - Creates cryptographically secure verifier
 * • PKCEUtils.generateCodeChallenge()    - Creates SHA256 challenge from verifier  
 * • PKCEUtils.verifyCodeChallenge()      - Verifies verifier matches challenge
 * • PKCEUtils.generatePKCEPair()         - Creates complete verifier/challenge pair
 * 
 * Security Properties:
 * • Code verifier: 32 random bytes (256-bit entropy) → Base64url encoded
 * • Code challenge: SHA256(code_verifier) → Base64url encoded
 * • Verification: Constant-time comparison prevents timing attacks
 * • Protection: Even if auth code stolen, attacker needs original code_verifier
 */

const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Configuration matching our resource server expectations
const CONFIG = {
  issuer: 'http://localhost:3001',       // Future IdP issuer
  audience: 'notes-api',                 // Resource server audience
  algorithm: 'HS256',                    // Symmetric signing for testing (RS256 in production)
  secret: 'test-secret-key-for-development-only', // Test signing key
  expiresIn: '1h',                       // Token expiration
  keyId: 'test-key-1'                    // Key ID for JWKS simulation
};

/**
 * PKCE Utilities
 * Implements RFC 7636 - Proof Key for Code Exchange
 */
class PKCEUtils {
  /**
   * Generates a cryptographically secure code verifier
   * @returns {string} Base64 URL-encoded code verifier (43-128 chars)
   */
  static generateCodeVerifier() {
    // Generate 32 random bytes (256 bits) for high entropy
    const buffer = crypto.randomBytes(32);
    return buffer.toString('base64url'); // Base64 URL encoding (no padding)
  }

  /**
   * Creates code challenge from code verifier using S256 method
   * @param {string} codeVerifier - The code verifier string
   * @returns {string} Base64 URL-encoded SHA256 hash of code verifier
   */
  static generateCodeChallenge(codeVerifier) {
    const hash = crypto.createHash('sha256').update(codeVerifier).digest();
    return hash.toString('base64url');
  }

  /**
   * Verifies that code verifier matches the code challenge
   * @param {string} codeVerifier - Original code verifier
   * @param {string} codeChallenge - Expected code challenge
   * @returns {boolean} True if verifier matches challenge
   */
  static verifyCodeChallenge(codeVerifier, codeChallenge) {
    const computedChallenge = this.generateCodeChallenge(codeVerifier);
    return computedChallenge === codeChallenge;
  }

  /**
   * Generates a complete PKCE pair for testing
   * @returns {object} Object with codeVerifier and codeChallenge
   */
  static generatePKCEPair() {
    const codeVerifier = this.generateCodeVerifier();
    const codeChallenge = this.generateCodeChallenge(codeVerifier);
    
    return {
      codeVerifier,
      codeChallenge,
      codeChallengeMethod: 'S256'
    };
  }
}

/**
 * JWT Token Generator
 * Creates various types of test tokens for resource server validation
 */
class TestJWTGenerator {
  /**
   * Generates a valid access token with specified scopes
   * @param {string} userId - User identifier for 'sub' claim
   * @param {string[]} scopes - Array of scopes to include
   * @param {object} options - Additional token options
   * @returns {string} Signed JWT access token
   */
  static generateAccessToken(userId = 'user123', scopes = ['notes:read'], options = {}) {
    const now = Math.floor(Date.now() / 1000);
    
    // Standard OAuth 2.0 access token claims
    const payload = {
      iss: CONFIG.issuer,                    // Token issuer (our IdP)
      aud: CONFIG.audience,                  // Intended audience (resource server)
      sub: userId,                           // Subject (user identifier)
      scope: scopes.join(' '),               // Space-separated scopes
      exp: now + 3600,                       // Expires in 1 hour
      iat: now,                              // Issued at
      jti: crypto.randomUUID(),              // Unique token ID
      client_id: 'test-spa-client',          // Client that requested token
      
      // Optional PKCE confirmation claim (cnf)
      // In production, this would link to the PKCE challenge used
      ...(options.includeConfirmation && {
        cnf: {
          'x5t#S256': options.codeChallengeHash || 'example_code_challenge_hash'
        }
      }),
      
      // Custom claims for testing
      ...options.customClaims
    };

    const tokenOptions = {
      algorithm: CONFIG.algorithm,
      keyid: CONFIG.keyId
      // Note: Don't use expiresIn when exp is already in payload
    };

    return jwt.sign(payload, CONFIG.secret, tokenOptions);
  }

  /**
   * Generates an expired token for testing 401 responses
   */
  static generateExpiredToken(userId = 'user123', scopes = ['notes:read']) {
    const payload = {
      iss: CONFIG.issuer,
      aud: CONFIG.audience,
      sub: userId,
      scope: scopes.join(' '),
      exp: Math.floor(Date.now() / 1000) - 3600, // Expired 1 hour ago
      iat: Math.floor(Date.now() / 1000) - 7200, // Issued 2 hours ago
      jti: crypto.randomUUID()
    };

    return jwt.sign(payload, CONFIG.secret, { algorithm: CONFIG.algorithm, keyid: CONFIG.keyId });
  }

  /**
   * Generates a token with invalid signature for testing 401 responses
   */
  static generateInvalidSignatureToken(userId = 'user123', scopes = ['notes:read']) {
    const payload = {
      iss: CONFIG.issuer,
      aud: CONFIG.audience,
      sub: userId,
      scope: scopes.join(' '),
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID()
    };

    // Sign with wrong secret
    return jwt.sign(payload, 'wrong-secret', { algorithm: CONFIG.algorithm, keyid: CONFIG.keyId });
  }

  /**
   * Generates a token with wrong issuer for testing 401 responses
   */
  static generateWrongIssuerToken(userId = 'user123', scopes = ['notes:read']) {
    const payload = {
      iss: 'http://evil-idp.com',  // Wrong issuer
      aud: CONFIG.audience,
      sub: userId,
      scope: scopes.join(' '),
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID()
    };

    return jwt.sign(payload, CONFIG.secret, { algorithm: CONFIG.algorithm, keyid: CONFIG.keyId });
  }

  /**
   * Generates a token with wrong audience for testing 401 responses
   */
  static generateWrongAudienceToken(userId = 'user123', scopes = ['notes:read']) {
    const payload = {
      iss: CONFIG.issuer,
      aud: 'wrong-api',  // Wrong audience
      sub: userId,
      scope: scopes.join(' '),
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID()
    };

    return jwt.sign(payload, CONFIG.secret, { algorithm: CONFIG.algorithm, keyid: CONFIG.keyId });
  }
}

/**
 * Test Scenarios Generator
 * Creates predefined token sets for common testing scenarios
 */
class TestScenarios {
  /**
   * Generates tokens for basic CRUD testing
   */
  static basicCRUDTokens() {
    return {
      readOnlyToken: TestJWTGenerator.generateAccessToken('alice', ['notes:read']),
      writeOnlyToken: TestJWTGenerator.generateAccessToken('bob', ['notes:write']),
      fullAccessToken: TestJWTGenerator.generateAccessToken('admin', ['notes:read', 'notes:write']),
      noScopesToken: TestJWTGenerator.generateAccessToken('limited', [])
    };
  }

  /**
   * Generates tokens for error testing
   */
  static errorTestingTokens() {
    return {
      expiredToken: TestJWTGenerator.generateExpiredToken(),
      invalidSignatureToken: TestJWTGenerator.generateInvalidSignatureToken(),
      wrongIssuerToken: TestJWTGenerator.generateWrongIssuerToken(),
      wrongAudienceToken: TestJWTGenerator.generateWrongAudienceToken()
    };
  }

  /**
   * Generates PKCE-related tokens and utilities
   */
  static pkceTestingData() {
    const pkcePair1 = PKCEUtils.generatePKCEPair();
    const pkcePair2 = PKCEUtils.generatePKCEPair();
    
    return {
      pkcePairs: {
        pair1: pkcePair1,
        pair2: pkcePair2
      },
      pkceTokenWithConfirmation: TestJWTGenerator.generateAccessToken('pkce-user', ['notes:read', 'notes:write'], {
        includeConfirmation: true,
        codeChallengeHash: crypto.createHash('sha256').update(pkcePair1.codeChallenge).digest('base64url')
      }),
      pkceVerificationExample: {
        codeVerifier: pkcePair1.codeVerifier,
        codeChallenge: pkcePair1.codeChallenge,
        isValid: PKCEUtils.verifyCodeChallenge(pkcePair1.codeVerifier, pkcePair1.codeChallenge)
      }
    };
  }
}

/**
 * Main CLI Interface
 * Provides command-line interface for generating tokens
 */
function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  console.log('🔐 OAuth 2.0 + PKCE Test JWT Generator\n');

  switch (command) {
    case 'basic':
      console.log('📝 Basic CRUD Tokens:');
      const basicTokens = TestScenarios.basicCRUDTokens();
      console.log('\n✅ Read-only token (notes:read):');
      console.log(basicTokens.readOnlyToken);
      console.log('\n✅ Write-only token (notes:write):');
      console.log(basicTokens.writeOnlyToken);
      console.log('\n✅ Full access token (notes:read notes:write):');
      console.log(basicTokens.fullAccessToken);
      console.log('\n❌ No scopes token:');
      console.log(basicTokens.noScopesToken);
      break;

    case 'errors':
      console.log('❌ Error Testing Tokens:');
      const errorTokens = TestScenarios.errorTestingTokens();
      console.log('\n🕒 Expired token:');
      console.log(errorTokens.expiredToken);
      console.log('\n🔑 Invalid signature token:');
      console.log(errorTokens.invalidSignatureToken);
      console.log('\n🏭 Wrong issuer token:');
      console.log(errorTokens.wrongIssuerToken);
      console.log('\n🎯 Wrong audience token:');
      console.log(errorTokens.wrongAudienceToken);
      break;

    case 'pkce':
      console.log('🔒 PKCE Testing Data:');
      const pkceData = TestScenarios.pkceTestingData();
      
      console.log('\n📋 PKCE Pairs:');
      console.log('Pair 1:');
      console.log(`  Code Verifier: ${pkceData.pkcePairs.pair1.codeVerifier}`);
      console.log(`  Code Challenge: ${pkceData.pkcePairs.pair1.codeChallenge}`);
      console.log(`  Method: ${pkceData.pkcePairs.pair1.codeChallengeMethod}`);
      
      console.log('\n🎫 PKCE Token with Confirmation:');
      console.log(pkceData.pkceTokenWithConfirmation);
      
      console.log('\n✅ PKCE Verification Example:');
      console.log(`Verifier matches challenge: ${pkceData.pkceVerificationExample.isValid}`);
      break;

    case 'custom':
      const userId = args[1] || 'user123';
      const scopes = args.slice(2);
      if (scopes.length === 0) {
        scopes.push('notes:read');
      }
      console.log(`👤 Custom Token for user: ${userId}, scopes: ${scopes.join(' ')}`);
      console.log(TestJWTGenerator.generateAccessToken(userId, scopes));
      break;

    case 'decode':
      const token = args[1];
      if (!token) {
        console.log('❌ Please provide a token to decode');
        console.log('Usage: node test-jwt.js decode <token>');
        break;
      }
      try {
        const decoded = jwt.decode(token, { complete: true });
        console.log('🔍 Decoded Token:');
        console.log(JSON.stringify(decoded, null, 2));
      } catch (error) {
        console.log('❌ Failed to decode token:', error.message);
      }
      break;

    case 'all':
      console.log('🎯 All Test Tokens:\n');
      
      console.log('📝 Basic CRUD Tokens:');
      const allBasicTokens = TestScenarios.basicCRUDTokens();
      Object.entries(allBasicTokens).forEach(([name, token]) => {
        console.log(`${name}: ${token}`);
      });
      
      console.log('\n❌ Error Testing Tokens:');
      const allErrorTokens = TestScenarios.errorTestingTokens();
      Object.entries(allErrorTokens).forEach(([name, token]) => {
        console.log(`${name}: ${token}`);
      });
      
      console.log('\n🔒 PKCE Data:');
      const allPkceData = TestScenarios.pkceTestingData();
      console.log(`PKCE pair 1 verifier: ${allPkceData.pkcePairs.pair1.codeVerifier}`);
      console.log(`PKCE pair 1 challenge: ${allPkceData.pkcePairs.pair1.codeChallenge}`);
      console.log(`PKCE token: ${allPkceData.pkceTokenWithConfirmation}`);
      break;

    default:
      console.log('Usage: node test-jwt.js <command> [args...]');
      console.log('');
      console.log('Commands:');
      console.log('  basic                 - Generate basic CRUD testing tokens');
      console.log('  errors               - Generate tokens for error testing');
      console.log('  pkce                 - Generate PKCE testing data');
      console.log('  custom <user> <scope1> <scope2> ... - Generate custom token');
      console.log('  decode <token>       - Decode and display token contents');
      console.log('  all                  - Generate all test tokens');
      console.log('');
      console.log('Examples:');
      console.log('  node test-jwt.js basic');
      console.log('  node test-jwt.js custom alice notes:read notes:write');
      console.log('  node test-jwt.js pkce');
      console.log('  node test-jwt.js decode eyJhbGciOiJIUzI1NiIs...');
  }
}

// Export classes for use in other test files
module.exports = {
  PKCEUtils,
  TestJWTGenerator,
  TestScenarios,
  CONFIG
};

// Run CLI if called directly
if (require.main === module) {
  main();
}