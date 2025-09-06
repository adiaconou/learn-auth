/**
 * Cryptographic Utilities for OAuth 2.0 PKCE
 * 
 * Implements PKCE (Proof Key for Code Exchange) RFC 7636 for secure
 * OAuth 2.0 authorization in public clients (SPAs).
 * 
 * Key concepts:
 * - Code Verifier: Cryptographically random string (43-128 chars)
 * - Code Challenge: SHA256 hash of verifier, base64url encoded
 * - PKCE prevents authorization code interception attacks
 */

import { debugLog } from '../config';

/**
 * PKCE Parameters Interface
 */
export interface PKCEParams {
  codeVerifier: string;           // Random string (43-128 characters)
  codeChallenge: string;          // SHA256(codeVerifier) base64url encoded
  codeChallengeMethod: 'S256';    // Hash method (always S256)
}

/**
 * Generate a cryptographically secure random string
 * 
 * Used for PKCE code verifier and OAuth state/nonce parameters.
 * Uses browser's crypto.getRandomValues for security.
 * 
 * @param length - Length of random string (default: 128, max for PKCE)
 * @param enforcePKCELength - Whether to enforce PKCE length limits (43-128 chars)
 * @returns Base64url encoded random string
 */
export function generateRandomString(length: number = 128, enforcePKCELength: boolean = false): string {
  debugLog('CRYPTO', `Generating random string of length ${length}`);
  
  // Validate length for PKCE compliance only if specifically requested
  if (enforcePKCELength && (length < 43 || length > 128)) {
    throw new Error(`Invalid length ${length}. PKCE code verifier must be 43-128 characters.`);
  }
  
  // General validation for reasonable length limits
  if (length < 1 || length > 256) {
    throw new Error(`Invalid length ${length}. Must be between 1-256 characters.`);
  }
  
  // Generate random bytes using browser crypto API
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  
  // Convert to base64url encoding (RFC 4648)
  const randomString = base64UrlEncode(array);
  
  debugLog('CRYPTO', `Generated random string: ${randomString.substring(0, 10)}... (${randomString.length} chars)`);
  return randomString;
}

/**
 * Base64url encode a byte array
 * 
 * Base64url encoding (RFC 4648 Section 5) is base64 with:
 * - '+' replaced with '-'
 * - '/' replaced with '_'  
 * - Padding '=' characters removed
 * 
 * Required for PKCE code challenge and JWT handling.
 * 
 * @param buffer - Byte array to encode
 * @returns Base64url encoded string
 */
export function base64UrlEncode(buffer: ArrayBuffer | Uint8Array): string {
  debugLog('CRYPTO', `Encoding ${buffer.byteLength} bytes to base64url`);
  
  // Convert to Uint8Array if needed
  const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer;
  
  // Convert bytes to binary string
  let binaryString = '';
  for (let i = 0; i < bytes.length; i++) {
    binaryString += String.fromCharCode(bytes[i]);
  }
  
  // Encode to base64 then convert to base64url
  const base64String = btoa(binaryString);
  const base64UrlString = base64String
    .replace(/\+/g, '-')    // Replace + with -
    .replace(/\//g, '_')    // Replace / with _
    .replace(/=/g, '');     // Remove padding
  
  debugLog('CRYPTO', `Base64url encoded: ${base64UrlString.substring(0, 20)}...`);
  return base64UrlString;
}

/**
 * Generate SHA256 hash of input string
 * 
 * Used for PKCE code challenge generation.
 * Uses browser's SubtleCrypto API for secure hashing.
 * 
 * @param input - String to hash
 * @returns Promise resolving to SHA256 hash as ArrayBuffer
 */
export async function sha256Hash(input: string): Promise<ArrayBuffer> {
  debugLog('CRYPTO', `Computing SHA256 hash of input: ${input.substring(0, 20)}...`);
  
  // Encode string as UTF-8 bytes
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  
  // Compute SHA256 hash using SubtleCrypto
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  
  debugLog('CRYPTO', `SHA256 hash computed: ${hashBuffer.byteLength} bytes`);
  return hashBuffer;
}

/**
 * Generate PKCE parameters for OAuth 2.0 authorization
 * 
 * Creates a complete PKCE parameter set according to RFC 7636:
 * 1. Generate random code verifier (128 characters for max entropy)
 * 2. Compute SHA256 hash of code verifier
 * 3. Base64url encode the hash as code challenge
 * 
 * The code verifier is kept secret by the client.
 * The code challenge is sent to the authorization server.
 * 
 * @returns Promise resolving to PKCE parameters
 */
export async function generatePKCEParams(): Promise<PKCEParams> {
  console.log('🔐 Generating PKCE parameters for OAuth 2.0 flow...');
  
  try {
    // Step 1: Generate cryptographically random code verifier
    const codeVerifier = generateRandomString(128, true); // Maximum entropy with PKCE validation
    debugLog('PKCE', `Code verifier generated: ${codeVerifier.length} characters`);
    
    // Step 2: Compute SHA256 hash of code verifier
    const hashBuffer = await sha256Hash(codeVerifier);
    
    // Step 3: Base64url encode the hash as code challenge
    const codeChallenge = base64UrlEncode(hashBuffer);
    debugLog('PKCE', `Code challenge generated: ${codeChallenge}`);
    
    const pkceParams: PKCEParams = {
      codeVerifier,
      codeChallenge,
      codeChallengeMethod: 'S256',
    };
    
    console.log('✅ PKCE parameters generated successfully:');
    console.log(`   • Code Challenge Method: S256`);
    console.log(`   • Code Challenge: ${codeChallenge}`);
    console.log(`   • Code Verifier: [HIDDEN - ${codeVerifier.length} chars]`);
    
    return pkceParams;
    
  } catch (error) {
    console.error('❌ Failed to generate PKCE parameters:', error);
    throw new Error(`PKCE generation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Validate PKCE code verifier format
 * 
 * Ensures code verifier meets RFC 7636 requirements:
 * - Length: 43-128 characters
 * - Characters: [A-Z] [a-z] [0-9] "-" "." "_" "~"
 * 
 * @param codeVerifier - Code verifier to validate
 * @returns True if valid, false otherwise
 */
export function validateCodeVerifier(codeVerifier: string): boolean {
  debugLog('CRYPTO', `Validating code verifier: ${codeVerifier.length} chars`);
  
  // Check length requirement (RFC 7636)
  if (codeVerifier.length < 43 || codeVerifier.length > 128) {
    debugLog('CRYPTO', `Invalid length: ${codeVerifier.length} (must be 43-128)`);
    return false;
  }
  
  // Check character set requirement (RFC 7636)
  const validPattern = /^[A-Za-z0-9\-._~]+$/;
  const isValid = validPattern.test(codeVerifier);
  
  debugLog('CRYPTO', `Code verifier validation result: ${isValid ? 'VALID' : 'INVALID'}`);
  return isValid;
}

/**
 * Generate secure state parameter for OAuth 2.0
 * 
 * The state parameter prevents CSRF attacks during OAuth flow.
 * Must be unguessable and tied to the user's session.
 * 
 * @returns Random state string
 */
export function generateState(): string {
  const state = generateRandomString(32);
  debugLog('OAUTH', `State parameter generated: ${state}`);
  return state;
}

/**
 * Generate nonce for OpenID Connect
 * 
 * The nonce prevents replay attacks on ID tokens.
 * Must be unique for each authentication request.
 * 
 * @returns Random nonce string
 */
export function generateNonce(): string {
  const nonce = generateRandomString(32);
  debugLog('OIDC', `Nonce generated: ${nonce}`);
  return nonce;
}