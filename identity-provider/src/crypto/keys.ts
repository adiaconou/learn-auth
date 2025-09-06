import { generateKeyPairSync } from 'crypto';
import { pki } from 'node-forge';
import { securityConfig } from '../config';

/**
 * Cryptographic Key Management for JWT Signing
 * 
 * This module handles RSA key pair generation and management for JWT token signing.
 * In production, keys should be:
 * - Generated once and stored securely (HSM, Key Vault, etc.)
 * - Rotated regularly (every 6-12 months)
 * - Protected with proper access controls
 * 
 * For this learning project, we generate keys at startup for simplicity.
 * 
 * Key Security Concepts:
 * - RSA Keys: Asymmetric encryption where private key signs, public key verifies
 * - Key ID (kid): Identifies which key was used for signing (supports key rotation)
 * - PEM Format: Standard format for storing cryptographic keys as base64-encoded text
 * - JWKS: JSON Web Key Set format for publishing public keys to token consumers
 * 
 * Key Generation Sequence:
 * ```
 * ┌────────────────────┐    ┌─────────────────┐    ┌──────────────────┐
 * │    Application     │    │  keys.ts Module │    │   Node.js Crypto │
 * │     Startup        │    │  (This Module)  │    │     Module       │
 * └────────────────────┘    └─────────────────┘    └──────────────────┘
 *           │                        │                       │
 *           │ 1. getCurrentKeyPair() │                       │
 *           ├───────────────────────►│                       │
 *           │                        │                       │
 *           │                        │ 2. Check if key exists│
 *           │                        │    (currentKeyPair)   │
 *           │                        │                       │
 *           │                        │ 3. generateRSAKeyPair()│
 *           │                        │◄──────────────────────┤
 *           │                        │                       │
 *           │                        │ 4. generateKeyPairSync()│
 *           │                        ├──────────────────────►│
 *           │                        │   ('rsa', {options})  │
 *           │                        │                       │
 *           │                        │ 5. RSA Key Pair      │
 *           │                        │   {privateKey, publicKey}│
 *           │                        │◄──────────────────────┤
 *           │                        │                       │
 *           │                        │ 6. Create KeyPair obj │
 *           │                        │   + keyId + algorithm │
 *           │                        │                       │
 *           │                        │ 7. Store in memory    │
 *           │                        │   (currentKeyPair)    │
 *           │                        │                       │
 *           │ 8. Return KeyPair      │                       │
 *           │◄───────────────────────┤                       │
 *           │                        │                       │
 *           │ 9. generateJWKS()      │                       │
 *           ├───────────────────────►│                       │
 *           │                        │                       │
 *           │                        │ 10. pemToJwk()        │
 *           │                        │     Parse PEM → JWK   │
 *           │                        │                       │
 *           │ 11. JWKS Response      │                       │
 *           │◄───────────────────────┤                       │
 *           │                        │                       │
 * ```
 * 
 * JWT Signature & Verification Flow:
 * ```
 * ┌─────────────────────┐         ┌─────────────────────┐         ┌─────────────────────┐
 * │   Identity Provider │         │    Resource Server  │         │      Client App     │
 * │    (This Module)    │         │     (Phase 1)       │         │      (Phase 3)      │
 * └─────────────────────┘         └─────────────────────┘         └─────────────────────┘
 *           │                               │                               │
 *           │ 1. Sign JWT with Private Key  │                               │
 *           │    Header: {"alg":"RS256",    │                               │
 *           │             "kid":"key-id"}   │                               │
 *           │    Signature: RSA-SHA256      │                               │
 *           │                               │                               │
 *           │ 2. Send JWT Access Token      │                               │
 *           ├──────────────────────────────────────────────────────────────►│
 *           │                               │                               │
 *           │                               │ 3. API Request + JWT          │
 *           │                               │◄──────────────────────────────┤
 *           │                               │                               │
 *           │                               │ 4. GET /.well-known/jwks.json│
 *           │                               │    (Fetch public keys)        │
 *           │◄──────────────────────────────┤                               │
 *           │                               │                               │
 *           │ 5. Return JWKS                │                               │
 *           │    {keys: [{kty, n, e, kid}]} │                               │
 *           ├──────────────────────────────►│                               │
 *           │                               │                               │
 *           │                               │ 6. Find key by kid            │
 *           │                               │    Extract n, e → Public Key  │
 *           │                               │                               │
 *           │                               │ 7. Verify JWT Signature       │
 *           │                               │    ✅ Valid = Allow Access    │
 *           │                               │    ❌ Invalid = 401 Error     │
 *           │                               │                               │
 *           │                               │ 8. API Response               │
 *           │                               ├──────────────────────────────►│
 * ```
 * 
 * Key Management Lifecycle:
 * ```
 * [Key Generation] → [PEM Storage] → [JWK Conversion] → [JWKS Publication]
 *        ↓                                                       ↓
 * [JWT Signing] ←──────────── [Private Key] ──────────── [Resource Server
 *     ↓                                                   Verification]
 * [Token Issuance] ──────────────────────────────────────────────┘
 * ```
 * 
 * ## API Summary
 * 
 * ### Core Key Management
 * - `generateRSAKeyPair(keySize)` - Generate new RSA key pair with specified bit length
 * - `getCurrentKeyPair()` - Get active key pair (generates if none exists)
 * - `rotateKeyPair(keySize)` - Generate new key pair for key rotation scenarios
 * 
 * ### JWT/JWKS Integration
 * - `pemToJwk(publicKeyPem, keyId)` - Convert PEM public key to JWK format
 * - `generateJWKS()` - Create JSON Web Key Set for /.well-known/jwks.json endpoint
 * 
 * ### Utilities & Validation
 * - `validateKeyConfiguration()` - Validate key format and configuration
 * - `logKeyInfo()` - Log key information for debugging (private key redacted)
 * - `base64urlEncode(buffer)` - Convert buffer to base64url encoding (JWT standard)
 * 
 * ### Key Interfaces
 * - `KeyPair` - RSA key pair with metadata (privateKey, publicKey, keyId, algorithm)
 * - `JsonWebKey` - JWK format for JWKS publication (kty, use, alg, kid, n, e)
 * - `JsonWebKeySet` - JWKS response format containing array of JWKs
 * 
 * ### Usage Examples
 * ```typescript
 * // Get current key pair (auto-generates if needed)
 * const keyPair = getCurrentKeyPair();
 * 
 * // Generate JWKS for resource servers
 * const jwks = generateJWKS();
 * 
 * // Validate configuration
 * const { isValid, errors } = validateKeyConfiguration();
 * 
 * // Key rotation (production scenario)
 * const newKeyPair = rotateKeyPair(4096);
 * ```
 */

export interface KeyPair {
  // Private key for signing JWT tokens (keep secret!)
  privateKey: string;  // PEM format RSA private key
  
  // Public key for verifying JWT signatures (can be shared)
  publicKey: string;   // PEM format RSA public key
  
  // Key identifier for JWT header and JWKS
  keyId: string;       // Unique identifier for this key pair
  
  // Algorithm used with this key
  algorithm: string;   // "RS256" (RSA with SHA-256)
}

/**
 * JSON Web Key (JWK) format for JWKS endpoint
 * This is how we publish our public key so resource servers can verify our JWTs
 */
export interface JsonWebKey {
  kty: string;    // Key type: "RSA"
  use: string;    // Key use: "sig" (signature)
  alg: string;    // Algorithm: "RS256"
  kid: string;    // Key ID (matches JWT header)
  n: string;      // RSA public key modulus (base64url encoded)
  e: string;      // RSA public key exponent (base64url encoded)
}

/**
 * JWKS (JSON Web Key Set) response format
 * Published at /.well-known/jwks.json for resource servers to fetch
 */
export interface JsonWebKeySet {
  keys: JsonWebKey[];
}

let currentKeyPair: KeyPair | null = null;

/**
 * Generate a new RSA key pair for JWT signing
 * 
 * @param keySize - RSA key size in bits (2048 minimum, 4096 for high security)
 * @returns Generated key pair with metadata
 */
export function generateRSAKeyPair(keySize: number = 2048): KeyPair {
  console.log(`Generating ${keySize}-bit RSA key pair for JWT signing...`);
  
  // Generate RSA key pair using Node.js crypto module
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: keySize,
    publicKeyEncoding: {
      type: 'spki',      // SubjectPublicKeyInfo format
      format: 'pem'      // PEM encoding (base64 with headers)
    },
    privateKeyEncoding: {
      type: 'pkcs8',     // PKCS#8 format
      format: 'pem'      // PEM encoding
    }
  });
  
  const keyPair: KeyPair = {
    privateKey,
    publicKey,
    keyId: securityConfig.keyId,
    algorithm: securityConfig.algorithm
  };
  
  console.log(`✅ RSA key pair generated successfully (Key ID: ${keyPair.keyId})`);
  return keyPair;
}

/**
 * Convert RSA public key from PEM format to JWK format
 * This is required for the JWKS endpoint that resource servers will call
 * 
 * @param publicKeyPem - RSA public key in PEM format
 * @param keyId - Key identifier
 * @returns JWK representation of the public key
 */
export function pemToJwk(publicKeyPem: string, keyId: string): JsonWebKey {
  // Use node-forge to parse the PEM and extract RSA components
  const publicKey = pki.publicKeyFromPem(publicKeyPem);
  const rsaPublicKey = publicKey as pki.rsa.PublicKey;
  
  // Extract RSA modulus (n) and exponent (e)
  const n = Buffer.from(rsaPublicKey.n.toString(16), 'hex');
  const e = Buffer.from(rsaPublicKey.e.toString(16), 'hex');
  
  // Convert to base64url encoding (URL-safe base64 without padding)
  const nBase64url = base64urlEncode(n);
  const eBase64url = base64urlEncode(e);
  
  return {
    kty: 'RSA',          // Key type
    use: 'sig',          // Used for signatures
    alg: 'RS256',        // RSA with SHA-256
    kid: keyId,          // Key identifier
    n: nBase64url,       // Modulus
    e: eBase64url        // Exponent
  };
}

/**
 * Base64URL encode a buffer (URL-safe base64 without padding)
 * This is the encoding required by JWT and JWK specifications
 * 
 * @param buffer - Buffer to encode
 * @returns Base64URL encoded string
 */
function base64urlEncode(buffer: Buffer): string {
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')    // Replace + with -
    .replace(/\//g, '_')    // Replace / with _
    .replace(/=/g, '');     // Remove padding
}

/**
 * Get or generate the current key pair for the Identity Provider
 * In production, this would load from secure storage instead of generating
 * 
 * @returns Current active key pair
 */
export function getCurrentKeyPair(): KeyPair {
  if (!currentKeyPair) {
    console.log('No key pair found, generating new RSA key pair...');
    currentKeyPair = generateRSAKeyPair();
  }
  
  return currentKeyPair;
}

/**
 * Generate JWKS (JSON Web Key Set) for the /.well-known/jwks.json endpoint
 * Resource servers will fetch this to verify JWT signatures
 * 
 * @returns JWKS containing our public key
 */
export function generateJWKS(): JsonWebKeySet {
  const keyPair = getCurrentKeyPair();
  const jwk = pemToJwk(keyPair.publicKey, keyPair.keyId);
  
  return {
    keys: [jwk]
  };
}

/**
 * Rotate to a new key pair (for production key rotation)
 * In production, you'd:
 * 1. Generate new key pair
 * 2. Publish both old and new keys in JWKS
 * 3. Start signing with new key
 * 4. Wait for all old tokens to expire
 * 5. Remove old key from JWKS
 * 
 * @param keySize - RSA key size for new key pair
 */
export function rotateKeyPair(keySize: number = 2048): KeyPair {
  console.log('🔄 Rotating RSA key pair...');
  const oldKeyId = currentKeyPair?.keyId;
  
  // Generate new key pair
  currentKeyPair = generateRSAKeyPair(keySize);
  
  console.log(`✅ Key rotation complete: ${oldKeyId} → ${currentKeyPair.keyId}`);
  return currentKeyPair;
}

/**
 * Validate that we have a properly configured key pair
 * Checks key format, algorithm, and key ID
 * 
 * @returns Validation result
 */
export function validateKeyConfiguration(): { isValid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  try {
    const keyPair = getCurrentKeyPair();
    
    // Check private key format
    if (!keyPair.privateKey.includes('BEGIN PRIVATE KEY')) {
      errors.push('Private key is not in valid PEM format');
    }
    
    // Check public key format
    if (!keyPair.publicKey.includes('BEGIN PUBLIC KEY')) {
      errors.push('Public key is not in valid PEM format');
    }
    
    // Check algorithm
    if (keyPair.algorithm !== 'RS256') {
      errors.push('Only RS256 algorithm is supported');
    }
    
    // Check key ID
    if (!keyPair.keyId || keyPair.keyId.length === 0) {
      errors.push('Key ID must be provided');
    }
    
    // Try to generate JWK (will throw if key is invalid)
    pemToJwk(keyPair.publicKey, keyPair.keyId);
    
  } catch (error) {
    errors.push(`Key validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
}

/**
 * Log key information for debugging (without exposing private key)
 */
export function logKeyInfo(): void {
  if (securityConfig.algorithm === 'RS256') {
    const keyPair = getCurrentKeyPair();
    console.log('=== RSA Key Pair Information ===');
    console.log(`Key ID: ${keyPair.keyId}`);
    console.log(`Algorithm: ${keyPair.algorithm}`);
    console.log(`Private Key: [REDACTED - ${keyPair.privateKey.length} chars]`);
    console.log(`Public Key Length: ${keyPair.publicKey.length} chars`);
    
    const validation = validateKeyConfiguration();
    console.log(`Key Validation: ${validation.isValid ? '✅ Valid' : '❌ Invalid'}`);
    if (!validation.isValid) {
      console.log('Validation Errors:', validation.errors);
    }
    console.log('===============================');
  }
}

// Initialize key pair on module load for development
// In production, this would be done during application startup
if (process.env.NODE_ENV !== 'test') {
  getCurrentKeyPair();
}