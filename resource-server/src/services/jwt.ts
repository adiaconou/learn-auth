/**
 * JWT Validation Service
 * 
 * Handles JWT access token validation for OAuth 2.0 resource server.
 * 
 * Data Flow Diagram:
 * 
 *    ┌─────────────┐    ┌─────────────────┐    ┌─────────────────┐
 *    │ Client App  │───→│ Identity Provider│    │ JWKS Endpoint   │
 *    │             │    │                 │    │                 │
 *    └─────────────┘    └─────────────────┘    └─────────────────┘
 *           │                      │                      ▲
 *           │ 1. Get JWT           │ 2. Signs JWT         │
 *           │    access token      │    with private key  │ 4. Fetch public
 *           ▼                      ▼                      │    key (cached)
 *    ┌─────────────┐    ┌─────────────────┐              │
 *    │   Request   │───→│ Resource Server │──────────────┘
 *    │ Bearer <jwt>│ 3. │ (this service)  │
 *    └─────────────┘    └─────────────────┘
 *                              │
 *                              ▼ 5. Validate signature
 *                       ┌─────────────────┐    & claims
 *                       │ Protected API   │
 *                       │   Endpoints     │
 *                       └─────────────────┘
 * 
 * Sequence Diagram (Token Validation Flow):
 * 
 *   Client    Resource Server  JwtValidationService  JWKS Client    IdP JWKS Endpoint
 *     │              │                │                 │                │
 *     │─── POST ────→│                │                 │                │
 *     │ Bearer <jwt> │                │                 │                │
 *     │              │                │                 │                │
 *     │              │ verifyToken()  │                 │                │
 *     │              │───────────────→│                 │                │
 *     │              │                │ ┌─────────────┐ │                │
 *     │              │                │ │jwt.decode() │ │                │
 *     │              │                │ │get 'kid'    │ │                │
 *     │              │                │ └─────────────┘ │                │
 *     │              │                │                 │                │
 *     │              │                │ getSigningKey() │                │
 *     │              │                │────────────────→│                │
 *     │              │                │    (kid)        │                │
 *     │              │                │                 │                │
 *     │              │                │                 │──── GET ──────→│
 *     │              │                │                 │ /.well-known/  │
 *     │              │                │                 │   jwks.json    │
 *     │              │                │                 │                │
 *     │              │                │                 │←── JSON ──────│
 *     │              │                │                 │ RSA public keys│
 *     │              │                │                 │                │
 *     │              │                │←─ public key ───│                │
 *     │              │                │   (cached)      │                │
 *     │              │                │                 │                │
 *     │              │                │ ┌─────────────┐ │                │
 *     │              │                │ │jwt.verify() │ │                │
 *     │              │                │ │validateClaims()               │
 *     │              │                │ └─────────────┘ │                │
 *     │              │                │                 │                │
 *     │              │←── DecodedToken │                │                │
 *     │              │                │                 │                │
 *     │←─── 200 ────│                │                 │                │
 *     │ {success}    │                │                 │                │
 * 
 * JWT tokens are used in the OAuth 2.0 flow as follows:
 * 
 * 1. Client app obtains JWT access token from Identity Provider
 * 2. Client includes JWT as Bearer token in Authorization header: "Bearer <jwt>"
 * 3. This service validates token signature and claims on each API request
 * 4. If valid, request proceeds with user context from token claims
 * 
 * Validates token signature using JWKS (JSON Web Key Set) and verifies
 * standard OAuth 2.0 claims for security.
 */

import jwt from 'jsonwebtoken';
import jwksClient, { JwksClient } from 'jwks-rsa';
import config from '../config/index';

/**
 * Decoded JWT payload with OAuth 2.0 standard claims.
 * 
 * Claims are key-value pairs in the JWT payload that provide information
 * about the token and the authenticated user. They enable the resource server
 * to make authorization decisions without contacting the Identity Provider.
 */
interface DecodedToken {
  iss: string;      // Issuer: URL of IdP that created token, validates token source (e.g., "http://localhost:3001")
  aud: string;      // Audience: intended recipient (this API), prevents token misuse (e.g., "notes-api")
  sub: string;      // Subject: unique user identifier, used for data isolation (e.g., "user123")
  scope: string;    // Scopes: space-separated permissions (e.g., "notes:read notes:write")
  exp: number;      // Expiration: Unix timestamp when token becomes invalid (e.g., 1692834600)
  iat: number;      // Issued At: Unix timestamp when token was created (e.g., 1692748200)
}

/**
 * JWT header containing key ID for JWKS lookup
 */
interface JwtHeader {
  kid: string;      // Key ID for finding public key in JWKS
  alg: string;      // Signing algorithm (should be RS256)
}

/**
 * JWT validation service using JWKS for signature verification.
 * 
 * JWT Structure (3 parts separated by dots):
 * 
 *   eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFiYzEyMyJ9
 *   .eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEiLCJhdWQiOiJub3Rlcy1hcGkifQ
 *   .SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c-signature-here
 *   
 *   └── Header ──┘ └─────── Payload ─────────┘ └─── Signature ───┘
 * 
 * How JWT Signing Works:
 * 1. IdP creates header (algorithm, key ID) and payload (claims)
 * 2. IdP base64url-encodes both: "header.payload"
 * 3. IdP signs this string with PRIVATE key using RS256 algorithm
 * 4. IdP base64url-encodes the signature and appends: "header.payload.signature"
 * 5. Full JWT token is sent to client as single string
 * 
 * How This Service Verifies:
 * 1. Split JWT by dots to get [header, payload, signature]
 * 2. Decode header to get 'kid' (key ID)
 * 3. Fetch matching PUBLIC key from JWKS endpoint
 * 4. Use PUBLIC key to verify "header.payload" matches the signature
 * 5. If match = token is authentic and unmodified
 * 
 * Asymmetric Cryptography Overview:
 * 
 * The Identity Provider (IdP) and Resource Server use a key pair system:
 * 1. IdP keeps a PRIVATE key (secret) to SIGN JWT tokens
 * 2. IdP publishes matching PUBLIC keys via JWKS endpoint for verification
 * 3. Resource Server uses PUBLIC key to VERIFY token signatures
 * 
 * This ensures:
 * - Only the IdP can create valid tokens (has private key)
 * - Anyone can verify tokens are authentic (public key is... public)
 * - If signature verification passes, token hasn't been tampered with
 * 
 * JWKS (JSON Web Key Set) Process:
 * 1. JWT header contains 'kid' (Key ID) pointing to specific public key
 * 2. This service fetches public key from IdP's /.well-known/jwks.json endpoint
 * 3. Public key is cached IN MEMORY to avoid repeated network calls
 * 4. Public key verifies the token's signature matches its content
 * 5. If signature is valid, we trust the token claims (iss, aud, sub, etc.)
 * 
 * Where Public Keys Are Stored:
 * - Primary: IdP's JWKS endpoint (e.g., http://localhost:3001/.well-known/jwks.json)
 * - Cache: jwksClient stores keys in memory for 10 minutes (see constructor)
 * - Network: Each request to JWKS endpoint fetches fresh keys from IdP
 * 
 * JWKS Endpoint Example Response:
 * {
 *   "keys": [
 *     {
 *       "kid": "abc123",
 *       "kty": "RSA", 
 *       "use": "sig",
 *       "n": "0vxyz...",  // RSA public key modulus
 *       "e": "AQAB"      // RSA public key exponent
 *     }
 *   ]
 * }
 * 
 * Key concepts:
 * - JWKS: JSON Web Key Set containing public keys for token verification
 * - Asymmetric cryptography: IdP signs with private key, resource server verifies with public key
 * - Claims validation: Ensures token is intended for this resource server and hasn't expired
 */
class JwtValidationService {
  private jwksClient: JwksClient;

  constructor() {
    // Initialize JWKS client with caching and rate limiting
    this.jwksClient = jwksClient({
      jwksUri: config.identityProvider.jwksUri,
      cache: true,                    // Cache keys for performance
      cacheMaxAge: 600000,           // Cache for 10 minutes
      rateLimit: true,               // Prevent JWKS endpoint abuse
      jwksRequestsPerMinute: 5       // Limit key fetching
    });
  }

  /**
   * Verifies JWT token signature and validates OAuth 2.0 claims
   * 
   * Development Mode: Uses HMAC secret for Phase 1 testing
   * Production Mode: Uses JWKS endpoint for Phase 2 integration
   * 
   * @param token - JWT access token from Authorization header
   * @returns Decoded token payload with validated claims
   * @throws Error if token is invalid, expired, or has wrong audience/issuer
   */
  async verifyToken(token: string): Promise<DecodedToken> {
    try {
      // Check if we're in development/test mode
      if (config.development.enableTestMode) {
        // Development Mode: Use HMAC secret validation for test tokens
        console.log('🧪 Test mode enabled - using HMAC validation');
        
        const decoded = jwt.verify(token, config.development.testSecret, {
          issuer: config.identityProvider.issuer,      // Must match our IdP
          audience: config.resourceServer.audience,     // Must be intended for us
          algorithms: ['HS256']                         // HMAC for testing
        }) as DecodedToken;

        // Validate required OAuth 2.0 claims
        this.validateClaims(decoded);
        return decoded;
      }

      // Production Mode: Use JWKS endpoint validation
      console.log('🔐 Production mode - using JWKS validation');

      // Step 1: Decode header to get key ID (without verification)
      const decodedHeader = jwt.decode(token, { complete: true });
      
      if (!decodedHeader || typeof decodedHeader === 'string' || !decodedHeader.header) {
        throw new Error('Invalid token format');
      }

      const header = decodedHeader.header as JwtHeader;
      
      if (!header.kid) {
        throw new Error('Token missing key ID (kid)');
      }

      // Step 2: Get public key from JWKS endpoint using key ID
      const key = await this.getSigningKey(header.kid);
      
      // Step 3: Verify signature and validate claims
      const decoded = jwt.verify(token, key, {
        issuer: config.identityProvider.issuer,      // Must match our IdP
        audience: config.resourceServer.audience,     // Must be intended for us
        algorithms: ['RS256']                         // Only allow secure algorithm
      }) as DecodedToken;

      // Step 4: Validate required OAuth 2.0 claims
      this.validateClaims(decoded);

      return decoded;
    } catch (error) {
      // Convert specific JWT errors to descriptive messages
      if (error instanceof jwt.TokenExpiredError) {
        throw new Error('Token has expired');
      } else if (error instanceof jwt.JsonWebTokenError) {
        throw new Error('Invalid token signature or format');
      } else if (error instanceof jwt.NotBeforeError) {
        throw new Error('Token not active yet');
      } else {
        throw new Error(`Token validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }
  }

  /**
   * Fetches public key from JWKS endpoint using key ID
   * 
   * @param kid - Key ID from JWT header
   * @returns Public key in PEM format for signature verification
   */
  private async getSigningKey(kid: string): Promise<string> {
    try {
      const key = await this.jwksClient.getSigningKey(kid);
      return key.getPublicKey();
    } catch (error) {
      throw new Error(`Failed to get signing key: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Validates required OAuth 2.0 claims in token payload
   * 
   * @param decoded - Decoded JWT payload
   * @throws Error if any required claim is missing
   */
  private validateClaims(decoded: DecodedToken): void {
    if (!decoded.iss) {
      throw new Error('Token missing issuer claim');
    }
    
    if (!decoded.aud) {
      throw new Error('Token missing audience claim');
    }
    
    if (!decoded.sub) {
      throw new Error('Token missing subject claim');
    }
    
    if (decoded.scope === undefined) {
      throw new Error('Token missing scope claim');
    }
    
    if (!decoded.exp) {
      throw new Error('Token missing expiration claim');
    }
    
    if (!decoded.iat) {
      throw new Error('Token missing issued at claim');
    }
  }
}

// Export singleton instance for consistent usage across the application
export default new JwtValidationService();
export { DecodedToken };