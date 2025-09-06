import { generateJWKS } from './keys';

/**
 * JWKS (JSON Web Key Set) Management
 * 
 * This module provides JWKS functionality for the /.well-known/jwks.json endpoint.
 * JWKS is how OAuth 2.0/OIDC systems publish their public keys so resource servers
 * can verify JWT signatures without needing shared secrets.
 * 
 * Key JWKS Concepts:
 * - JWKS: Collection of public keys in JWK (JSON Web Key) format
 * - JWK: Individual public key with metadata (algorithm, use, key ID)
 * - Key Rotation: JWKS can contain multiple keys to support seamless rotation
 * - Caching: Resource servers should cache JWKS with appropriate TTL
 * 
 * JWKS Response Flow:
 * ```
 * ┌─────────────────┐              ┌─────────────────┐
 * │ Resource Server │              │ Identity Provider│
 * │   (Phase 1)     │              │   (This Module) │
 * └─────────────────┘              └─────────────────┘
 *          │                                │
 *          │ GET /.well-known/jwks.json     │
 *          ├───────────────────────────────►│
 *          │                                │
 *          │                                │ generateJWKS()
 *          │                                │ (from keys.ts)
 *          │                                │
 *          │ JWKS Response                  │
 *          │ {                              │
 *          │   "keys": [                    │
 *          │     {                          │
 *          │       "kty": "RSA",            │
 *          │       "use": "sig",            │
 *          │       "alg": "RS256",          │
 *          │       "kid": "idp-key-1",      │
 *          │       "n": "base64url...",     │
 *          │       "e": "AQAB"              │
 *          │     }                          │
 *          │   ]                            │
 *          │ }                              │
 *          │◄───────────────────────────────┤
 *          │                                │
 *          │ Cache JWKS (TTL: 1 hour)       │
 *          │                                │
 * ```
 * 
 * ## API Summary
 * 
 * ### Core Functions
 * - `getJWKS()` - Get current JWKS (cached with TTL)
 * - `refreshJWKS()` - Force refresh of JWKS cache
 * 
 * ### Caching & Performance
 * - `jwksCache` - In-memory cache with TTL
 * - `JWKS_CACHE_TTL` - Cache expiration (5 minutes default)
 * 
 * ### Production Considerations
 * - JWKS should be cached by resource servers (1+ hours)
 * - Key rotation requires publishing both old and new keys
 * - JWKS endpoint should have high availability
 * - Consider CDN caching for high-traffic scenarios
 */

// JWKS cache configuration
const JWKS_CACHE_TTL = 5 * 60 * 1000; // 5 minutes in milliseconds

interface JWKSCache {
  jwks: any;
  timestamp: number;
}

let jwksCache: JWKSCache | null = null;

/**
 * Get JWKS with caching support
 * 
 * This function provides caching to avoid regenerating JWKS on every request.
 * In production, JWKS rarely changes (only during key rotation), so caching
 * improves performance significantly.
 * 
 * @returns Current JWKS with public keys
 */
export function getJWKS(): any {
  const now = Date.now();
  
  // Check if we have valid cached JWKS
  if (jwksCache && (now - jwksCache.timestamp) < JWKS_CACHE_TTL) {
    return jwksCache.jwks;
  }
  
  // Generate fresh JWKS
  console.log('🔄 Generating fresh JWKS (cache expired or not found)');
  const jwks = generateJWKS();
  
  // Update cache
  jwksCache = {
    jwks,
    timestamp: now
  };
  
  console.log(`✅ JWKS cached successfully (TTL: ${JWKS_CACHE_TTL / 1000}s)`);
  return jwks;
}

/**
 * Force refresh of JWKS cache
 * 
 * Useful when keys have been rotated and we need to immediately
 * publish the new JWKS without waiting for cache expiration.
 * 
 * @returns Fresh JWKS
 */
export function refreshJWKS(): any {
  console.log('🔄 Force refreshing JWKS cache...');
  jwksCache = null;  // Clear cache
  return getJWKS();  // Generate fresh
}

/**
 * Get JWKS cache statistics for monitoring
 * 
 * @returns Cache status information
 */
export function getJWKSCacheInfo(): { 
  cached: boolean; 
  age: number; 
  ttl: number; 
  expiresIn: number;
} {
  if (!jwksCache) {
    return {
      cached: false,
      age: 0,
      ttl: JWKS_CACHE_TTL,
      expiresIn: 0
    };
  }
  
  const now = Date.now();
  const age = now - jwksCache.timestamp;
  const expiresIn = Math.max(0, JWKS_CACHE_TTL - age);
  
  return {
    cached: true,
    age,
    ttl: JWKS_CACHE_TTL,
    expiresIn
  };
}

/**
 * Log JWKS information for debugging
 */
export function logJWKSInfo(): void {
  const jwks = getJWKS();
  const cacheInfo = getJWKSCacheInfo();
  
  console.log('=== JWKS Information ===');
  console.log(`Keys Count: ${jwks.keys?.length || 0}`);
  console.log(`Cache Status: ${cacheInfo.cached ? 'CACHED' : 'NOT CACHED'}`);
  if (cacheInfo.cached) {
    console.log(`Cache Age: ${Math.round(cacheInfo.age / 1000)}s`);
    console.log(`Expires In: ${Math.round(cacheInfo.expiresIn / 1000)}s`);
  }
  
  // Log key information (without exposing key material)
  if (jwks.keys && jwks.keys.length > 0) {
    jwks.keys.forEach((key: any, index: number) => {
      console.log(`Key ${index + 1}:`);
      console.log(`  - Key ID: ${key.kid}`);
      console.log(`  - Key Type: ${key.kty}`);
      console.log(`  - Algorithm: ${key.alg}`);
      console.log(`  - Use: ${key.use}`);
      console.log(`  - Modulus Length: ${key.n?.length || 0} chars`);
    });
  }
  console.log('========================');
}