import { Router, Request, Response } from 'express';
import { serverConfig } from '../config';
import { getJWKS } from '../crypto/jwks';

/**
 * OIDC Discovery & JWKS Endpoints
 * 
 * This module implements the well-known discovery endpoints that allow OAuth 2.0/OIDC
 * clients and resource servers to automatically discover Identity Provider capabilities
 * and retrieve public keys for JWT verification.
 * 
 * Key OIDC Discovery Concepts:
 * - Discovery Document: Metadata about IdP capabilities and endpoints
 * - JWKS Endpoint: Public keys for JWT signature verification
 * - Auto-Discovery: Clients can configure themselves by fetching these endpoints
 * - Standards Compliance: Follows RFC 8414 (OAuth 2.0) and OIDC Discovery specs
 * 
 * Discovery Flow:
 * ```
 * ┌─────────────────┐              ┌─────────────────┐              ┌─────────────────┐
 * │   Client App    │              │  Identity       │              │ Resource Server │
 * │ (SPA/Mobile)    │              │  Provider       │              │ (Notes API)     │
 * └─────────────────┘              │ (This Module)   │              └─────────────────┘
 *          │                       └─────────────────┘                       │
 *          │ 1. Discover IdP Config │                                        │
 *          │ GET /.well-known/      │                                        │
 *          │     openid-configuration│                                       │
 *          ├───────────────────────►│                                        │
 *          │                        │                                        │
 *          │ 2. Discovery Document  │                                        │
 *          │ {                      │                                        │
 *          │   issuer: "...",       │                                        │
 *          │   authorization_       │                                        │
 *          │     endpoint: "...",   │                                        │
 *          │   token_endpoint: "...",│                                       │
 *          │   jwks_uri: "...",     │                                        │
 *          │   scopes_supported: [] │                                        │
 *          │ }                      │                                        │
 *          │◄───────────────────────┤                                        │
 *          │                        │                                        │
 *          │ 3. Client Configuration│                                        │
 *          │    (Auto-setup from    │                                        │
 *          │     discovery doc)     │                                        │
 *          │                        │                                        │
 *          │                        │ 4. Fetch Public Keys                  │
 *          │                        │ GET /.well-known/jwks.json             │
 *          │                        │◄───────────────────────────────────────┤
 *          │                        │                                        │
 *          │                        │ 5. JWKS Response                       │
 *          │                        │ {                                      │
 *          │                        │   keys: [{                             │
 *          │                        │     kty: "RSA",                        │
 *          │                        │     kid: "key-1",                      │
 *          │                        │     n: "modulus...",                   │
 *          │                        │     e: "exponent..."                   │
 *          │                        │   }]                                   │
 *          │                        │ }                                      │
 *          │                        ├───────────────────────────────────────►│
 *          │                        │                                        │
 *          │                        │ 6. Cache Keys & Verify JWTs            │
 *          │                        │    (Resource Server ready)             │
 *          │                        │                                        │
 * ```
 * 
 * Endpoint Security & Caching:
 * ```
 * [Discovery Endpoint] ────────────────┬─────► [Cache Headers: 1 hour]
 *         │                           │
 *         │                           └─────► [No Authentication Required]
 *         │
 *         ▼
 * [JWKS Endpoint] ─────────────────────┬─────► [Cache Headers: 1 hour]  
 *                                      │
 *                                      └─────► [Rate Limiting Recommended]
 * ```
 * 
 * ## API Summary
 * 
 * ### Discovery Document Endpoint
 * - `GET /.well-known/openid-configuration` - Returns OIDC discovery metadata
 * - Response: Complete IdP configuration with all supported endpoints and capabilities
 * - Caching: 1 hour cache headers for performance (rarely changes)
 * - Standards: RFC 8414 (OAuth 2.0) + OIDC Discovery 1.0
 * 
 * ### JWKS Endpoint  
 * - `GET /.well-known/jwks.json` - Returns JSON Web Key Set for JWT verification
 * - Response: Public keys in JWK format for resource servers
 * - Caching: Server-side cache (5 min) + client cache headers (1 hour)
 * - Security: Rate limiting recommended in production
 * 
 * ### Supported Features
 * - Authorization Code Flow with PKCE (response_types: ["code"])
 * - RSA-256 JWT signing (id_token_signing_alg_values_supported: ["RS256"])
 * - Standard OIDC scopes (scopes_supported: ["openid", "profile", "email"])
 * - Custom API scopes (["notes:read", "notes:write"])
 * - Refresh token grant (grant_types_supported: ["authorization_code", "refresh_token"])
 * 
 * ### Production Considerations
 * - Discovery document changes very rarely (safe to cache for hours/days)
 * - JWKS should be cached but refreshed during key rotation
 * - Consider CDN caching for high-traffic scenarios
 * - Implement rate limiting on JWKS endpoint
 * - Monitor cache hit ratios for performance optimization
 * 
 * ### Standards Compliance
 * - OIDC Discovery 1.0: Complete discovery document format
 * - RFC 8414: OAuth 2.0 Authorization Server Metadata
 * - RFC 7517: JSON Web Key Set format
 * - RFC 7636: PKCE support indication
 */

const router = Router();

/**
 * OIDC Discovery Document Interface
 * Defines the structure of /.well-known/openid-configuration response
 */
interface OIDCDiscoveryDocument {
  // Core Identity Provider Information
  issuer: string;                                    // IdP identifier URL
  
  // OAuth 2.0 Core Endpoints
  authorization_endpoint: string;                    // Where clients start auth flow
  token_endpoint: string;                           // Where clients exchange codes for tokens
  userinfo_endpoint: string;                        // Where clients get user profile info
  jwks_uri: string;                                 // Where to fetch public keys
  
  // Supported Capabilities
  response_types_supported: string[];               // ["code"] - Only auth code flow
  subject_types_supported: string[];               // ["public"] - Subject identifier types
  id_token_signing_alg_values_supported: string[]; // ["RS256"] - JWT signing algorithms
  
  // Scope & Grant Support
  scopes_supported: string[];                       // Available OAuth scopes
  grant_types_supported: string[];                 // Supported grant types
  
  // PKCE Support (RFC 7636)
  code_challenge_methods_supported: string[];      // ["S256"] - PKCE challenge methods
  
  // Optional OIDC Features
  token_endpoint_auth_methods_supported: string[]; // Client authentication methods
}

/**
 * Generate OIDC Discovery Document
 * 
 * Creates the discovery metadata that clients use to configure themselves.
 * This document describes all IdP capabilities and endpoint locations.
 * 
 * @returns Complete OIDC discovery document
 */
function generateDiscoveryDocument(): OIDCDiscoveryDocument {
  return {
    // Identity Provider identifier (must match JWT 'iss' claim)
    issuer: serverConfig.issuer,
    
    // Core OAuth 2.0 + OIDC Endpoints
    authorization_endpoint: serverConfig.authorizationEndpoint,
    token_endpoint: serverConfig.tokenEndpoint,
    userinfo_endpoint: serverConfig.userinfoEndpoint,
    jwks_uri: serverConfig.jwksUri,
    
    // Flow Support - Only Authorization Code Flow (most secure)
    response_types_supported: [
      "code"  // Authorization Code Flow (with PKCE for public clients)
    ],
    
    // Subject Types - How user identifiers are formatted
    subject_types_supported: [
      "public"  // Same sub claim for all clients (simpler for learning)
    ],
    
    // JWT Signing Algorithms - Only RS256 for maximum compatibility
    id_token_signing_alg_values_supported: [
      "RS256"  // RSA with SHA-256 (widely supported, secure)
    ],
    
    // OAuth 2.0 Scopes - What permissions clients can request
    scopes_supported: [
      "openid",      // Required for OIDC (triggers ID token issuance)
      "profile",     // User profile information (name, etc.)
      "email",       // User email address
      "notes:read",  // Read access to notes API
      "notes:write"  // Write access to notes API
    ],
    
    // Grant Types - How clients can obtain tokens
    grant_types_supported: [
      "authorization_code",  // Standard auth code flow
      "refresh_token"        // Token renewal without re-authentication
    ],
    
    // PKCE Support - Required for public clients (SPAs/mobile)
    code_challenge_methods_supported: [
      "S256"  // SHA256 challenge method (most secure)
    ],
    
    // Client Authentication - How clients authenticate to token endpoint
    token_endpoint_auth_methods_supported: [
      "none",           // For public clients (SPAs) - no client secret
      "client_secret_post"  // For confidential clients - secret in POST body
    ]
  };
}

/**
 * GET /.well-known/openid-configuration
 * 
 * Returns OIDC discovery document that describes this Identity Provider's
 * capabilities and endpoint URLs. Clients use this for auto-configuration.
 * 
 * Response Headers:
 * - Cache-Control: Public caching (1 hour) - discovery rarely changes
 * - Content-Type: application/json (per OIDC spec)
 * 
 * Example Response:
 * ```json
 * {
 *   "issuer": "http://localhost:3001",
 *   "authorization_endpoint": "http://localhost:3001/authorize",
 *   "token_endpoint": "http://localhost:3001/token",
 *   "scopes_supported": ["openid", "notes:read", "notes:write"],
 *   "response_types_supported": ["code"]
 * }
 * ```
 */
router.get('/.well-known/openid-configuration', (req: Request, res: Response) => {
  try {
    const discoveryDoc = generateDiscoveryDocument();
    
    // Set caching headers - discovery document changes very rarely
    res.setHeader('Cache-Control', 'public, max-age=3600'); // 1 hour cache
    res.setHeader('Content-Type', 'application/json');
    
    console.log('📋 Serving OIDC discovery document');
    res.json(discoveryDoc);
    
  } catch (error) {
    console.error('❌ Error generating discovery document:', error);
    res.status(500).json({
      error: 'server_error',
      error_description: 'Failed to generate discovery document'
    });
  }
});

/**
 * GET /.well-known/jwks.json
 * 
 * Returns JSON Web Key Set containing public keys for JWT signature verification.
 * Resource servers fetch this to validate access tokens issued by this IdP.
 * 
 * Response Headers:
 * - Cache-Control: Public caching (1 hour) with revalidation
 * - Content-Type: application/json (per RFC 7517)
 * 
 * Caching Strategy:
 * - Server-side: 5 minute cache (handled by getJWKS())
 * - Client-side: 1 hour cache with revalidation
 * - Key Rotation: Cache automatically refreshes when keys change
 * 
 * Example Response:
 * ```json
 * {
 *   "keys": [
 *     {
 *       "kty": "RSA",
 *       "use": "sig", 
 *       "alg": "RS256",
 *       "kid": "idp-key-1",
 *       "n": "base64url-encoded-modulus",
 *       "e": "AQAB"
 *     }
 *   ]
 * }
 * ```
 */
router.get('/.well-known/jwks.json', (req: Request, res: Response) => {
  try {
    const jwks = getJWKS();
    
    // Set caching headers for JWKS
    // - Clients should cache but revalidate (keys can rotate)
    // - Shorter cache than discovery document (keys change more often)
    res.setHeader('Cache-Control', 'public, max-age=3600, must-revalidate'); // 1 hour with revalidation
    res.setHeader('Content-Type', 'application/json');
    
    console.log('🔑 Serving JWKS for JWT verification');
    res.json(jwks);
    
  } catch (error) {
    console.error('❌ Error serving JWKS:', error);
    res.status(500).json({
      error: 'server_error', 
      error_description: 'Failed to generate JWKS'
    });
  }
});

/**
 * Health check endpoint for monitoring discovery service availability
 * 
 * GET /health - Returns service health status
 * Used by load balancers and monitoring systems to verify discovery endpoints
 */
router.get('/health', (req: Request, res: Response) => {
  try {
    // Verify we can generate both discovery doc and JWKS
    const discoveryDoc = generateDiscoveryDocument();
    const jwks = getJWKS();
    
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      endpoints: {
        discovery: '/.well-known/openid-configuration',
        jwks: '/.well-known/jwks.json'
      },
      issuer: discoveryDoc.issuer,
      keys_count: jwks.keys?.length || 0
    });
    
  } catch (error) {
    console.error('❌ Health check failed:', error);
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

export default router;