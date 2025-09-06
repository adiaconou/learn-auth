/**
 * Data Models for OAuth 2.0 + OIDC Identity Provider
 * 
 * This module defines TypeScript interfaces for all data entities used in the
 * OAuth 2.0 Authorization Code flow with PKCE and OpenID Connect implementation.
 * 
 * Key OAuth 2.0/OIDC Concepts:
 * - User: The resource owner (person logging in)
 * - OAuth Client: The application requesting access (SPA, mobile app, API)
 * - Authorization Code: Short-lived code exchanged for tokens
 * - Access Token: JWT granting API access with specific scopes
 * - ID Token: JWT containing user identity information (OIDC)
 * - Refresh Token: Long-lived token for obtaining new access tokens
 * - Consent Grant: User's permission for client to access specific scopes
 * 
 * Data Flow Relationships:
 * ```
 * ┌─────────────┐    ┌─────────────────┐    ┌─────────────────┐
 * │    User     │───►│ Authorization   │───►│  Access Token   │
 * │             │    │     Code        │    │   (JWT Claims) │
 * └─────────────┘    └─────────────────┘    └─────────────────┘
 *        │                     │                       │
 *        │                     │                       ▼
 *        │                     │            ┌─────────────────┐
 *        │                     │            │   ID Token      │
 *        │                     │            │  (JWT Claims)  │
 *        │                     │            └─────────────────┘
 *        │                     │
 *        │                     ▼
 *        │            ┌─────────────────┐
 *        │            │ Refresh Token   │
 *        │            │                 │
 *        │            └─────────────────┘
 *        │
 *        ▼
 * ┌─────────────────┐    ┌─────────────────┐
 * │ Consent Grant   │◄───│  OAuth Client   │
 * │                 │    │                 │
 * └─────────────────┘    └─────────────────┘
 * ```
 * 
 * Security Considerations:
 * - Passwords: Always hashed with bcrypt (never store plaintext)
 * - Authorization Codes: Single-use, short expiration (10 minutes max)
 * - PKCE: Code challenge/verifier for public client security
 * - Refresh Tokens: Long-lived but revocable for security
 * - Scopes: Principle of least privilege (request minimum needed)
 */

/**
 * User Entity
 * 
 * Represents a user account in the Identity Provider.
 * Contains authentication credentials and profile information.
 * 
 * Security Notes:
 * - Password is bcrypt hashed (never store plaintext)
 * - User ID becomes 'sub' claim in JWT tokens
 * - Profile fields map to OIDC standard claims
 */
export interface User {
  /** Unique user identifier (becomes JWT 'sub' claim) */
  id: string;
  
  /** Username for login (unique across system) */
  username: string;
  
  /** Email address (used for OIDC 'email' claim) */
  email: string;
  
  /** Bcrypt hashed password (NEVER store plaintext) */
  passwordHash: string;
  
  /** Display name (used for OIDC 'name' claim) */
  name?: string;
  
  /** Account creation timestamp */
  createdAt: Date;
  
  /** Last login timestamp (for security monitoring) */
  lastLoginAt?: Date;
  
  /** Account status for admin controls */
  isActive: boolean;
}

/**
 * OAuth Client Entity
 * 
 * Represents an OAuth 2.0 client application that can request tokens.
 * Distinguishes between public clients (SPAs) and confidential clients (servers).
 * 
 * Client Types:
 * - Public: Cannot securely store secrets (SPAs, mobile apps)
 * - Confidential: Can securely store secrets (server applications)
 */
export interface OAuthClient {
  /** Unique client identifier (sent in OAuth requests) */
  id: string;
  
  /** Human-readable client name for consent screens */
  name: string;
  
  /** Client type determines security requirements */
  type: 'public' | 'confidential';
  
  /** Valid redirect URIs (exact match required for security) */
  redirectUris: string[];
  
  /** Scopes this client is allowed to request */
  allowedScopes: string[];
  
  /** Client secret (only for confidential clients) */
  secret?: string;
  
  /** Whether PKCE is required (true for public clients) */
  requirePkce: boolean;
  
  /** Client registration timestamp */
  createdAt: Date;
  
  /** Whether client is active (for admin controls) */
  isActive: boolean;
}

/**
 * Authorization Code Entity
 * 
 * Short-lived code issued during OAuth 2.0 Authorization Code flow.
 * Exchanged for access tokens at the token endpoint.
 * 
 * Security Requirements:
 * - Single use only (marked as used after exchange)
 * - Short expiration (10 minutes maximum per OAuth spec)
 * - PKCE challenge stored for verification
 */
export interface AuthorizationCode {
  /** The authorization code value (random, unguessable) */
  code: string;
  
  /** Client that requested this code */
  clientId: string;
  
  /** User who authorized this code */
  userId: string;
  
  /** Redirect URI used in authorization request (must match token request) */
  redirectUri: string;
  
  /** Requested scopes (space-separated string) */
  scope: string;
  
  /** OIDC nonce for ID token (replay protection) */
  nonce?: string;
  
  /** PKCE code challenge (SHA256 of verifier) */
  codeChallenge?: string;
  
  /** PKCE challenge method (should be 'S256') */
  codeChallengeMethod?: string;
  
  /** When this code expires (10 minutes max) */
  expiresAt: Date;
  
  /** Whether this code has been used (single-use only) */
  used: boolean;
  
  /** When this code was created */
  createdAt: Date;
}

/**
 * Refresh Token Entity
 * 
 * Long-lived token for obtaining new access tokens without re-authentication.
 * Provides better UX while maintaining security through revocation capability.
 */
export interface RefreshToken {
  /** Unique refresh token identifier */
  id: string;
  
  /** User this token belongs to */
  userId: string;
  
  /** Client this token was issued to */
  clientId: string;
  
  /** Scopes associated with this refresh token */
  scope: string;
  
  /** When this refresh token expires (30 days typical) */
  expiresAt: Date;
  
  /** Whether this token has been revoked */
  revoked: boolean;
  
  /** When this token was created */
  createdAt: Date;
  
  /** Last time this token was used */
  lastUsedAt?: Date;
}

/**
 * Consent Grant Entity
 * 
 * Records user's consent for a client to access specific scopes.
 * Enables "skip consent" for trusted clients and previously consented scopes.
 */
export interface ConsentGrant {
  /** User who gave consent */
  userId: string;
  
  /** Client that received consent */
  clientId: string;
  
  /** Scopes that were consented to (space-separated) */
  scope: string;
  
  /** When consent was granted */
  grantedAt: Date;
  
  /** When consent expires (optional - never expires if not set) */
  expiresAt?: Date;
  
  /** Whether consent has been revoked */
  revoked: boolean;
}

/**
 * JWT Access Token Claims
 * 
 * Standard claims structure for JWT access tokens.
 * Used by resource servers to make authorization decisions.
 */
export interface AccessTokenClaims {
  /** Issuer - Identity Provider URL */
  iss: string;
  
  /** Audience - Resource Server identifier */
  aud: string;
  
  /** Subject - User identifier */
  sub: string;
  
  /** Scopes - Space-separated list of permissions */
  scope: string;
  
  /** Expiration time - Unix timestamp */
  exp: number;
  
  /** Issued at - Unix timestamp */
  iat: number;
  
  /** JWT ID - Unique identifier for this token */
  jti: string;
  
  /** Client ID that requested this token */
  client_id: string;
  
  /** Token type (always 'Bearer' for access tokens) */
  token_type?: 'Bearer';
}

/**
 * JWT ID Token Claims (OIDC)
 * 
 * Standard claims structure for OIDC ID tokens.
 * Contains user identity information for client applications.
 */
export interface IdTokenClaims {
  /** Issuer - Identity Provider URL */
  iss: string;
  
  /** Audience - Client ID */
  aud: string;
  
  /** Subject - User identifier */
  sub: string;
  
  /** Expiration time - Unix timestamp */
  exp: number;
  
  /** Issued at - Unix timestamp */
  iat: number;
  
  /** Nonce - Replay protection (from authorization request) */
  nonce?: string;
  
  /** Authentication time - When user authenticated */
  auth_time?: number;
  
  // Standard OIDC Profile Claims
  /** User's email address */
  email?: string;
  
  /** Whether email is verified */
  email_verified?: boolean;
  
  /** User's full name */
  name?: string;
  
  /** User's given name */
  given_name?: string;
  
  /** User's family name */
  family_name?: string;
  
  /** User's preferred username */
  preferred_username?: string;
}

/**
 * Session Data
 * 
 * Information stored in user's browser session during authentication flows.
 * Used to maintain state between authorization request and token exchange.
 */
export interface SessionData {
  /** Whether user is authenticated */
  authenticated: boolean;
  
  /** Authenticated user ID */
  userId?: string;
  
  /** When authentication occurred */
  authenticatedAt?: Date;
  
  /** Pending authorization request details */
  pendingAuth?: {
    clientId: string;
    redirectUri: string;
    scope: string;
    state: string;
    nonce?: string;
    codeChallenge?: string;
    codeChallengeMethod?: string;
  };
  
  /** CSRF token for form protection */
  csrfToken?: string;
}

/**
 * Token Response
 * 
 * Standard OAuth 2.0/OIDC token endpoint response format.
 * Returned after successful authorization code exchange.
 */
export interface TokenResponse {
  /** JWT access token for API authorization */
  access_token: string;
  
  /** Token type (always 'Bearer') */
  token_type: 'Bearer';
  
  /** Access token lifetime in seconds */
  expires_in: number;
  
  /** JWT ID token with user identity (OIDC) */
  id_token?: string;
  
  /** Refresh token for token renewal */
  refresh_token?: string;
  
  /** Scopes granted (may be subset of requested) */
  scope?: string;
}

/**
 * Error Response
 * 
 * Standard OAuth 2.0 error response format.
 * Used for authorization and token endpoint errors.
 */
export interface ErrorResponse {
  /** Error code (standardized) */
  error: string;
  
  /** Human-readable error description */
  error_description?: string;
  
  /** URI with error information */
  error_uri?: string;
  
  /** State parameter from request (for CSRF protection) */
  state?: string;
}

/**
 * Common OAuth 2.0 Error Codes
 */
export const OAuth2ErrorCodes = {
  // Authorization Endpoint Errors
  INVALID_REQUEST: 'invalid_request',
  UNAUTHORIZED_CLIENT: 'unauthorized_client', 
  ACCESS_DENIED: 'access_denied',
  UNSUPPORTED_RESPONSE_TYPE: 'unsupported_response_type',
  INVALID_SCOPE: 'invalid_scope',
  SERVER_ERROR: 'server_error',
  TEMPORARILY_UNAVAILABLE: 'temporarily_unavailable',
  
  // Token Endpoint Errors
  INVALID_CLIENT: 'invalid_client',
  INVALID_GRANT: 'invalid_grant',
  UNSUPPORTED_GRANT_TYPE: 'unsupported_grant_type'
} as const;

/**
 * PKCE Code Challenge Methods
 */
export const PKCEMethods = {
  PLAIN: 'plain',      // Not recommended (plaintext)
  S256: 'S256'         // Recommended (SHA256 hash)
} as const;