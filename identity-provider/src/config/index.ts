import { randomBytes } from 'crypto';

/**
 * Identity Provider Configuration
 * 
 * Manages all configuration settings for the OAuth 2.0 Authorization Server + OIDC Identity Provider.
 * Combines environment variables with secure defaults for development and production environments.
 * 
 * Key Security Concepts:
 * - JWT Token Lifetimes: Balance security (short) vs usability (not too short)
 * - PKCE: Required for public clients (SPAs) to prevent code interception
 * - Session Security: Secure cookies and session secrets for web authentication
 * - CORS: Restrict origins to prevent unauthorized cross-origin requests
 */

export interface SecurityConfig {
  // JWT Token Settings
  accessTokenTtl: number;        // Access token lifetime (15 minutes recommended)
  idTokenTtl: number;           // ID token lifetime (1 hour recommended)  
  refreshTokenTtl: number;      // Refresh token lifetime (30 days recommended)
  authorizationCodeTtl: number; // Authorization code lifetime (10 minutes max per OAuth spec)
  
  // PKCE Security Settings
  codeVerifierLength: number;   // PKCE code verifier length (43-128 chars per RFC 7636)
  codeChallengeMethod: string;  // Only 'S256' supported (SHA256 hashing)
  
  // Session & CSRF Protection
  sessionSecret: string;        // Secret for encrypting session cookies
  csrfSecret: string;          // Secret for CSRF token generation
  sessionMaxAge: number;       // Session cookie max age
  
  // Cryptographic Settings
  keyId: string;               // Key ID for JWKS (Key ID header in JWTs)
  algorithm: string;           // JWT signing algorithm (RS256 recommended)
  
  // Network & Security Headers
  allowedOrigins: string[];    // CORS allowed origins (frontend URLs)
  requireHttps: boolean;       // Enforce HTTPS in production
  trustProxy: boolean;         // Trust proxy headers (for load balancers)
}

export interface ServerConfig {
  // Server Settings
  port: number;                // Server port (3001 for IdP)
  host: string;               // Server host
  issuer: string;             // OAuth/OIDC issuer URL
  
  // External Service URLs
  resourceServerUrl: string;   // Phase 1 Resource Server URL
  frontendUrl: string;        // Phase 3 Frontend SPA URL (future)
  
  // Discovery Endpoints (auto-constructed from issuer)
  jwksUri: string;            // JWKS endpoint URL
  authorizationEndpoint: string;
  tokenEndpoint: string;
  userinfoEndpoint: string;
  discoveryEndpoint: string;
}

export interface ClientConfig {
  // Pre-registered OAuth Clients for Development
  spaClient: {
    id: string;
    name: string;
    type: 'public';
    redirectUris: string[];
    allowedScopes: string[];
    requirePkce: boolean;
  };
  
  apiClient: {
    id: string;
    name: string; 
    type: 'confidential';
    secret: string;
    allowedScopes: string[];
    requirePkce: boolean;
  };
}

export interface AppConfig {
  server: ServerConfig;
  security: SecurityConfig;
  clients: ClientConfig;
  environment: 'development' | 'production' | 'test';
  logLevel: 'debug' | 'info' | 'warn' | 'error';
}

/**
 * Generate secure random session secrets if not provided via environment
 */
function generateSecureSecret(): string {
  return randomBytes(32).toString('hex');
}

/**
 * Create server configuration with environment variable overrides
 */
function createServerConfig(): ServerConfig {
  const port = parseInt(process.env.IDP_PORT || '3001', 10);
  const host = process.env.IDP_HOST || 'localhost';
  const issuer = process.env.IDP_ISSUER || `http://${host}:${port}`;
  
  return {
    port,
    host,
    issuer,
    resourceServerUrl: process.env.RESOURCE_SERVER_URL || 'http://localhost:3000',
    frontendUrl: process.env.FRONTEND_URL || 'http://localhost:5173',
    
    // Auto-construct discovery endpoints from issuer
    jwksUri: `${issuer}/.well-known/jwks.json`,
    authorizationEndpoint: `${issuer}/authorize`,
    tokenEndpoint: `${issuer}/token`,
    userinfoEndpoint: `${issuer}/userinfo`,
    discoveryEndpoint: `${issuer}/.well-known/openid-configuration`
  };
}

/**
 * Create security configuration with environment variable overrides
 */
function createSecurityConfig(): SecurityConfig {
  return {
    // JWT Token Lifetimes (in seconds)
    accessTokenTtl: parseInt(process.env.ACCESS_TOKEN_TTL || '900', 10),      // 15 minutes
    idTokenTtl: parseInt(process.env.ID_TOKEN_TTL || '3600', 10),            // 1 hour
    refreshTokenTtl: parseInt(process.env.REFRESH_TOKEN_TTL || '2592000', 10), // 30 days
    authorizationCodeTtl: parseInt(process.env.AUTH_CODE_TTL || '600', 10),   // 10 minutes
    
    // PKCE Settings (RFC 7636)
    codeVerifierLength: 43,        // Minimum length per spec
    codeChallengeMethod: 'S256',   // SHA256 only (most secure)
    
    // Session Security
    sessionSecret: process.env.SESSION_SECRET || generateSecureSecret(),
    csrfSecret: process.env.CSRF_SECRET || generateSecureSecret(),
    sessionMaxAge: parseInt(process.env.SESSION_MAX_AGE || '86400000', 10), // 24 hours
    
    // Cryptographic Settings
    keyId: process.env.JWT_KEY_ID || 'idp-key-1',
    algorithm: 'RS256',            // RSA with SHA-256
    
    // Network Security
    allowedOrigins: process.env.CORS_ORIGINS?.split(',') || [
      'http://localhost:5173',     // Future frontend SPA
      'http://localhost:3000'      // Resource server (for admin endpoints)
    ],
    requireHttps: process.env.NODE_ENV === 'production',
    trustProxy: process.env.TRUST_PROXY === 'true'
  };
}

/**
 * Create pre-registered OAuth client configurations for development
 */
function createClientConfig(): ClientConfig {
  return {
    // Single Page Application (React/Vue/Angular)
    spaClient: {
      id: process.env.SPA_CLIENT_ID || 'notes-spa',
      name: 'Notes SPA Client',
      type: 'public',
      redirectUris: [
        'http://localhost:5173/callback',    // Local development
        'http://localhost:5173/silent-renew' // Silent token renewal
      ],
      allowedScopes: ['openid', 'notes:read', 'notes:write', 'profile', 'email'],
      requirePkce: true // Required for public clients per RFC 7636
    },
    
    // API/Service Client (for server-to-server communication)
    apiClient: {
      id: process.env.API_CLIENT_ID || 'notes-api',
      name: 'Notes API Client',
      type: 'confidential',
      secret: process.env.API_CLIENT_SECRET || 'api-client-secret-dev-only',
      allowedScopes: ['notes:read', 'notes:write'],
      requirePkce: false // Optional for confidential clients
    }
  };
}

/**
 * Create complete application configuration
 */
function createConfig(): AppConfig {
  const environment = (process.env.NODE_ENV as 'development' | 'production' | 'test') || 'development';
  
  return {
    server: createServerConfig(),
    security: createSecurityConfig(),
    clients: createClientConfig(),
    environment,
    logLevel: (process.env.LOG_LEVEL as 'debug' | 'info' | 'warn' | 'error') || 
              (environment === 'development' ? 'debug' : 'info')
  };
}

// Export singleton configuration instance
export const config: AppConfig = createConfig();

// Export individual config sections for convenience
export const serverConfig = config.server;
export const securityConfig = config.security; 
export const clientConfig = config.clients;

// Export helper functions for validation
export function validateConfig(): { isValid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  // Validate required URLs are properly formatted
  try {
    new URL(config.server.issuer);
    new URL(config.server.resourceServerUrl);
    new URL(config.server.frontendUrl);
  } catch (e) {
    errors.push('Invalid URL configuration detected');
  }
  
  // Validate token TTL values are reasonable
  if (config.security.accessTokenTtl > 3600) {
    errors.push('Access token TTL should not exceed 1 hour for security');
  }
  
  if (config.security.authorizationCodeTtl > 600) {
    errors.push('Authorization code TTL should not exceed 10 minutes per OAuth 2.0 spec');
  }
  
  // Validate session secrets in production
  if (config.environment === 'production') {
    if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
      errors.push('Production requires SESSION_SECRET environment variable (32+ chars)');
    }
    
    if (!process.env.CSRF_SECRET || process.env.CSRF_SECRET.length < 32) {
      errors.push('Production requires CSRF_SECRET environment variable (32+ chars)');
    }
    
    if (!config.security.requireHttps) {
      errors.push('Production requires HTTPS enforcement');
    }
  }
  
  // Validate client configurations
  if (!config.clients.spaClient.redirectUris.length) {
    errors.push('SPA client must have at least one redirect URI');
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
}

/**
 * Log configuration summary (without secrets) for debugging
 */
export function logConfigSummary(): void {
  if (config.logLevel === 'debug') {
    console.log('=== Identity Provider Configuration ===');
    console.log(`Environment: ${config.environment}`);
    console.log(`Server: ${config.server.issuer}`);
    console.log(`Resource Server: ${config.server.resourceServerUrl}`);
    console.log(`Access Token TTL: ${config.security.accessTokenTtl}s`);
    console.log(`PKCE Required: ${config.clients.spaClient.requirePkce}`);
    console.log(`CORS Origins: ${config.security.allowedOrigins.join(', ')}`);
    console.log(`HTTPS Required: ${config.security.requireHttps}`);
    console.log('=====================================');
  }
}