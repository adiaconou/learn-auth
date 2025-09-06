/**
 * Application Configuration
 * 
 * Centralized configuration management for the OAuth 2.0 + OIDC SPA.
 * Handles environment variables and provides typed configuration access.
 * 
 * Security considerations:
 * - No secrets are stored in frontend config (client is public)
 * - All values are safe to expose in browser
 * - Environment variables are prefixed with VITE_ for Vite bundling
 */

export interface AppConfig {
  // Identity Provider Settings
  identityProvider: {
    issuer: string;                 // IdP base URL
    clientId: string;               // Public client identifier
    redirectUri: string;            // OAuth callback URL
    scope: string;                  // Requested OAuth scopes
    responseType: 'code';           // Authorization code flow
    codeChallengeMethod: 'S256';    // PKCE method
  };
  
  // Resource Server Settings  
  resourceServer: {
    baseUrl: string;                // Notes API base URL
    audience: string;               // Expected JWT audience
  };
  
  // Security Settings
  security: {
    tokenStorageType: 'memory' | 'localStorage' | 'sessionStorage';
    autoRefreshTokens: boolean;     // Automatic refresh before expiry
    refreshThresholdSec: number;    // Refresh when expires in X seconds
    logoutOnTokenExpiry: boolean;   // Force logout if refresh fails
  };
  
  // Development Settings
  development: {
    enableDebugLogs: boolean;       // Console logging
    mockAuthFlow: boolean;          // Skip real OAuth for testing
    bypassTokenValidation: boolean; // Skip JWT validation
  };
}

/**
 * Get configuration value with fallback and validation
 */
function getEnvVar(key: string, defaultValue: string, required: boolean = false): string {
  const value = import.meta.env[key] || defaultValue;
  
  if (required && !value) {
    throw new Error(`Required environment variable ${key} is not set`);
  }
  
  console.log(`🔧 Config: ${key} = ${value}`);
  return value;
}

/**
 * Main application configuration
 * 
 * Environment variables (all optional with sensible defaults):
 * - VITE_IDP_ISSUER: Identity Provider base URL
 * - VITE_IDP_CLIENT_ID: OAuth client ID
 * - VITE_RESOURCE_SERVER_URL: Notes API base URL
 * - VITE_REDIRECT_URI: OAuth callback URL
 * - VITE_ENABLE_DEBUG: Enable debug logging
 */
export const config: AppConfig = {
  identityProvider: {
    issuer: getEnvVar('VITE_IDP_ISSUER', 'http://localhost:3001'),
    clientId: getEnvVar('VITE_IDP_CLIENT_ID', 'notes-spa'),
    redirectUri: getEnvVar('VITE_REDIRECT_URI', 'http://localhost:5173/callback'),
    scope: 'openid notes:read notes:write',
    responseType: 'code',
    codeChallengeMethod: 'S256',
  },
  
  resourceServer: {
    baseUrl: getEnvVar('VITE_RESOURCE_SERVER_URL', 'http://localhost:3000'),
    audience: 'notes-api',
  },
  
  security: {
    tokenStorageType: 'memory', // Most secure for learning app
    autoRefreshTokens: true,
    refreshThresholdSec: 300,   // Refresh 5 minutes before expiry
    logoutOnTokenExpiry: true,
  },
  
  development: {
    enableDebugLogs: getEnvVar('VITE_ENABLE_DEBUG', 'true') === 'true',
    mockAuthFlow: false,
    bypassTokenValidation: false,
  },
};

/**
 * Debug logging utility
 */
export function debugLog(category: string, message: string, data?: any) {
  if (config.development.enableDebugLogs) {
    const timestamp = new Date().toISOString();
    console.log(`🔍 [${timestamp}] [${category}] ${message}`, data || '');
  }
}

/**
 * Initialize configuration and log startup info
 */
export function initializeConfig(): AppConfig {
  console.log('🚀 OAuth 2.0 + OIDC Learning App - Configuration Loaded');
  console.log('📋 Configuration Summary:');
  console.log(`   • Identity Provider: ${config.identityProvider.issuer}`);
  console.log(`   • Client ID: ${config.identityProvider.clientId}`);
  console.log(`   • Redirect URI: ${config.identityProvider.redirectUri}`);
  console.log(`   • Resource Server: ${config.resourceServer.baseUrl}`);
  console.log(`   • Debug Logging: ${config.development.enableDebugLogs ? 'Enabled' : 'Disabled'}`);
  console.log(`   • Token Storage: ${config.security.tokenStorageType}`);
  
  // Validate URLs
  try {
    new URL(config.identityProvider.issuer);
    new URL(config.identityProvider.redirectUri);
    new URL(config.resourceServer.baseUrl);
    debugLog('CONFIG', 'All URLs validated successfully');
  } catch (error) {
    console.error('❌ Invalid URL in configuration:', error);
    throw new Error('Configuration validation failed: Invalid URL format');
  }
  
  return config;
}

// Initialize configuration on module load
initializeConfig();

export default config;