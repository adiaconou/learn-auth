/**
 * OAuth Client Management Service
 * 
 * Handles OAuth 2.0 client validation, registration, and management.
 * Validates client credentials, redirect URIs, and scope permissions
 * according to RFC 6749 OAuth 2.0 specification.
 * 
 * Key responsibilities:
 * - Client authentication and validation
 * - Redirect URI validation (exact matching for security)
 * - Scope validation and authorization
 * - PKCE requirement enforcement for public clients
 * - Client type management (public vs confidential)
 */

import { clientConfig } from '../config';
import { debugLog } from '../config';
import { OAuthClient } from '../storage/models';

/**
 * OAuth Client Validation Result
 */
export interface ClientValidationResult {
  isValid: boolean;
  client?: OAuthClient;
  error?: string;
  errorDescription?: string;
}

/**
 * Redirect URI Validation Result
 */
export interface RedirectValidationResult {
  isValid: boolean;
  error?: string;
  errorDescription?: string;
}

/**
 * Scope Validation Result
 */
export interface ScopeValidationResult {
  isValid: boolean;
  grantedScopes: string[];
  error?: string;
  errorDescription?: string;
}

/**
 * OAuth Client Management Service
 * 
 * Manages OAuth client registration, validation, and permissions.
 * In production, this would integrate with a client registration system.
 */
export class ClientService {
  
  /**
   * Get registered OAuth client by ID
   * 
   * @param clientId Client identifier
   * @returns OAuth client or null if not found
   */
  getClient(clientId: string): OAuthClient | null {
    debugLog('CLIENT', `Looking up client: ${clientId}`);
    
    // Check pre-registered SPA client
    if (clientId === clientConfig.spaClient.id) {
      const client: OAuthClient = {
        id: clientConfig.spaClient.id,
        name: clientConfig.spaClient.name,
        type: clientConfig.spaClient.type,
        redirectUris: clientConfig.spaClient.redirectUris,
        allowedScopes: clientConfig.spaClient.allowedScopes,
        requirePkce: clientConfig.spaClient.requirePkce,
        isActive: true,
        createdAt: new Date()
      };
      
      debugLog('CLIENT', `Found SPA client: ${client.name}`);
      return client;
    }
    
    // Check pre-registered API client
    if (clientId === clientConfig.apiClient.id) {
      const client: OAuthClient = {
        id: clientConfig.apiClient.id,
        name: clientConfig.apiClient.name,
        type: clientConfig.apiClient.type,
        redirectUris: [], // API clients typically don't use redirects
        allowedScopes: clientConfig.apiClient.allowedScopes,
        secret: clientConfig.apiClient.secret,
        requirePkce: clientConfig.apiClient.requirePkce,
        isActive: true,
        createdAt: new Date()
      };
      
      debugLog('CLIENT', `Found API client: ${client.name}`);
      return client;
    }
    
    debugLog('CLIENT', `Client not found: ${clientId}`);
    return null;
  }

  /**
   * Validate OAuth client for authorization request
   * 
   * Performs comprehensive client validation according to OAuth 2.0 spec:
   * - Client existence and status
   * - Client type and authentication requirements
   * - PKCE requirements for public clients
   * 
   * @param clientId Client identifier from authorization request
   * @param codeChallenge PKCE code challenge (required for public clients)
   * @param codeChallengeMethod PKCE challenge method
   * @returns Client validation result
   */
  validateClient(
    clientId: string, 
    codeChallenge?: string, 
    codeChallengeMethod?: string
  ): ClientValidationResult {
    debugLog('CLIENT', `Validating client: ${clientId}`);
    
    // Step 1: Check if client exists
    const client = this.getClient(clientId);
    if (!client) {
      debugLog('CLIENT', `Client validation failed: client not found`);
      return {
        isValid: false,
        error: 'invalid_client',
        errorDescription: `Unknown client: ${clientId}`
      };
    }
    
    // Step 2: Validate PKCE requirements for public clients
    if (client.requirePkce) {
      if (!codeChallenge) {
        debugLog('CLIENT', `PKCE validation failed: missing code_challenge`);
        return {
          isValid: false,
          error: 'invalid_request',
          errorDescription: 'code_challenge parameter is required for this client'
        };
      }
      
      if (!codeChallengeMethod || codeChallengeMethod !== 'S256') {
        debugLog('CLIENT', `PKCE validation failed: invalid challenge method`);
        return {
          isValid: false,
          error: 'invalid_request',
          errorDescription: 'code_challenge_method must be S256'
        };
      }
      
      debugLog('CLIENT', `PKCE validation passed for public client`);
    }
    
    debugLog('CLIENT', `Client validation successful: ${client.name}`);
    return {
      isValid: true,
      client
    };
  }

  /**
   * Validate redirect URI for OAuth authorization request
   * 
   * Performs exact matching of redirect URIs as required by OAuth 2.0 spec.
   * This prevents authorization code interception attacks.
   * 
   * @param client OAuth client
   * @param redirectUri Redirect URI from authorization request
   * @returns Redirect validation result
   */
  validateRedirectUri(client: OAuthClient, redirectUri: string): RedirectValidationResult {
    debugLog('CLIENT', `Validating redirect URI: ${redirectUri}`);
    debugLog('CLIENT', `Allowed URIs: ${client.redirectUris.join(', ')}`);
    
    // OAuth 2.0 requires exact string matching of redirect URIs
    if (!client.redirectUris.includes(redirectUri)) {
      debugLog('CLIENT', `Redirect URI validation failed: not in allowed list`);
      return {
        isValid: false,
        error: 'invalid_request',
        errorDescription: 'redirect_uri is not registered for this client'
      };
    }
    
    // Additional security: validate URI format
    try {
      const url = new URL(redirectUri);
      
      // Prevent javascript: and data: schemes for security
      if (url.protocol === 'javascript:' || url.protocol === 'data:') {
        debugLog('CLIENT', `Redirect URI validation failed: dangerous protocol`);
        return {
          isValid: false,
          error: 'invalid_request',
          errorDescription: 'redirect_uri uses an invalid protocol'
        };
      }
      
    } catch (error) {
      debugLog('CLIENT', `Redirect URI validation failed: malformed URL`);
      return {
        isValid: false,
        error: 'invalid_request',
        errorDescription: 'redirect_uri is not a valid URL'
      };
    }
    
    debugLog('CLIENT', `Redirect URI validation successful`);
    return { isValid: true };
  }

  /**
   * Validate and filter requested scopes
   * 
   * Ensures client can only request scopes they are authorized for.
   * Returns the intersection of requested and allowed scopes.
   * 
   * @param client OAuth client
   * @param requestedScopes Space-separated scope string
   * @returns Scope validation result with granted scopes
   */
  validateScopes(client: OAuthClient, requestedScopes: string): ScopeValidationResult {
    debugLog('CLIENT', `Validating scopes: ${requestedScopes}`);
    debugLog('CLIENT', `Allowed scopes: ${client.allowedScopes.join(', ')}`);
    
    // Parse requested scopes (space-separated string)
    const requestedScopeList = requestedScopes.trim().split(/\s+/).filter(s => s.length > 0);
    
    if (requestedScopeList.length === 0) {
      debugLog('CLIENT', `Scope validation failed: no scopes requested`);
      return {
        isValid: false,
        grantedScopes: [],
        error: 'invalid_scope',
        errorDescription: 'No scopes requested'
      };
    }
    
    // Filter scopes to only those the client is allowed to request
    const grantedScopes: string[] = [];
    const unauthorizedScopes: string[] = [];
    
    for (const scope of requestedScopeList) {
      if (client.allowedScopes.includes(scope)) {
        grantedScopes.push(scope);
      } else {
        unauthorizedScopes.push(scope);
      }
    }
    
    // If no valid scopes, return error
    if (grantedScopes.length === 0) {
      debugLog('CLIENT', `Scope validation failed: no authorized scopes`);
      return {
        isValid: false,
        grantedScopes: [],
        error: 'invalid_scope',
        errorDescription: `Client is not authorized for requested scopes: ${requestedScopes}`
      };
    }
    
    // Log any unauthorized scopes (but don't fail the request)
    if (unauthorizedScopes.length > 0) {
      debugLog('CLIENT', `Unauthorized scopes ignored: ${unauthorizedScopes.join(', ')}`);
    }
    
    debugLog('CLIENT', `Scope validation successful: ${grantedScopes.join(', ')}`);
    return {
      isValid: true,
      grantedScopes
    };
  }

  /**
   * Check if client requires user consent for requested scopes
   * 
   * In production, this would check:
   * - First-party vs third-party clients
   * - Previously granted consent
   * - Trusted client status
   * - Scope sensitivity levels
   * 
   * @param client OAuth client
   * @param scopes Requested scopes
   * @returns True if consent is required
   */
  requiresConsent(client: OAuthClient, scopes: string[]): boolean {
    debugLog('CLIENT', `Checking consent requirements for: ${client.name}`);
    
    // For learning purposes, always require consent for scope authorization
    // In production, first-party clients might skip consent for basic scopes
    const requiresConsent = true;
    
    debugLog('CLIENT', `Consent required: ${requiresConsent}`);
    return requiresConsent;
  }

  /**
   * Authenticate confidential client using client credentials
   * 
   * Used during token exchange to verify client identity.
   * Public clients (SPAs) don't use client authentication.
   * 
   * @param clientId Client identifier
   * @param clientSecret Client secret (for confidential clients)
   * @returns Client validation result
   */
  authenticateClient(clientId: string, clientSecret?: string): ClientValidationResult {
    debugLog('CLIENT', `Authenticating client: ${clientId}`);
    
    const client = this.getClient(clientId);
    if (!client) {
      return {
        isValid: false,
        error: 'invalid_client',
        errorDescription: 'Client authentication failed'
      };
    }
    
    // Public clients don't require authentication
    if (client.type === 'public') {
      debugLog('CLIENT', `Public client authentication successful`);
      return {
        isValid: true,
        client
      };
    }
    
    // Confidential clients require secret authentication
    if (client.type === 'confidential') {
      if (!clientSecret || clientSecret !== client.secret) {
        debugLog('CLIENT', `Confidential client authentication failed`);
        return {
          isValid: false,
          error: 'invalid_client',
          errorDescription: 'Client authentication failed'
        };
      }
      
      debugLog('CLIENT', `Confidential client authentication successful`);
      return {
        isValid: true,
        client
      };
    }
    
    return {
      isValid: false,
      error: 'invalid_client',
      errorDescription: 'Unknown client type'
    };
  }
}

// Export singleton instance
export const clientService = new ClientService();
export default clientService;