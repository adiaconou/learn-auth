/**
 * Authentication Service
 * 
 * Core OAuth 2.0 + OIDC client implementation for the learning application.
 * Handles authorization code flow with PKCE for secure authentication.
 * 
 * Key responsibilities:
 * - OAuth 2.0 authorization initiation
 * - PKCE parameter generation and management
 * - Authorization URL construction
 * - State management for CSRF protection
 * 
 * Security features:
 * - PKCE for public client security
 * - State parameter for CSRF protection
 * - Nonce for ID token replay protection
 * - Comprehensive logging for debugging
 */

import config, { debugLog } from '../config';
import { generatePKCEParams, generateState, generateNonce, type PKCEParams } from '../utils/crypto';

/**
 * Authorization Request State
 * 
 * Contains all parameters needed for OAuth authorization request
 * and stored locally for callback validation.
 */
export interface AuthRequest {
  state: string;              // CSRF protection parameter
  nonce: string;              // ID token replay protection
  pkce: PKCEParams;           // PKCE code challenge/verifier
  redirectUri: string;        // OAuth callback URL
  scope: string;              // Requested OAuth scopes
  createdAt: number;          // Request timestamp
}

/**
 * Token Response from Identity Provider
 * 
 * Standard OAuth 2.0 token endpoint response
 */
export interface TokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  scope: string;
  id_token?: string;
  refresh_token?: string;
}

/**
 * Parsed Token Set
 * 
 * Processed tokens with expiration timestamps
 */
export interface TokenSet {
  accessToken: string;
  idToken?: string;
  refreshToken?: string;
  tokenType: 'Bearer';
  expiresAt: number;
  scope: string;
}

/**
 * Decoded ID Token Claims
 * 
 * Standard OIDC ID token claims
 */
export interface IdTokenClaims {
  sub: string;                    // Subject (user ID)
  aud: string | string[];         // Audience (client ID)
  iss: string;                    // Issuer (Identity Provider)
  exp: number;                    // Expiration time
  iat: number;                    // Issued at time
  auth_time?: number;             // Authentication time
  nonce?: string;                 // Nonce for replay protection
  email?: string;                 // Email address
  name?: string;                  // Full name
  given_name?: string;            // First name
  family_name?: string;           // Last name
  picture?: string;               // Profile picture URL
}

/**
 * Authentication Service Class
 * 
 * Manages OAuth 2.0 + OIDC authentication flows for the SPA.
 */
export class AuthService {
  private readonly config = config.identityProvider;
  
  constructor() {
    console.log('🔐 AuthService initialized');
    debugLog('AUTH', 'Service configuration', {
      issuer: this.config.issuer,
      clientId: this.config.clientId,
      redirectUri: this.config.redirectUri,
      scope: this.config.scope,
    });
  }

  /**
   * Initiate OAuth 2.0 authorization flow
   * 
   * This method starts the OAuth flow by:
   * 1. Generating PKCE parameters for security
   * 2. Creating state and nonce for protection
   * 3. Storing request parameters for callback validation
   * 4. Building authorization URL with all parameters
   * 5. Redirecting user to Identity Provider
   * 
   * @param redirectUri - Optional custom redirect URI
   */
  async initiateLogin(redirectUri?: string): Promise<void> {
    console.log('🚀 Starting OAuth 2.0 authorization flow...');
    
    try {
      // Step 1: Create authorization request with security parameters
      const authRequest = await this.createAuthRequest(redirectUri);
      console.log('📋 Authorization request created:');
      console.log(`   • State: ${authRequest.state}`);
      console.log(`   • Nonce: ${authRequest.nonce}`);
      console.log(`   • PKCE Challenge: ${authRequest.pkce.codeChallenge}`);
      console.log(`   • Redirect URI: ${authRequest.redirectUri}`);
      console.log(`   • Scope: ${authRequest.scope}`);
      
      // Step 2: Store request state for callback validation
      this.storeAuthRequest(authRequest);
      debugLog('AUTH', 'Auth request stored in session storage');
      
      // Step 3: Build authorization URL
      const authUrl = this.buildAuthorizationUrl(authRequest);
      console.log('🔗 Authorization URL constructed:');
      console.log(`   ${authUrl}`);
      
      // Step 4: Log the redirect action
      console.log('🔄 Redirecting to Identity Provider for authentication...');
      console.log('👤 User will be prompted to authenticate and grant consent');
      
      // Step 5: Redirect to Identity Provider
      window.location.href = authUrl;
      
    } catch (error) {
      console.error('❌ Failed to initiate OAuth flow:', error);
      throw new Error(`Login initiation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Create authorization request with security parameters
   * 
   * Generates all cryptographic parameters needed for secure OAuth flow:
   * - PKCE parameters for public client security
   * - State parameter for CSRF protection
   * - Nonce for ID token replay protection
   * 
   * @param redirectUri - Optional custom redirect URI
   * @returns Promise resolving to complete auth request
   */
  private async createAuthRequest(redirectUri?: string): Promise<AuthRequest> {
    debugLog('AUTH', 'Creating authorization request...');
    
    // Generate PKCE parameters for secure authorization
    const pkce = await generatePKCEParams();
    
    // Generate security parameters
    const state = generateState();
    const nonce = generateNonce();
    
    const authRequest: AuthRequest = {
      state,
      nonce,
      pkce,
      redirectUri: redirectUri || this.config.redirectUri,
      scope: this.config.scope,
      createdAt: Date.now(),
    };
    
    debugLog('AUTH', 'Authorization request created', {
      state: authRequest.state,
      nonce: authRequest.nonce,
      redirectUri: authRequest.redirectUri,
      scope: authRequest.scope,
      codeChallenge: authRequest.pkce.codeChallenge,
    });
    
    return authRequest;
  }

  /**
   * Build OAuth 2.0 authorization URL
   * 
   * Constructs the complete authorization URL according to RFC 6749 and RFC 7636.
   * Includes all required and optional parameters for OAuth + OIDC + PKCE flow.
   * 
   * @param authRequest - Authorization request parameters
   * @returns Complete authorization URL
   */
  private buildAuthorizationUrl(authRequest: AuthRequest): string {
    debugLog('AUTH', 'Building authorization URL...');
    
    // Build URL parameters according to OAuth 2.0 + OIDC + PKCE specs
    const params = new URLSearchParams({
      // OAuth 2.0 Core Parameters (RFC 6749)
      response_type: this.config.responseType,          // 'code' for authorization code flow
      client_id: this.config.clientId,                  // Public client identifier
      redirect_uri: authRequest.redirectUri,            // Callback URL
      scope: authRequest.scope,                         // Requested permissions
      state: authRequest.state,                         // CSRF protection
      
      // OpenID Connect Parameters (OIDC Core)
      nonce: authRequest.nonce,                         // ID token replay protection
      
      // PKCE Parameters (RFC 7636)
      code_challenge: authRequest.pkce.codeChallenge,  // SHA256 hash of code verifier
      code_challenge_method: authRequest.pkce.codeChallengeMethod, // 'S256'
    });
    
    // Construct complete authorization endpoint URL
    const authorizationUrl = `${this.config.issuer}/authorize?${params.toString()}`;
    
    debugLog('AUTH', 'Authorization URL built', { url: authorizationUrl });
    console.log('📝 Authorization URL parameters:');
    console.log(`   • response_type: ${params.get('response_type')}`);
    console.log(`   • client_id: ${params.get('client_id')}`);
    console.log(`   • redirect_uri: ${params.get('redirect_uri')}`);
    console.log(`   • scope: ${params.get('scope')}`);
    console.log(`   • state: ${params.get('state')}`);
    console.log(`   • nonce: ${params.get('nonce')}`);
    console.log(`   • code_challenge_method: ${params.get('code_challenge_method')}`);
    console.log(`   • code_challenge: ${params.get('code_challenge')}`);
    
    return authorizationUrl;
  }

  /**
   * Store authorization request for callback validation
   * 
   * Stores auth request parameters in session storage for later
   * validation during OAuth callback processing.
   * 
   * Uses session storage (not localStorage) to ensure the state
   * is automatically cleared when the browser tab is closed.
   * 
   * @param authRequest - Authorization request to store
   */
  private storeAuthRequest(authRequest: AuthRequest): void {
    debugLog('AUTH', 'Storing auth request in session storage');
    
    try {
      const serialized = JSON.stringify(authRequest);
      sessionStorage.setItem('oauth_auth_request', serialized);
      
      console.log('💾 Authorization request stored in session storage');
      console.log(`   • Storage key: oauth_auth_request`);
      console.log(`   • Data size: ${serialized.length} characters`);
      
    } catch (error) {
      console.error('❌ Failed to store auth request:', error);
      throw new Error('Failed to store authorization request');
    }
  }

  /**
   * Retrieve stored authorization request
   * 
   * Used during callback processing to validate the OAuth response
   * against the original request parameters.
   * 
   * @returns Stored auth request or null if not found
   */
  getStoredAuthRequest(): AuthRequest | null {
    debugLog('AUTH', 'Retrieving stored auth request');
    
    try {
      const serialized = sessionStorage.getItem('oauth_auth_request');
      
      if (!serialized) {
        debugLog('AUTH', 'No auth request found in session storage');
        return null;
      }
      
      const authRequest = JSON.parse(serialized) as AuthRequest;
      
      console.log('📥 Retrieved stored authorization request:');
      console.log(`   • State: ${authRequest.state}`);
      console.log(`   • Created: ${new Date(authRequest.createdAt).toISOString()}`);
      
      return authRequest;
      
    } catch (error) {
      console.error('❌ Failed to retrieve auth request:', error);
      return null;
    }
  }

  /**
   * Clear stored authorization request
   * 
   * Called after successful callback processing or on logout
   * to clean up temporary OAuth state.
   */
  clearStoredAuthRequest(): void {
    debugLog('AUTH', 'Clearing stored auth request');
    sessionStorage.removeItem('oauth_auth_request');
    console.log('🧹 Authorization request cleared from session storage');
  }

  /**
   * Handle OAuth callback and complete authentication flow
   * 
   * This method processes the OAuth callback by:
   * 1. Validating the state parameter to prevent CSRF attacks
   * 2. Extracting the authorization code from URL parameters
   * 3. Exchanging the code for tokens using PKCE verification
   * 4. Validating and decoding the ID token
   * 5. Storing tokens securely for future API calls
   * 
   * @param code - Authorization code from callback URL
   * @param state - State parameter from callback URL
   * @returns Promise resolving to token set and user info
   */
  async handleCallback(code: string, state: string): Promise<{ tokens: TokenSet; user: IdTokenClaims }> {
    console.log('🔄 Processing OAuth callback...');
    console.log(`   • Code: ${code.substring(0, 8)}...`);
    console.log(`   • State: ${state}`);
    
    try {
      // Step 1: Retrieve and validate stored authorization request
      const authRequest = this.getStoredAuthRequest();
      
      if (!authRequest) {
        throw new Error('No authorization request found - possible session timeout');
      }
      
      if (authRequest.state !== state) {
        console.error('❌ State mismatch detected:');
        console.error(`   • Expected: ${authRequest.state}`);
        console.error(`   • Received: ${state}`);
        throw new Error('Invalid state parameter - possible CSRF attack');
      }
      
      console.log('✅ State parameter validated successfully');
      console.log(`   • Request age: ${Date.now() - authRequest.createdAt}ms`);
      
      // Step 2: Exchange authorization code for tokens
      const tokens = await this.exchangeCodeForTokens(code, authRequest);
      console.log('✅ Tokens obtained successfully');
      console.log(`   • Access Token: ${tokens.accessToken.substring(0, 20)}...`);
      console.log(`   • ID Token: ${tokens.idToken?.substring(0, 20)}...`);
      console.log(`   • Expires At: ${new Date(tokens.expiresAt).toISOString()}`);
      console.log(`   • Scope: ${tokens.scope}`);
      
      // Step 3: Validate and decode ID token
      let user: IdTokenClaims;
      if (tokens.idToken) {
        user = await this.validateAndDecodeIdToken(tokens.idToken, authRequest.nonce);
        console.log('✅ ID token validated and decoded');
        console.log(`   • Subject (User ID): ${user.sub}`);
        console.log(`   • Email: ${user.email || 'not provided'}`);
        console.log(`   • Name: ${user.name || 'not provided'}`);
      } else {
        throw new Error('No ID token received - OIDC flow incomplete');
      }
      
      // Step 4: Store tokens and user info securely
      this.storeTokens(tokens);
      this.storeUser(user);
      
      // Step 5: Clean up authorization request
      this.clearStoredAuthRequest();
      
      console.log('🎉 OAuth callback processing completed successfully');
      return { tokens, user };
      
    } catch (error) {
      // Clean up on error
      this.clearStoredAuthRequest();
      
      console.error('❌ OAuth callback processing failed:', error);
      throw new Error(`Callback processing failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Exchange authorization code for tokens
   * 
   * Makes a POST request to the token endpoint with:
   * - Authorization code from callback
   * - PKCE code verifier for security
   * - Client credentials and redirect URI
   * 
   * @param code - Authorization code from callback
   * @param authRequest - Original authorization request with PKCE params
   * @returns Promise resolving to parsed token set
   */
  private async exchangeCodeForTokens(code: string, authRequest: AuthRequest): Promise<TokenSet> {
    console.log('🔄 Exchanging authorization code for tokens...');
    debugLog('AUTH', 'Token exchange initiated', {
      code: code.substring(0, 8) + '...',
      codeVerifier: authRequest.pkce.codeVerifier.substring(0, 8) + '...',
    });
    
    try {
      // Build token request parameters according to RFC 6749 + RFC 7636
      const tokenParams = new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: authRequest.redirectUri,
        client_id: this.config.clientId,
        code_verifier: authRequest.pkce.codeVerifier,  // PKCE verification
      });
      
      console.log('📨 Making token exchange request...');
      console.log(`   • Endpoint: ${this.config.issuer}/token`);
      console.log(`   • Grant Type: authorization_code`);
      console.log(`   • Client ID: ${this.config.clientId}`);
      console.log(`   • Redirect URI: ${authRequest.redirectUri}`);
      console.log(`   • Code Verifier: ${authRequest.pkce.codeVerifier.substring(0, 8)}...`);
      
      const response = await fetch(`${this.config.issuer}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json',
        },
        body: tokenParams.toString(),
      });
      
      console.log(`📥 Token response received: ${response.status} ${response.statusText}`);
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        console.error('❌ Token exchange failed:');
        console.error(`   • Status: ${response.status}`);
        console.error(`   • Error: ${errorData.error || 'unknown_error'}`);
        console.error(`   • Description: ${errorData.error_description || 'No description provided'}`);
        
        throw new Error(errorData.error_description || `Token exchange failed with status ${response.status}`);
      }
      
      const tokenResponse: TokenResponse = await response.json();
      const tokens = this.parseTokenResponse(tokenResponse);
      
      console.log('✅ Token exchange completed successfully');
      return tokens;
      
    } catch (error) {
      console.error('❌ Token exchange failed:', error);
      
      if (error instanceof TypeError) {
        throw new Error('Network error during token exchange - check if Identity Provider is running');
      }
      
      throw error;
    }
  }

  /**
   * Parse token response into structured token set
   * 
   * Converts the raw token endpoint response into a structured
   * token set with calculated expiration timestamps.
   * 
   * @param tokenResponse - Raw token response from IdP
   * @returns Parsed and structured token set
   */
  private parseTokenResponse(tokenResponse: TokenResponse): TokenSet {
    debugLog('AUTH', 'Parsing token response', {
      hasAccessToken: !!tokenResponse.access_token,
      hasIdToken: !!tokenResponse.id_token,
      hasRefreshToken: !!tokenResponse.refresh_token,
      expiresIn: tokenResponse.expires_in,
      scope: tokenResponse.scope,
    });
    
    // Calculate absolute expiration time
    const expiresAt = Date.now() + (tokenResponse.expires_in * 1000);
    
    const tokens: TokenSet = {
      accessToken: tokenResponse.access_token,
      idToken: tokenResponse.id_token,
      refreshToken: tokenResponse.refresh_token,
      tokenType: tokenResponse.token_type,
      expiresAt,
      scope: tokenResponse.scope,
    };
    
    console.log('📋 Token set parsed:');
    console.log(`   • Access Token Length: ${tokens.accessToken.length} characters`);
    console.log(`   • ID Token: ${tokens.idToken ? 'present' : 'not provided'}`);
    console.log(`   • Refresh Token: ${tokens.refreshToken ? 'present' : 'not provided'}`);
    console.log(`   • Token Type: ${tokens.tokenType}`);
    console.log(`   • Expires At: ${new Date(tokens.expiresAt).toISOString()}`);
    console.log(`   • Scope: ${tokens.scope}`);
    
    return tokens;
  }

  /**
   * Validate and decode ID token
   * 
   * Validates the ID token signature and claims, then decodes
   * the payload to extract user information. This is a simplified
   * validation - production should verify signature against JWKS.
   * 
   * @param idToken - JWT ID token from token response
   * @param expectedNonce - Nonce from original authorization request
   * @returns Promise resolving to decoded ID token claims
   */
  private async validateAndDecodeIdToken(idToken: string, expectedNonce: string): Promise<IdTokenClaims> {
    console.log('🔍 Validating and decoding ID token...');
    debugLog('AUTH', 'ID token validation started', {
      tokenLength: idToken.length,
      expectedNonce,
    });
    
    try {
      // Decode JWT payload (base64url decode the middle part)
      const [header, payload, signature] = idToken.split('.');
      
      if (!header || !payload || !signature) {
        throw new Error('Malformed ID token - missing JWT segments');
      }
      
      // Decode payload
      const decodedPayload = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
      const claims: IdTokenClaims = decodedPayload;
      
      console.log('📋 ID token decoded successfully:');
      console.log(`   • Issuer: ${claims.iss}`);
      console.log(`   • Subject: ${claims.sub}`);
      console.log(`   • Audience: ${Array.isArray(claims.aud) ? claims.aud.join(', ') : claims.aud}`);
      console.log(`   • Issued At: ${new Date(claims.iat * 1000).toISOString()}`);
      console.log(`   • Expires At: ${new Date(claims.exp * 1000).toISOString()}`);
      console.log(`   • Nonce: ${claims.nonce || 'not present'}`);
      
      // Validate basic claims
      if (claims.iss !== this.config.issuer) {
        throw new Error(`Invalid issuer: expected ${this.config.issuer}, got ${claims.iss}`);
      }
      
      // Validate audience (client ID)
      const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
      if (!audience.includes(this.config.clientId)) {
        throw new Error(`Invalid audience: token not intended for client ${this.config.clientId}`);
      }
      
      // Validate expiration
      if (claims.exp * 1000 <= Date.now()) {
        throw new Error('ID token has expired');
      }
      
      // Validate nonce for replay protection
      if (claims.nonce !== expectedNonce) {
        console.error('❌ Nonce mismatch detected:');
        console.error(`   • Expected: ${expectedNonce}`);
        console.error(`   • Received: ${claims.nonce || 'none'}`);
        throw new Error('Invalid nonce - possible token replay attack');
      }
      
      console.log('✅ ID token validation completed successfully');
      
      // Extract user information
      const userInfo = {
        sub: claims.sub,
        email: claims.email,
        name: claims.name || claims.given_name || claims.email,
        auth_time: claims.auth_time,
      };
      
      console.log('👤 User information extracted:');
      console.log(`   • User ID: ${userInfo.sub}`);
      console.log(`   • Email: ${userInfo.email || 'not provided'}`);
      console.log(`   • Name: ${userInfo.name || 'not provided'}`);
      
      return claims;
      
    } catch (error) {
      console.error('❌ ID token validation failed:', error);
      
      if (error instanceof SyntaxError) {
        throw new Error('ID token payload is not valid JSON');
      }
      
      throw error;
    }
  }

  /**
   * Store tokens securely
   * 
   * Stores the token set in session storage for use in API calls.
   * In production, consider more secure storage options.
   * 
   * @param tokens - Token set to store
   */
  private storeTokens(tokens: TokenSet): void {
    debugLog('AUTH', 'Storing tokens securely');
    
    try {
      const tokenData = JSON.stringify(tokens);
      sessionStorage.setItem('oauth_tokens', tokenData);
      
      console.log('💾 Tokens stored in session storage');
      console.log(`   • Storage key: oauth_tokens`);
      console.log(`   • Data size: ${tokenData.length} characters`);
      
    } catch (error) {
      console.error('❌ Failed to store tokens:', error);
      throw new Error('Failed to store authentication tokens');
    }
  }

  /**
   * Store user information
   * 
   * Stores user profile information from ID token claims
   * for display in the application.
   * 
   * @param user - User information to store
   */
  private storeUser(user: IdTokenClaims): void {
    debugLog('AUTH', 'Storing user information');
    
    try {
      const userData = JSON.stringify(user);
      sessionStorage.setItem('oauth_user', userData);
      
      console.log('💾 User information stored in session storage');
      console.log(`   • Storage key: oauth_user`);
      console.log(`   • User ID: ${user.sub}`);
      
    } catch (error) {
      console.error('❌ Failed to store user information:', error);
      throw new Error('Failed to store user information');
    }
  }

  /**
   * Get stored tokens
   * 
   * Retrieves the current token set from storage.
   * 
   * @returns Stored token set or null if not found
   */
  getStoredTokens(): TokenSet | null {
    try {
      const tokenData = sessionStorage.getItem('oauth_tokens');
      
      if (!tokenData) {
        return null;
      }
      
      return JSON.parse(tokenData) as TokenSet;
      
    } catch (error) {
      console.error('❌ Failed to retrieve tokens:', error);
      return null;
    }
  }

  /**
   * Get stored user information
   * 
   * Retrieves the current user information from storage.
   * 
   * @returns Stored user information or null if not found
   */
  getStoredUser(): IdTokenClaims | null {
    try {
      const userData = sessionStorage.getItem('oauth_user');
      
      if (!userData) {
        return null;
      }
      
      return JSON.parse(userData) as IdTokenClaims;
      
    } catch (error) {
      console.error('❌ Failed to retrieve user information:', error);
      return null;
    }
  }

  /**
   * Clear all stored authentication data
   * 
   * Removes all tokens, user info, and auth state from storage.
   * Called during logout or authentication errors.
   */
  clearAllStoredData(): void {
    console.log('🧹 Clearing all stored authentication data...');
    
    sessionStorage.removeItem('oauth_tokens');
    sessionStorage.removeItem('oauth_user');
    sessionStorage.removeItem('oauth_auth_request');
    
    console.log('✅ All authentication data cleared');
  }

  /**
   * Check if user is currently authenticated
   * 
   * @returns True if user has valid tokens
   */
  isAuthenticated(): boolean {
    const tokens = this.getStoredTokens();
    return tokens !== null && tokens.expiresAt > Date.now();
  }
}

// Export singleton instance
export const authService = new AuthService();

export default authService;