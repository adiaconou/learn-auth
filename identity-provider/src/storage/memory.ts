import { 
  User, 
  OAuthClient, 
  AuthorizationCode, 
  RefreshToken, 
  ConsentGrant 
} from './models';

/**
 * In-Memory Storage for OAuth 2.0 + OIDC Identity Provider
 * 
 * This module provides in-memory storage for all OAuth/OIDC entities during development.
 * In production, these would be replaced with persistent databases (PostgreSQL, MongoDB, etc.).
 * 
 * Key Storage Concepts:
 * - Thread-Safe Operations: All operations are synchronous and atomic
 * - TTL Cleanup: Automatic cleanup of expired codes and tokens
 * - Memory Efficiency: Maps for O(1) lookups, cleanup to prevent memory leaks
 * - Development Focus: Simple implementation prioritizing learning over production concerns
 * 
 * Storage Architecture:
 * ```
 * ┌─────────────────────────────────────────────────────────┐
 * │                  Memory Storage                         │
 * ├─────────────────────────────────────────────────────────┤
 * │ Users Map            │ OAuth Clients Map               │
 * │ ├─ userId → User     │ ├─ clientId → OAuthClient      │
 * │ └─ username → userId │ └─ (indexed lookup)             │
 * ├─────────────────────────────────────────────────────────┤
 * │ Authorization Codes  │ Refresh Tokens Map              │
 * │ ├─ code → AuthCode   │ ├─ tokenId → RefreshToken      │
 * │ └─ (auto-cleanup)    │ └─ (cleanup on revocation)     │
 * ├─────────────────────────────────────────────────────────┤
 * │ Consent Grants       │ Cleanup Tasks                   │
 * │ ├─ userId+clientId   │ ├─ Expired Codes (every 5 min) │
 * │ └─ → ConsentGrant    │ └─ Expired Tokens (hourly)     │
 * └─────────────────────────────────────────────────────────┘
 * ```
 * 
 * Cleanup Strategy:
 * - Authorization Codes: Cleaned up every 5 minutes (short TTL)
 * - Refresh Tokens: Cleaned up hourly (longer TTL)
 * - Expired Entities: Removed automatically to prevent memory leaks
 * 
 * ## Production Migration Notes
 * 
 * When moving to production databases:
 * - Replace Maps with database queries
 * - Add database indexes on frequently queried fields
 * - Implement proper connection pooling
 * - Add database transactions for multi-table operations
 * - Use database triggers or scheduled jobs for cleanup
 * - Add audit logging for security events
 * - Implement read replicas for high availability
 */

// In-memory storage maps
const users = new Map<string, User>();                    // userId → User
const usersByUsername = new Map<string, string>();        // username → userId
const usersByEmail = new Map<string, string>();           // email → userId

const oauthClients = new Map<string, OAuthClient>();      // clientId → OAuthClient

const authorizationCodes = new Map<string, AuthorizationCode>();  // code → AuthorizationCode
const refreshTokens = new Map<string, RefreshToken>();    // tokenId → RefreshToken

const consentGrants = new Map<string, ConsentGrant>();    // "userId:clientId" → ConsentGrant

/**
 * User Storage Operations
 * 
 * Manages user accounts with authentication credentials and profile information.
 * Provides lookups by ID, username, and email for different authentication flows.
 */
export const userStore = {
  /**
   * Create a new user account
   * 
   * @param user User data to store
   * @throws Error if username or email already exists
   */
  create(user: User): void {
    // Check for duplicate username
    if (usersByUsername.has(user.username)) {
      throw new Error(`Username '${user.username}' already exists`);
    }
    
    // Check for duplicate email
    if (usersByEmail.has(user.email)) {
      throw new Error(`Email '${user.email}' already exists`);
    }
    
    // Store user with indexes
    users.set(user.id, user);
    usersByUsername.set(user.username, user.id);
    usersByEmail.set(user.email, user.id);
    
    console.log(`👤 Created user: ${user.username} (${user.id})`);
  },
  
  /**
   * Find user by ID
   * 
   * @param userId User identifier
   * @returns User or undefined if not found
   */
  findById(userId: string): User | undefined {
    return users.get(userId);
  },
  
  /**
   * Find user by username (for login)
   * 
   * @param username Username to search for
   * @returns User or undefined if not found
   */
  findByUsername(username: string): User | undefined {
    const userId = usersByUsername.get(username);
    return userId ? users.get(userId) : undefined;
  },
  
  /**
   * Find user by email address
   * 
   * @param email Email to search for  
   * @returns User or undefined if not found
   */
  findByEmail(email: string): User | undefined {
    const userId = usersByEmail.get(email);
    return userId ? users.get(userId) : undefined;
  },
  
  /**
   * Update user information
   * 
   * @param userId User ID to update
   * @param updates Partial user data to update
   * @returns Updated user or undefined if not found
   */
  update(userId: string, updates: Partial<User>): User | undefined {
    const user = users.get(userId);
    if (!user) return undefined;
    
    const updatedUser = { ...user, ...updates };
    users.set(userId, updatedUser);
    
    console.log(`👤 Updated user: ${user.username} (${userId})`);
    return updatedUser;
  },
  
  /**
   * Get all users (for admin/debug purposes)
   * 
   * @returns Array of all users
   */
  getAll(): User[] {
    return Array.from(users.values());
  },
  
  /**
   * Delete user account
   * 
   * @param userId User ID to delete
   * @returns True if deleted, false if not found
   */
  delete(userId: string): boolean {
    const user = users.get(userId);
    if (!user) return false;
    
    users.delete(userId);
    usersByUsername.delete(user.username);
    usersByEmail.delete(user.email);
    
    console.log(`👤 Deleted user: ${user.username} (${userId})`);
    return true;
  }
};

/**
 * OAuth Client Storage Operations
 * 
 * Manages registered OAuth 2.0 clients (applications) that can request tokens.
 * Handles both public clients (SPAs) and confidential clients (server apps).
 */
export const clientStore = {
  /**
   * Register a new OAuth client
   * 
   * @param client OAuth client data
   * @throws Error if client ID already exists
   */
  create(client: OAuthClient): void {
    if (oauthClients.has(client.id)) {
      throw new Error(`Client ID '${client.id}' already exists`);
    }
    
    oauthClients.set(client.id, client);
    console.log(`🔐 Registered OAuth client: ${client.name} (${client.id})`);
  },
  
  /**
   * Find client by ID
   * 
   * @param clientId Client identifier
   * @returns OAuth client or undefined if not found
   */
  findById(clientId: string): OAuthClient | undefined {
    return oauthClients.get(clientId);
  },
  
  /**
   * Validate client credentials (for confidential clients)
   * 
   * @param clientId Client identifier
   * @param clientSecret Client secret
   * @returns True if credentials are valid
   */
  validateCredentials(clientId: string, clientSecret: string): boolean {
    const client = oauthClients.get(clientId);
    if (!client || !client.isActive) return false;
    
    // Public clients don't have secrets
    if (client.type === 'public') {
      return clientSecret === undefined || clientSecret === '';
    }
    
    // Confidential clients must provide correct secret
    return client.secret === clientSecret;
  },
  
  /**
   * Check if redirect URI is registered for client
   * 
   * @param clientId Client identifier
   * @param redirectUri Redirect URI to validate
   * @returns True if redirect URI is valid for this client
   */
  isValidRedirectUri(clientId: string, redirectUri: string): boolean {
    const client = oauthClients.get(clientId);
    return client?.redirectUris.includes(redirectUri) || false;
  },
  
  /**
   * Get all registered clients (for admin purposes)
   * 
   * @returns Array of all OAuth clients
   */
  getAll(): OAuthClient[] {
    return Array.from(oauthClients.values());
  }
};

/**
 * Authorization Code Storage Operations
 * 
 * Manages short-lived authorization codes used in the OAuth 2.0 Authorization Code flow.
 * Codes are single-use and automatically expire after 10 minutes.
 */
export const authCodeStore = {
  /**
   * Store new authorization code
   * 
   * @param authCode Authorization code data
   */
  create(authCode: AuthorizationCode): void {
    authorizationCodes.set(authCode.code, authCode);
    console.log(`🎫 Created authorization code for client: ${authCode.clientId}`);
  },
  
  /**
   * Find authorization code by value
   * 
   * @param code Authorization code string
   * @returns Authorization code or undefined if not found/expired
   */
  findByCode(code: string): AuthorizationCode | undefined {
    const authCode = authorizationCodes.get(code);
    
    // Check expiration
    if (authCode && authCode.expiresAt < new Date()) {
      authorizationCodes.delete(code);
      console.log(`🎫 Authorization code expired: ${code}`);
      return undefined;
    }
    
    return authCode;
  },
  
  /**
   * Mark authorization code as used (single-use only)
   * 
   * @param code Authorization code string
   * @returns True if successfully marked as used
   */
  markAsUsed(code: string): boolean {
    const authCode = authorizationCodes.get(code);
    if (!authCode) return false;
    
    authCode.used = true;
    console.log(`🎫 Authorization code used: ${code}`);
    return true;
  },
  
  /**
   * Delete authorization code
   * 
   * @param code Authorization code string
   * @returns True if deleted, false if not found
   */
  delete(code: string): boolean {
    const deleted = authorizationCodes.delete(code);
    if (deleted) {
      console.log(`🎫 Authorization code deleted: ${code}`);
    }
    return deleted;
  },
  
  /**
   * Clean up expired authorization codes
   * 
   * @returns Number of codes cleaned up
   */
  cleanupExpired(): number {
    const now = new Date();
    let cleanedUp = 0;
    
    for (const [code, authCode] of authorizationCodes) {
      if (authCode.expiresAt < now) {
        authorizationCodes.delete(code);
        cleanedUp++;
      }
    }
    
    if (cleanedUp > 0) {
      console.log(`🧹 Cleaned up ${cleanedUp} expired authorization codes`);
    }
    
    return cleanedUp;
  }
};

/**
 * Refresh Token Storage Operations
 * 
 * Manages long-lived refresh tokens used for obtaining new access tokens
 * without requiring user re-authentication.
 */
export const refreshTokenStore = {
  /**
   * Create new refresh token
   * 
   * @param refreshToken Refresh token data
   */
  create(refreshToken: RefreshToken): void {
    refreshTokens.set(refreshToken.id, refreshToken);
    console.log(`🔄 Created refresh token for user: ${refreshToken.userId}`);
  },
  
  /**
   * Find refresh token by ID
   * 
   * @param tokenId Refresh token identifier
   * @returns Refresh token or undefined if not found/expired/revoked
   */
  findById(tokenId: string): RefreshToken | undefined {
    const token = refreshTokens.get(tokenId);
    
    // Check if expired or revoked
    if (token && (token.expiresAt < new Date() || token.revoked)) {
      if (token.expiresAt < new Date()) {
        refreshTokens.delete(tokenId);
        console.log(`🔄 Refresh token expired: ${tokenId}`);
      }
      return undefined;
    }
    
    return token;
  },
  
  /**
   * Update last used timestamp
   * 
   * @param tokenId Refresh token ID
   * @returns Updated token or undefined if not found
   */
  updateLastUsed(tokenId: string): RefreshToken | undefined {
    const token = refreshTokens.get(tokenId);
    if (!token) return undefined;
    
    token.lastUsedAt = new Date();
    console.log(`🔄 Refresh token used: ${tokenId}`);
    return token;
  },
  
  /**
   * Revoke refresh token
   * 
   * @param tokenId Refresh token ID
   * @returns True if revoked, false if not found
   */
  revoke(tokenId: string): boolean {
    const token = refreshTokens.get(tokenId);
    if (!token) return false;
    
    token.revoked = true;
    console.log(`🔄 Refresh token revoked: ${tokenId}`);
    return true;
  },
  
  /**
   * Revoke all refresh tokens for a user
   * 
   * @param userId User identifier
   * @returns Number of tokens revoked
   */
  revokeAllForUser(userId: string): number {
    let revoked = 0;
    
    for (const token of refreshTokens.values()) {
      if (token.userId === userId && !token.revoked) {
        token.revoked = true;
        revoked++;
      }
    }
    
    if (revoked > 0) {
      console.log(`🔄 Revoked ${revoked} refresh tokens for user: ${userId}`);
    }
    
    return revoked;
  },
  
  /**
   * Clean up expired and revoked refresh tokens
   * 
   * @returns Number of tokens cleaned up
   */
  cleanupExpired(): number {
    const now = new Date();
    let cleanedUp = 0;
    
    for (const [tokenId, token] of refreshTokens) {
      if (token.expiresAt < now || token.revoked) {
        refreshTokens.delete(tokenId);
        cleanedUp++;
      }
    }
    
    if (cleanedUp > 0) {
      console.log(`🧹 Cleaned up ${cleanedUp} expired/revoked refresh tokens`);
    }
    
    return cleanedUp;
  }
};

/**
 * Consent Grant Storage Operations
 * 
 * Manages user consent records for OAuth clients and scopes.
 * Enables "skip consent" for previously authorized applications.
 */
export const consentStore = {
  /**
   * Generate consent key for storage
   * 
   * @param userId User identifier
   * @param clientId Client identifier
   * @returns Consent key for map storage
   */
  getConsentKey(userId: string, clientId: string): string {
    return `${userId}:${clientId}`;
  },
  
  /**
   * Grant consent for client and scopes
   * 
   * @param consent Consent grant data
   */
  grant(consent: ConsentGrant): void {
    const key = this.getConsentKey(consent.userId, consent.clientId);
    consentGrants.set(key, consent);
    console.log(`✅ Consent granted: ${consent.clientId} → ${consent.scope}`);
  },
  
  /**
   * Check if user has consented to scopes for client
   * 
   * @param userId User identifier
   * @param clientId Client identifier
   * @param requestedScopes Space-separated scopes to check
   * @returns True if all requested scopes are consented
   */
  hasConsent(userId: string, clientId: string, requestedScopes: string): boolean {
    const key = this.getConsentKey(userId, clientId);
    const consent = consentGrants.get(key);
    
    if (!consent || consent.revoked) return false;
    
    // Check if consent has expired
    if (consent.expiresAt && consent.expiresAt < new Date()) {
      consentGrants.delete(key);
      console.log(`✅ Consent expired for: ${clientId}`);
      return false;
    }
    
    // Check if all requested scopes are included in consent
    const consentedScopes = new Set(consent.scope.split(' '));
    const requested = requestedScopes.split(' ');
    
    return requested.every(scope => consentedScopes.has(scope));
  },
  
  /**
   * Get existing consent grant
   * 
   * @param userId User identifier  
   * @param clientId Client identifier
   * @returns Consent grant or undefined if not found
   */
  findConsent(userId: string, clientId: string): ConsentGrant | undefined {
    const key = this.getConsentKey(userId, clientId);
    return consentGrants.get(key);
  },
  
  /**
   * Revoke consent for client
   * 
   * @param userId User identifier
   * @param clientId Client identifier
   * @returns True if revoked, false if not found
   */
  revoke(userId: string, clientId: string): boolean {
    const key = this.getConsentKey(userId, clientId);
    const consent = consentGrants.get(key);
    
    if (!consent) return false;
    
    consent.revoked = true;
    console.log(`✅ Consent revoked: ${clientId}`);
    return true;
  },
  
  /**
   * Get all consents for a user
   * 
   * @param userId User identifier
   * @returns Array of consent grants for the user
   */
  getConsentsForUser(userId: string): ConsentGrant[] {
    return Array.from(consentGrants.values())
      .filter(consent => consent.userId === userId && !consent.revoked);
  }
};

/**
 * Storage Statistics
 * 
 * Provides metrics about storage usage for monitoring and debugging.
 */
export const storageStats = {
  /**
   * Get current storage statistics
   * 
   * @returns Storage usage metrics
   */
  getStats() {
    const now = new Date();
    
    // Count active vs expired authorization codes
    let activeAuthCodes = 0;
    let expiredAuthCodes = 0;
    
    for (const authCode of authorizationCodes.values()) {
      if (authCode.expiresAt > now && !authCode.used) {
        activeAuthCodes++;
      } else {
        expiredAuthCodes++;
      }
    }
    
    // Count active vs expired/revoked refresh tokens
    let activeRefreshTokens = 0;
    let expiredRefreshTokens = 0;
    
    for (const token of refreshTokens.values()) {
      if (token.expiresAt > now && !token.revoked) {
        activeRefreshTokens++;
      } else {
        expiredRefreshTokens++;
      }
    }
    
    return {
      users: {
        total: users.size,
        active: Array.from(users.values()).filter(u => u.isActive).length
      },
      clients: {
        total: oauthClients.size,
        active: Array.from(oauthClients.values()).filter(c => c.isActive).length
      },
      authorizationCodes: {
        total: authorizationCodes.size,
        active: activeAuthCodes,
        expired: expiredAuthCodes
      },
      refreshTokens: {
        total: refreshTokens.size,
        active: activeRefreshTokens,
        expired: expiredRefreshTokens
      },
      consents: {
        total: consentGrants.size,
        active: Array.from(consentGrants.values()).filter(c => !c.revoked).length
      }
    };
  },
  
  /**
   * Log current storage statistics
   */
  logStats(): void {
    const stats = this.getStats();
    console.log('📊 Storage Statistics:');
    console.log(`  Users: ${stats.users.active}/${stats.users.total} active`);
    console.log(`  Clients: ${stats.clients.active}/${stats.clients.total} active`);
    console.log(`  Auth Codes: ${stats.authorizationCodes.active}/${stats.authorizationCodes.total} active`);
    console.log(`  Refresh Tokens: ${stats.refreshTokens.active}/${stats.refreshTokens.total} active`);
    console.log(`  Consents: ${stats.consents.active}/${stats.consents.total} active`);
  }
};

/**
 * Automatic Cleanup Tasks
 * 
 * Periodically clean up expired entities to prevent memory leaks.
 * In production, this would be handled by database TTL or scheduled jobs.
 */

// Clean up expired authorization codes every 5 minutes
const authCodeCleanupInterval = setInterval(() => {
  authCodeStore.cleanupExpired();
}, 5 * 60 * 1000);

// Clean up expired refresh tokens every hour
const refreshTokenCleanupInterval = setInterval(() => {
  refreshTokenStore.cleanupExpired();
}, 60 * 60 * 1000);

// Log storage stats every 30 minutes (in debug mode)
const statsLogInterval = setInterval(() => {
  if (process.env.NODE_ENV === 'development') {
    storageStats.logStats();
  }
}, 30 * 60 * 1000);

/**
 * Cleanup function for graceful shutdown
 * 
 * Clears all intervals to prevent memory leaks during testing or shutdown.
 */
export function cleanupStorage(): void {
  clearInterval(authCodeCleanupInterval);
  clearInterval(refreshTokenCleanupInterval);
  clearInterval(statsLogInterval);
  
  console.log('🧹 Storage cleanup intervals cleared');
}

/**
 * Reset all storage (for testing purposes)
 * 
 * WARNING: This will delete ALL data in memory storage.
 * Only use for testing or development reset.
 */
export function resetAllStorage(): void {
  users.clear();
  usersByUsername.clear();
  usersByEmail.clear();
  oauthClients.clear();
  authorizationCodes.clear();
  refreshTokens.clear();
  consentGrants.clear();
  
  console.log('🗑️  All storage cleared');
}