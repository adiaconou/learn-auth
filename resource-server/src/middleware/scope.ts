/**
 * OAuth 2.0 Scope Authorization Middleware
 * 
 * Express middleware for scope-based authorization. Validates that authenticated users
 * have the required OAuth 2.0 scopes to access protected API endpoints.
 * 
 * Scope-Based Authorization Flow:
 * 
 *                        ┌─── Resource Server ──────────────────────────────┐
 *   Client               │ Express App  AuthMiddleware  ScopeMiddleware      │
 *     │                  │      │            │               │              │
 *     │─── POST ────────→│      │            │               │              │
 *     │ Bearer <jwt>     │      │            │               │              │
 *     │ (scope: "notes:  │      │            │               │              │
 *     │  read notes:     │      │            │               │              │
 *     │  write")         │      │            │               │              │
 *     │                  │      │            │               │              │
 *     │                  │      │─ request ─→│               │              │
 *     │                  │      │            │ verifyToken() │              │
 *     │                  │      │            │ ┌───────────┐ │              │
 *     │                  │      │            │ │ attach    │ │              │
 *     │                  │      │            │ │ req.user  │ │              │
 *     │                  │      │            │ │ {scope:   │ │              │
 *     │                  │      │            │ │ "notes:   │ │              │
 *     │                  │      │            │ │ read..."}  │ │              │
 *     │                  │      │            │ └───────────┘ │              │
 *     │                  │      │            │               │              │
 *     │                  │      │←─ next() ──│               │              │
 *     │                  │      │            │               │              │
 *     │                  │      │─ request ─────────────────→│              │
 *     │                  │      │            │   checkScope()│              │
 *     │                  │      │            │               │ ┌──────────┐ │
 *     │                  │      │            │               │ │ route:   │ │
 *     │                  │      │            │               │ │ POST     │ │
 *     │                  │      │            │               │ │ /notes   │ │
 *     │                  │      │            │               │ │ requires │ │
 *     │                  │      │            │               │ │"notes:   │ │
 *     │                  │      │            │               │ │ write"   │ │
 *     │                  │      │            │               │ └──────────┘ │
 *     │                  │      │            │               │              │
 *     │                  │      │            │               │ ┌──────────┐ │
 *     │                  │      │            │               │ │ user has │ │
 *     │                  │      │            │               │ │"notes:   │ │
 *     │                  │      │            │               │ │ write"?  │ │
 *     │                  │      │            │               │ │ ✓ YES    │ │
 *     │                  │      │            │               │ └──────────┘ │
 *     │                  │      │            │               │              │
 *     │                  │      │←─ next() ─────────────────│              │
 *     │                  │      │            │               │              │
 *     │                  │      │─ continue ────────────────────────────────→│
 *     │                  │      │            │               │   [Route    │
 *     │                  │      │            │               │   Handler]  │
 *     │                  │      │            │               │              │
 *     │←─── 201 ────────│      │            │               │              │
 *     │ {created note}   │      │            │               │              │
 *                        └──────────────────────────────────────────────────┘
 * 
 * Flow:
 * 1. Receive request with authenticated user context (from auth middleware)
 * 2. Determine required scope(s) for the current route and HTTP method
 * 3. Check if user's token scopes include ALL required scopes
 * 4. Continue to route handler if authorized, or return 403 error if insufficient scope
 * 
 * OAuth 2.0 Scopes in this API:
 * - `notes:read` - Allows reading notes (GET /notes, GET /notes/:id)
 * - `notes:write` - Allows creating/updating/deleting notes (POST/PUT/DELETE /notes)
 * 
 * Example Token Scopes:
 * - "notes:read" - Can only view notes
 * - "notes:write" - Can only create/modify notes (but not read - unusual but valid)
 * - "notes:read notes:write" - Full access to notes API
 * - "" (empty) - No access to any notes endpoints
 * 
 * Usage:
 *   // Apply to all routes that need notes:read
 *   router.get('/notes', authMiddleware, requireScope(['notes:read']), notesController.getAll);
 *   
 *   // Apply to routes that need notes:write
 *   router.post('/notes', authMiddleware, requireScope(['notes:write']), notesController.create);
 *   
 *   // Multiple scopes (user must have ALL listed scopes)
 *   router.get('/admin/notes', authMiddleware, requireScope(['notes:read', 'admin:access']), adminController);
 */

import { Request, Response, NextFunction } from 'express';
import { AuthenticatedRequest } from './auth';

/**
 * OAuth 2.0 error response for insufficient scope (RFC 6750)
 */
interface OAuth2ScopeErrorResponse {
  error: string;
  error_description: string;
  scope?: string; // Optional: indicate which scopes are required
}

/**
 * Creates Express middleware that validates user has required OAuth 2.0 scopes.
 * 
 * This middleware must be used AFTER the authentication middleware, as it depends
 * on the user context being attached to the request object.
 * 
 * Authorization Logic:
 * 1. Extract user's scopes from JWT token (space-separated string)
 * 2. Check if user has ALL required scopes for this endpoint
 * 3. Allow request if authorized, return 403 if insufficient scope
 * 
 * Why Check ALL Scopes:
 * Some endpoints might require multiple permissions. For example:
 * - Reading sensitive admin notes: ['notes:read', 'admin:access']
 * - Bulk operations: ['notes:write', 'bulk:operations']
 * 
 * The user must have every single scope in the required list.
 * 
 * @param requiredScopes - Array of scope strings that user must possess
 * @returns Express middleware function
 * 
 * @example
 * ```typescript
 * // Single scope requirement
 * router.get('/notes', authMiddleware, requireScope(['notes:read']), handler);
 * 
 * // Multiple scope requirement (user needs BOTH scopes)
 * router.delete('/admin/notes', authMiddleware, requireScope(['notes:write', 'admin:access']), handler);
 * ```
 */
export function requireScope(requiredScopes: string[]) {
  return (
    req: Request,
    res: Response,
    next: NextFunction
  ): Response | void => {
    try {
      // Cast to AuthenticatedRequest to access user property
      const authReq = req as AuthenticatedRequest;
      
      // Step 1: Validate that request has been authenticated
      // 
      // This middleware depends on the auth middleware running first to:
      // 1. Validate the JWT token signature and claims
      // 2. Attach user context (including scopes) to req.user
      // 
      // Without authentication, we can't perform authorization.
      if (!authReq.user || authReq.user.scope === undefined) {
        return res.status(401).json({
          error: 'invalid_token',
          error_description: 'Authentication required before scope validation'
        });
      }

      // Step 2: Parse user's scopes from JWT token
      // 
      // OAuth 2.0 scopes are stored as a space-separated string in the JWT 'scope' claim.
      // Example: "notes:read notes:write profile:read"
      // 
      // We split this into an array for easier comparison with required scopes.
      const userScopes = authReq.user.scope.split(' ').filter(scope => scope.length > 0);
      
      // Step 3: Check if user has ALL required scopes
      // 
      // Authorization Logic: User must possess EVERY scope in requiredScopes array.
      // 
      // Examples:
      // - Required: ['notes:read'] & User has: ['notes:read', 'notes:write'] ✓ PASS
      // - Required: ['notes:write'] & User has: ['notes:read'] ✗ FAIL  
      // - Required: ['notes:read', 'admin:access'] & User has: ['notes:read'] ✗ FAIL (missing admin:access)
      // - Required: [] & User has: any scopes ✓ PASS (no requirements)
      const hasAllRequiredScopes = requiredScopes.every(requiredScope => 
        userScopes.includes(requiredScope)
      );

      if (!hasAllRequiredScopes) {
        // Step 4: Return 403 Forbidden with OAuth 2.0 error format
        // 
        // HTTP 403 vs 401 in OAuth 2.0:
        // - 401 Unauthorized = "Who are you?" (authentication problem - invalid/missing token)
        // - 403 Forbidden = "I know who you are, but you can't do this" (authorization problem - insufficient scope)
        // 
        // We include the missing scopes in the error to help clients understand
        // what permissions they need to request in their next authorization.
        const missingScopes = requiredScopes.filter(required => 
          !userScopes.includes(required)
        );

        return res.status(403).json({
          error: 'insufficient_scope',
          error_description: `Access denied. Required scope(s): ${requiredScopes.join(', ')}. Missing: ${missingScopes.join(', ')}`,
          scope: requiredScopes.join(' ') // OAuth 2.0 standard: space-separated scopes
        });
      }

      // Step 5: Authorization successful - continue to route handler
      // 
      // At this point:
      // 1. User is authenticated (valid JWT token)
      // 2. User is authorized (has all required scopes)
      // 3. Request can proceed to the actual API endpoint logic
      // 
      // The route handler can now safely:
      // - Access req.user.sub for user identification
      // - Perform business logic knowing user has permission
      // - Apply additional fine-grained authorization if needed
      next();

    } catch (error) {
      // Handle unexpected errors during scope validation
      console.error('Scope validation middleware error:', error);
      
      return res.status(403).json({
        error: 'insufficient_scope',
        error_description: 'Scope validation failed'
      });
    }
  };
}

/**
 * Convenience middleware factory for common scope requirements.
 * Provides pre-configured middleware for typical OAuth 2.0 scope patterns.
 */
export const scopeMiddleware = {
  /**
   * Requires 'notes:read' scope for viewing notes
   */
  readNotes: requireScope(['notes:read']),
  
  /**
   * Requires 'notes:write' scope for creating/modifying notes
   */
  writeNotes: requireScope(['notes:write']),
  
  /**
   * Requires both 'notes:read' and 'notes:write' for full access
   */
  fullNotesAccess: requireScope(['notes:read', 'notes:write'])
};

export default requireScope;