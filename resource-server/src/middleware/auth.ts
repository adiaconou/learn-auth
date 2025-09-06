/**
 * JWT Authentication Middleware
 * 
 * Express middleware for OAuth 2.0 Bearer token authentication. Validates JWT access tokens
 * on protected API endpoints and attaches authenticated user context to request object.
 * 
 * Sequence Diagram (Authentication Flow):
 * 
 *                           ┌─── Resource Server ───────────────────────────────────┐
 *   Client                  │ Express App   AuthMiddleware  JwtValidationService    │  JWKS Client    IdP JWKS
 *     │                     │      │             │                │                 │       │              │
 *     │─── POST ───────────→│      │             │                │                 │       │              │
 *     │ Bearer <jwt>        │      │             │                │                 │       │              │
 *     │                     │      │             │                │                 │       │              │
 *     │                     │      │─ request ──→│                │                 │       │              │
 *     │                     │      │             │ extractToken() │                 │       │              │
 *     │                     │      │             │ ┌────────────┐ │                 │       │              │
 *     │                     │      │             │ │parse header│ │                 │       │              │
 *     │                     │      │             │ │"Bearer xyz"│ │                 │       │              │
 *     │                     │      │             │ └────────────┘ │                 │       │              │
 *     │                     │      │             │                │                 │       │              │
 *     │                     │      │             │ verifyToken()  │                 │       │              │
 *     │                     │      │             │───────────────→│                 │       │              │
 *     │                     │      │             │                │ getSigningKey() │       │              │
 *     │                     │      │             │                │────────────────→│───────│──────────────→│
 *     │                     │      │             │                │                 │   GET │/.well-known/ │
 *     │                     │      │             │                │                 │       │  jwks.json   │
 *     │                     │      │             │                │                 │←──────│──────────────│
 *     │                     │      │             │                │←─ public key ───│  JSON │   (cached)   │
 *     │                     │      │             │                │ jwt.verify()    │       │              │
 *     │                     │      │             │←── DecodedToken │                 │       │              │
 *     │                     │      │             │                │                 │       │              │
 *     │                     │      │             │ attachUserCtx()│                 │       │              │
 *     │                     │      │             │ ┌────────────┐ │                 │       │              │
 *     │                     │      │             │ │req.user = {│ │                 │       │              │
 *     │                     │      │             │ │ sub, scope │ │                 │       │              │
 *     │                     │      │             │ │}           │ │                 │       │              │
 *     │                     │      │             │ └────────────┘ │                 │       │              │
 *     │                     │      │             │                │                 │       │              │
 *     │                     │      │←─ next() ───│                │                 │       │              │
 *     │                     │      │             │                │                 │       │              │
 *     │                     │      │─ continue ─→│   [Scope Middleware & Route Handler]    │              │
 *     │                     │      │             │                │                 │       │              │
 *     │←─── 200 ───────────│      │             │                │                 │       │              │
 *     │ {response}          │      │             │                │                 │       │              │
 *                           └────────────────────────────────────────────────────────┐       │              │
 * 
 * Flow:
 * 1. Extract Bearer token from Authorization header
 * 2. Validate token using JWT validation service
 * 3. Attach user context (sub, scope) to Express request
 * 4. Continue to next middleware or return 401 error
 * 
 * Usage:
 *   app.use('/api', authMiddleware);
 *   // or
 *   router.get('/notes', authMiddleware, notesController);
 */

import { Request, Response, NextFunction } from 'express';
import jwtValidationService, { DecodedToken } from '../services/jwt';

/**
 * Extended Express Request interface with authenticated user context.
 * Available after successful JWT validation in protected routes.
 */
export interface AuthenticatedRequest extends Request {
  user: {
    sub: string;       // User ID from JWT 'sub' claim (e.g., "user123")
    scope: string;     // OAuth 2.0 scopes from JWT (e.g., "notes:read notes:write")
    iss: string;       // Token issuer for audit logging
    aud: string;       // Token audience for validation
  };
}

/**
 * OAuth 2.0 error response format (RFC 6750)
 */
interface OAuth2ErrorResponse {
  error: string;
  error_description: string;
}

/**
 * JWT Authentication Middleware for Express
 * 
 * Validates Bearer tokens and attaches user context to request.
 * Returns 401 Unauthorized for invalid/missing tokens.
 * 
 * @param req - Express request object
 * @param res - Express response object  
 * @param next - Express next function
 */
export async function authMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<Response | void> {
  try {
    // Step 1: Extract Bearer token from Authorization header
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
      return res.status(401).json({
        error: 'invalid_request',
        error_description: 'Authorization header is required'
      });
    }

    // Authorization header format: "Bearer <token>"
    const parts = authHeader.split(' ');
    
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      return res.status(401).json({
        error: 'invalid_request', 
        error_description: 'Authorization header must be "Bearer <token>"'
      });
    }

    const token = parts[1];
    
    if (!token) {
      return res.status(401).json({
        error: 'invalid_token',
        error_description: 'Access token is missing'
      });
    }

    // Step 2: Validate JWT token using validation service
    let decodedToken: DecodedToken;
    
    try {
      decodedToken = await jwtValidationService.verifyToken(token);
    } catch (error) {
      // Convert JWT validation errors to OAuth 2.0 error format
      return res.status(401).json({
        error: 'invalid_token',
        error_description: error instanceof Error ? error.message : 'Invalid access token'
      });
    }

    // Step 3: Attach authenticated user context to request
    // 
    // Purpose: Make user identity and permissions available throughout the request lifecycle.
    // This enables:
    // 
    // 1. DATA ISOLATION: Route handlers can filter data by user ID
    //    Example: GET /notes only returns notes where note.userId === req.user.sub
    // 
    // 2. AUTHORIZATION: Scope middleware can check permissions against req.user.scope
    //    Example: POST /notes requires "notes:write" scope in req.user.scope
    // 
    // 3. AUDIT LOGGING: Controllers can log actions with user context
    //    Example: "User user123 created note abc456" using req.user.sub
    // 
    // 4. PERSONALIZATION: APIs can customize responses per user
    //    Example: Include user preferences in API responses
    // 
    // Without this context, downstream middleware and routes would need to re-validate
    // the JWT token on every request, which is inefficient and violates DRY principle.
    //
    (req as AuthenticatedRequest).user = {
      sub: decodedToken.sub,           // User identifier for data isolation
      scope: decodedToken.scope,       // OAuth 2.0 permissions for authorization
      iss: decodedToken.iss,           // Token issuer (for audit logs)
      aud: decodedToken.aud            // Token audience (validation)
    };

    // Step 4: Continue to next middleware (scope validation, route handler, etc.)
    next();
    
  } catch (error) {
    // Handle unexpected errors (network issues, service unavailable, etc.)
    console.error('Authentication middleware error:', error);
    
    res.status(401).json({
      error: 'invalid_token',
      error_description: 'Token validation failed'
    });
  }
}

export default authMiddleware;