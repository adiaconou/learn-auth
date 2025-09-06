/**
 * OAuth 2.0 Resource Server Main Application
 * 
 * Express.js server that protects /notes API endpoints using JWT Bearer token authentication
 * and OAuth 2.0 scope-based authorization. Serves as a learning implementation of RFC 6749
 * (OAuth 2.0) and RFC 6750 (Bearer Token Usage) standards.
 * 
 * Architecture Overview:
 * 
 *                              ┌── Resource Server (this file) ──────────────────────────────┐
 *                              │                                                              │
 *   HTTP Client               │  Express App                                                 │
 *       │                     │       │                                                      │
 *       │─── GET /notes ─────→│       │                                                      │
 *       │ Authorization:      │       │                                                      │  
 *       │ Bearer <jwt>        │       │                                                      │
 *       │                     │       │                                                      │
 *       │                     │       ▼                                                      │
 *       │                     │  ┌─────────┐    ┌──────────────┐    ┌─────────────────┐    │
 *       │                     │  │  CORS   │───→│ Auth         │───→│ Scope           │    │
 *       │                     │  │         │    │ Middleware   │    │ Middleware      │    │
 *       │                     │  │ • Allow │    │              │    │                 │    │
 *       │                     │  │   Origins│    │ • Extract    │    │ • Check         │    │
 *       │                     │  │ • Handle│    │   JWT Token  │    │   Required      │    │
 *       │                     │  │   Preflight  │ • Validate   │    │   Scopes        │    │
 *       │                     │  │              │   Signature  │    │ • notes:read    │    │
 *       │                     │  │              │ • Verify     │    │ • notes:write   │    │
 *       │                     │  │              │   Claims     │    │                 │    │
 *       │                     │  │              │ • Attach     │    │                 │    │
 *       │                     │  │              │   req.user   │    │                 │    │
 *       │                     │  └─────────────┘    └──────────────┘    └─────────────────┘    │
 *       │                     │       │                    │                      │          │
 *       │                     │       │              401 Unauthorized       403 Forbidden  │
 *       │                     │       │              Invalid Token         Insufficient    │
 *       │                     │       │                                    Scope           │
 *       │                     │       │                                                      │
 *       │                     │       ▼                                                      │
 *       │                     │  ┌─────────────────┐                                        │
 *       │                     │  │ Route Handlers  │                                        │
 *       │                     │  │                 │                                        │
 *       │                     │  │ • /notes        │                                        │
 *       │                     │  │ • /notes/:id    │                                        │
 *       │                     │  │ • Business      │                                        │
 *       │                     │  │   Logic         │                                        │
 *       │                     │  │ • Data Access   │                                        │
 *       │                     │  │ • Response      │                                        │
 *       │                     │  │   Formatting    │                                        │
 *       │                     │  └─────────────────┘                                        │
 *       │                     │       │                                                      │
 *       │←─── 200 OK ─────────│       │                                                      │
 *       │ Content-Type:       │       ▼                                                      │
 *       │ application/json    │  ┌─────────────────┐                                        │
 *       │ {                   │  │ Error Handler   │                                        │
 *       │   "data": [notes]   │  │                 │                                        │
 *       │ }                   │  │ • 404 Not Found │                                        │
 *       │                     │  │ • 500 Internal  │                                        │
 *       │                     │  │   Server Error  │                                        │
 *       │                     │  └─────────────────┘                                        │
 *                              └──────────────────────────────────────────────────────────┘
 * 
 * Key Features:
 * 
 * 1. **Cross-Origin Resource Sharing (CORS)**
 *    - Allows frontend apps from different origins to access the API
 *    - Handles preflight OPTIONS requests for complex requests
 *    - Configures allowed headers for Authorization Bearer tokens
 * 
 * 2. **JWT Bearer Token Authentication** 
 *    - Validates JWT signature using JWKS (JSON Web Key Set) from Identity Provider
 *    - Verifies token claims: issuer (iss), audience (aud), expiration (exp)
 *    - Attaches authenticated user context (sub, scope) to request object
 * 
 * 3. **OAuth 2.0 Scope-Based Authorization**
 *    - Enforces fine-grained permissions using scope strings
 *    - `notes:read` scope required for GET operations  
 *    - `notes:write` scope required for POST/PUT/DELETE operations
 *    - Returns proper 401/403 status codes based on error type
 * 
 * 4. **RESTful API Design**
 *    - Consistent URL patterns (/notes, /notes/:id)
 *    - HTTP methods match operations (GET=read, POST=create, PUT=update, DELETE=delete)
 *    - JSON request/response bodies with proper Content-Type headers
 *    - Standard HTTP status codes (200, 201, 400, 401, 403, 404, 500)
 * 
 * 5. **Error Handling**
 *    - Global error handler for unhandled exceptions  
 *    - Structured error responses with error codes and descriptions
 *    - Proper logging for debugging and monitoring
 * 
 * OAuth 2.0 Security Considerations:
 * 
 * - **Bearer Token Security**: Tokens must be transmitted over HTTPS in production
 * - **Token Validation**: Every request validates token signature and claims
 * - **Scope Enforcement**: Principle of least privilege - users only get access they need
 * - **User Isolation**: Each user can only access their own notes (enforced by `sub` claim)
 * - **Token Expiration**: Short-lived access tokens reduce impact of token theft
 * 
 * Production Differences:
 * 
 * This is a learning implementation. Production systems would typically include:
 * - Database persistence (PostgreSQL, MongoDB) instead of in-memory storage
 * - Redis for session/token caching and rate limiting
 * - Structured logging (Winston, Bunyan) with correlation IDs
 * - Health check endpoints with dependency checks
 * - Metrics and monitoring (Prometheus, DataDog)
 * - API documentation (OpenAPI/Swagger)
 * - Input validation middleware (Joi, express-validator)
 * - Security headers (Helmet.js)
 * - Rate limiting and DDoS protection
 * - Load balancing and horizontal scaling
 */

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import config from './config/index';
import { authMiddleware } from './middleware/auth';
import notesRouter from './routes/notes';

/**
 * Create and configure Express application with middleware stack.
 * 
 * Middleware execution order is critical for security:
 * 1. CORS - Handle cross-origin requests first
 * 2. JSON parsing - Parse request bodies  
 * 3. Health endpoint - Allow unauthenticated health checks
 * 4. Auth middleware - Validate JWT tokens for protected routes
 * 5. Route handlers - Business logic with scope validation
 * 6. Error handler - Catch and format any unhandled errors
 */
const app = express();

/**
 * CORS (Cross-Origin Resource Sharing) Configuration
 * 
 * Enables frontend applications running on different domains/ports to access this API.
 * Essential for Single Page Applications (SPAs) that need to make API requests.
 * 
 * Security Notes:
 * - In production, specify exact origins instead of wildcards
 * - credentials: true allows cookies/auth headers in cross-origin requests
 * - Preflight requests (OPTIONS) are handled automatically
 */
app.use(cors({
  origin: config.resourceServer.corsOrigin,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['Content-Type']
}));

/**
 * JSON Body Parser Middleware
 * 
 * Parses incoming JSON request bodies and makes them available as req.body.
 * Includes size limit to prevent DoS attacks via large payloads.
 * 
 * Example: POST /notes with body {"title": "My Note", "content": "Note text"}
 * Results in: req.body = {title: "My Note", content: "Note text"}
 */
app.use(express.json({ limit: '10mb' }));

/**
 * Health Check Endpoint (Unauthenticated)
 * 
 * Provides a simple health status for load balancers, monitoring systems, and deployment tools.
 * Placed before auth middleware to allow unauthenticated access.
 * 
 * Returns:
 * - 200 OK: Service is healthy
 * - 500 Internal Server Error: Service dependencies are failing (in production)
 * 
 * Production Enhancements:
 * - Check database connectivity
 * - Verify external service dependencies (JWKS endpoint)
 * - Include response time metrics
 * - Return detailed status for different components
 */
app.get('/health', (req: Request, res: Response) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: 'notes-resource-server',
    version: process.env.npm_package_version || '1.0.0'
  });
});

/**
 * Apply Authentication Middleware to Protected Routes
 * 
 * All routes defined after this middleware will require valid JWT Bearer tokens.
 * The auth middleware:
 * 1. Extracts Bearer token from Authorization header
 * 2. Validates JWT signature using JWKS from Identity Provider
 * 3. Verifies token claims (issuer, audience, expiration)
 * 4. Attaches user context (req.user) for downstream middleware/routes
 * 
 * Routes that should NOT require authentication should be defined BEFORE this line.
 */
app.use(authMiddleware);

/**
 * Notes API Routes (Protected)
 * 
 * Mount the notes router at /notes path. All endpoints in this router will:
 * 1. Require valid JWT authentication (from auth middleware above)
 * 2. Enforce scope-based authorization (notes:read, notes:write)
 * 3. Provide CRUD operations for user's notes with proper isolation
 * 
 * Endpoints:
 * - GET /notes - List user's notes (requires notes:read scope)
 * - POST /notes - Create new note (requires notes:write scope)
 * - GET /notes/:id - Get specific note (requires notes:read scope)
 * - PUT /notes/:id - Update note (requires notes:write scope)  
 * - DELETE /notes/:id - Delete note (requires notes:write scope)
 */
app.use('/notes', notesRouter);

/**
 * 404 Not Found Handler
 * 
 * Catches requests to undefined endpoints and returns consistent error format.
 * Must be placed after all route definitions but before error handler.
 * 
 * Security Note: Avoid exposing internal application structure in error messages.
 */
app.use('*', (req: Request, res: Response) => {
  res.status(404).json({
    error: 'not_found',
    error_description: `The requested endpoint ${req.method} ${req.originalUrl} was not found`
  });
});

/**
 * Global Error Handler Middleware
 * 
 * Express error handling middleware that catches any unhandled errors from route handlers
 * or other middleware. Must be defined last and have 4 parameters for Express to recognize it.
 * 
 * Error Types Handled:
 * - Synchronous errors: thrown exceptions from route handlers
 * - Asynchronous errors: Promise rejections passed to next(error)
 * - Middleware errors: JWT validation failures, scope check failures
 * - System errors: Out of memory, file system errors, network issues
 * 
 * Security Considerations:
 * - Never expose internal error details (stack traces, file paths) to clients
 * - Log detailed error information for debugging while returning generic client messages
 * - Prevent information leakage that could help attackers understand system internals
 * 
 * Production Enhancements:
 * - Structured logging with correlation IDs for request tracing
 * - Error metrics and alerting for monitoring system health  
 * - Different error detail levels based on environment (dev vs prod)
 * - Integration with error tracking services (Sentry, Rollbar)
 */
app.use((error: any, req: Request, res: Response, next: NextFunction) => {
  // Log error details for debugging (server-side only)
  console.error('Unhandled error in Express application:', {
    message: error.message,
    stack: error.stack,
    url: req.originalUrl,
    method: req.method,
    timestamp: new Date().toISOString(),
    // Don't log sensitive data like Authorization headers
    headers: {
      'content-type': req.headers['content-type'],
      'user-agent': req.headers['user-agent']
    }
  });

  // Return generic error response to client (security best practice)
  if (res.headersSent) {
    // If response already started, delegate to default Express error handler
    return next(error);
  }

  res.status(500).json({
    error: 'internal_server_error',
    error_description: 'An unexpected error occurred while processing the request'
  });
});

/**
 * Start Express Server
 * 
 * Binds the Express application to specified port and begins listening for HTTP requests.
 * Includes proper error handling for common startup issues.
 * 
 * Common Startup Errors:
 * - EADDRINUSE: Port already in use by another process
 * - EACCES: Insufficient permissions to bind to port (typically ports < 1024)
 * - ENOTFOUND: Invalid hostname specified in configuration
 * 
 * Production Considerations:
 * - Use process managers (PM2, Docker) for automatic restarts
 * - Implement graceful shutdown handling for SIGTERM/SIGINT signals  
 * - Add startup health checks before accepting traffic
 * - Configure proper logging for server lifecycle events
 */
const server = app.listen(config.resourceServer.port, () => {
  console.log('🚀 OAuth 2.0 Resource Server started successfully!');
  console.log(`📍 Server URL: http://localhost:${config.resourceServer.port}`);
  console.log(`🔐 Protected endpoints: /notes (requires JWT Bearer token)`);
  console.log(`❤️  Health check: http://localhost:${config.resourceServer.port}/health`);
  console.log(`🌐 CORS origin: ${config.resourceServer.corsOrigin}`);
  console.log(`🔑 Expected token issuer: ${config.identityProvider.issuer}`);
  console.log(`📋 Expected token audience: ${config.resourceServer.audience}`);
  console.log('');
  console.log('💡 Ready to accept requests with valid JWT Bearer tokens!');
  console.log('   Example: Authorization: Bearer <your-jwt-token>');
});

/**
 * Graceful Shutdown Handler
 * 
 * Handles process termination signals (SIGTERM, SIGINT) to allow for clean server shutdown.
 * Important for production deployments where containers/processes are stopped gracefully.
 * 
 * Shutdown sequence:
 * 1. Stop accepting new connections
 * 2. Wait for existing requests to complete (with timeout)
 * 3. Close database connections and cleanup resources
 * 4. Exit process with appropriate status code
 * 
 * This prevents:
 * - Data corruption from incomplete transactions  
 * - Client errors from dropped connections
 * - Resource leaks from unclosed connections
 */
const gracefulShutdown = (signal: string) => {
  console.log(`\n🛑 Received ${signal} signal. Starting graceful shutdown...`);
  
  server.close((error) => {
    if (error) {
      console.error('❌ Error during server shutdown:', error);
      process.exit(1);
    }
    
    console.log('✅ HTTP server closed.');
    console.log('👋 OAuth 2.0 Resource Server shutdown complete.');
    process.exit(0);
  });

  // Force exit if graceful shutdown takes too long
  setTimeout(() => {
    console.error('⚠️  Forceful shutdown due to timeout');
    process.exit(1);
  }, 10000); // 10 second timeout
};

// Register shutdown signal handlers
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions and unhandled promise rejections
process.on('uncaughtException', (error) => {
  console.error('💥 Uncaught Exception:', error);
  gracefulShutdown('UNCAUGHT_EXCEPTION');
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('💥 Unhandled Promise Rejection at:', promise, 'reason:', reason);
  gracefulShutdown('UNHANDLED_REJECTION');
});

export default app;