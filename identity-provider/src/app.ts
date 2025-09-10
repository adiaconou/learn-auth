/**
 * Identity Provider Main Application
 * 
 * OAuth 2.0 Authorization Server + OIDC Identity Provider implementation.
 * 
 * This Express application provides:
 * - OIDC Discovery endpoints (.well-known/openid-configuration, JWKS)
 * - OAuth 2.0 Authorization Code + PKCE flow endpoints (/authorize, /token)
 * - User authentication and session management (/login, /logout)
 * - UserInfo endpoint for OIDC claims (/userinfo)
 * - Administrative endpoints for client management
 * 
 * Security features:
 * - Session-based authentication with secure cookies
 * - CORS protection for frontend integration
 * - CSRF protection for form submissions
 * - Security headers via Helmet
 * - PKCE validation for public clients
 * - JWT token signing and validation
 */

import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import helmet from 'helmet';
import path from 'path';
import { config, validateConfig, logConfigSummary } from './config';

// Import route handlers
import discoveryRoutes from './routes/discovery';
import loginRoutes from './routes/login';
import authorizeRoutes from './routes/authorize';
import registerRoutes from './routes/register';

const app = express();

/**
 * Application startup and configuration
 */
async function startServer(): Promise<void> {
  console.log('🚀 Starting Identity Provider...');
  
  // Step 1: Validate configuration
  const configValidation = validateConfig();
  if (!configValidation.isValid) {
    console.error('❌ Configuration validation failed:');
    configValidation.errors.forEach(error => console.error(`   • ${error}`));
    process.exit(1);
  }
  
  console.log('✅ Configuration validated successfully');
  logConfigSummary();

  // Step 2: Security middleware setup
  console.log('🔒 Setting up security middleware...');
  
  // Helmet for security headers
  app.use(helmet({
    // Allow inline styles for development (production should use CSP)
    contentSecurityPolicy: config.environment === 'development' ? false : undefined,
    // Enable cross-origin requests for JWKS and discovery endpoints
    crossOriginResourcePolicy: { policy: 'cross-origin' }
  }));

  // CORS configuration for frontend integration
  app.use(cors({
    origin: config.security.allowedOrigins,
    credentials: true, // Allow cookies for session management
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
  }));

  console.log(`✅ CORS configured for origins: ${config.security.allowedOrigins.join(', ')}`);

  // Step 3: Request parsing middleware
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));
  app.use(cookieParser());

  // Step 4: Session management
  console.log('📝 Configuring session management...');
  
  app.use(session({
    name: 'idp_session', // Custom session name
    secret: config.security.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: config.security.requireHttps, // HTTPS only in production
      httpOnly: true, // Prevent XSS attacks
      maxAge: config.security.sessionMaxAge,
      sameSite: 'lax' // CSRF protection while allowing OAuth redirects
    },
    rolling: true // Extend session on activity
  }));

  console.log('✅ Session middleware configured');
  console.log(`   • Secure cookies: ${config.security.requireHttps}`);
  console.log(`   • Max age: ${config.security.sessionMaxAge}ms`);

  // Step 5: View engine setup for login/consent pages
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views'));

  // Step 6: Request logging middleware (development only)
  if (config.environment === 'development') {
    app.use((req, res, next) => {
      const timestamp = new Date().toISOString();
      console.log(`📥 ${timestamp} ${req.method} ${req.path}`);
      if (Object.keys(req.query).length > 0) {
        console.log(`   Query: ${JSON.stringify(req.query)}`);
      }
      next();
    });
  }

  // Step 7: Mount route handlers
  console.log('🛣️  Mounting route handlers...');

  // OIDC Discovery and JWKS endpoints (no authentication required)
  app.use('/.well-known', discoveryRoutes);
  console.log('   • /.well-known/* - OIDC Discovery & JWKS');

  // Authentication endpoints
  app.use('/', loginRoutes);
  console.log('   • /login, /logout - User authentication');
  
  // User registration endpoint
  app.use('/register', registerRoutes);
  console.log('   • /register - User registration');

  // OAuth 2.0 endpoints
  app.use('/authorize', authorizeRoutes);
  console.log('   • /authorize - OAuth 2.0 Authorization Code Flow');
  // app.use('/token', tokenRoutes);          // Step 16
  // app.use('/userinfo', userinfoRoutes);    // Step 17
  // app.use('/consent', consentRoutes);      // Step 14

  // Administrative endpoints (development only)
  if (config.environment === 'development') {
    // app.use('/admin', adminRoutes);        // Step 20
    console.log('   • /admin/* - Client management (development only)');
  }

  // Step 8: Health check endpoint
  app.get('/health', (req, res) => {
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      environment: config.environment,
      version: '1.0.0',
      issuer: config.server.issuer
    });
  });

  console.log('   • /health - Health check');

  // Step 9: Static file serving for assets (CSS, images, etc.)
  app.use('/static', express.static(path.join(__dirname, '../static')));

  // Step 10: 404 handler for undefined routes
  app.use((req, res) => {
    console.log(`❌ 404 - Route not found: ${req.method} ${req.path}`);
    res.status(404).json({
      error: 'not_found',
      error_description: `The requested endpoint ${req.path} was not found`
    });
  });

  // Step 11: Global error handler
  app.use((error: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    console.error('❌ Unhandled error:', error);
    
    // Don't expose internal errors in production
    const isDevelopment = config.environment === 'development';
    
    res.status(error.status || 500).json({
      error: 'server_error',
      error_description: isDevelopment ? error.message : 'An internal server error occurred',
      ...(isDevelopment && { stack: error.stack })
    });
  });

  // Step 12: Start HTTP server
  const server = app.listen(config.server.port, config.server.host, async () => {
    console.log('🎉 Identity Provider started successfully!');
    console.log(`   • Server: ${config.server.issuer}`);
    console.log(`   • Environment: ${config.environment}`);
    console.log(`   • Process ID: ${process.pid}`);
    console.log('');
    console.log('📋 Available endpoints:');
    console.log(`   • Discovery: ${config.server.issuer}/.well-known/openid-configuration`);
    console.log(`   • JWKS: ${config.server.issuer}/.well-known/jwks.json`);
    console.log(`   • Login: ${config.server.issuer}/login`);
    console.log(`   • Health: ${config.server.issuer}/health`);
    console.log('');
    console.log('🔗 Integration URLs:');
    console.log(`   • Frontend SPA: ${config.server.frontendUrl}`);
    console.log(`   • Resource Server: ${config.server.resourceServerUrl}`);
    console.log('');
    
    // Initialize user service (loads test users in development)
    try {
      const { initializeUserService } = await import('./services/user');
      await initializeUserService();
    } catch (error) {
      console.error('❌ Failed to initialize user service:', error);
    }
    
    console.log('🚀 Ready to handle OAuth 2.0 + OIDC requests!');
  });

  // Graceful shutdown handling
  process.on('SIGTERM', () => {
    console.log('📴 SIGTERM received, shutting down gracefully...');
    server.close(() => {
      console.log('✅ Server closed successfully');
      process.exit(0);
    });
  });

  process.on('SIGINT', () => {
    console.log('\n📴 SIGINT received, shutting down gracefully...');
    server.close(() => {
      console.log('✅ Server closed successfully');
      process.exit(0);
    });
  });
}

// Handle startup errors
startServer().catch((error) => {
  console.error('❌ Failed to start Identity Provider:', error);
  process.exit(1);
});

export default app;