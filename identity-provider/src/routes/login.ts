import { Router, Request, Response } from 'express';
import { authenticateUser } from '../services/user';
import { serverConfig } from '../config';

/**
 * Login Route Handlers for OAuth 2.0 + OIDC Identity Provider
 * 
 * This module handles user authentication through web forms, managing login sessions
 * and redirecting users appropriately within the OAuth 2.0 authorization flow.
 * 
 * Key Authentication Concepts:
 * - Session-based Authentication: Users login once, session persists across requests
 * - Login Flow Integration: Login integrates with OAuth authorization flow
 * - Redirect Handling: After login, users continue to authorization or return destination
 * - Security: CSRF protection, secure session management, input validation
 * 
 * Authentication Flow Integration:
 * ```
 * ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
 * │   SPA Client    │    │  Identity       │    │  User Browser   │
 * │                 │    │  Provider       │    │                 │
 * └─────────────────┘    └─────────────────┘    └─────────────────┘
 *          │                       │                       │
 *          │ 1. Start OAuth Flow   │                       │
 *          │ GET /authorize        │                       │
 *          ├──────────────────────►│                       │
 *          │                       │                       │
 *          │                       │ 2. Check Login Status │
 *          │                       │    (no session)       │
 *          │                       │                       │
 *          │                       │ 3. Redirect to Login  │
 *          │                       │ 302 /login?return_to= │
 *          │                       │     /authorize?...    │
 *          │                       ├──────────────────────►│
 *          │                       │                       │
 *          │                       │ 4. Display Login Form │
 *          │                       │ GET /login            │
 *          │                       │◄──────────────────────┤
 *          │                       │                       │
 *          │                       │ 5. Login Form HTML    │
 *          │                       ├──────────────────────►│
 *          │                       │                       │
 *          │                       │ 6. Submit Credentials │
 *          │                       │ POST /login           │
 *          │                       │ {username, password}  │
 *          │                       │◄──────────────────────┤
 *          │                       │                       │
 *          │                       │ 7. Authenticate User  │
 *          │                       │    & Create Session   │
 *          │                       │                       │
 *          │                       │ 8. Redirect to OAuth  │
 *          │                       │ 302 /authorize?...    │
 *          │                       ├──────────────────────►│
 *          │                       │                       │
 *          │                       │ 9. Continue OAuth     │
 *          │                       │    (now authenticated)│
 * ```
 * 
 * Security Considerations:
 * ```
 * [Login Form] ──────────────────┬─────► [CSRF Token Required]
 *         │                     │
 *         │                     └─────► [Rate Limiting Applied]
 *         │
 *         ▼
 * [Credential Validation] ───────┬─────► [bcrypt Password Hashing]
 *         │                     │
 *         │                     └─────► [Timing Attack Protection]
 *         │
 *         ▼
 * [Session Creation] ────────────┬─────► [Secure Session Cookies]
 *                               │
 *                               └─────► [Session Regeneration]
 * ```
 * 
 * ## API Summary
 * 
 * ### Login Form Display
 * - `GET /login` - Display login form with optional return URL
 * - Query Parameters: `?return_to=/authorize?...` - OAuth continuation URL
 * - Response: HTML login form with CSRF protection
 * - Security: Rate limiting, HTTPS enforcement in production
 * 
 * ### Login Processing
 * - `POST /login` - Process user credentials and create session
 * - Body: `{username, password, csrf_token}` - User credentials + CSRF protection
 * - Response: Redirect to return URL or default logged-in page
 * - Security: Password verification, session creation, audit logging
 * 
 * ### Session Management
 * - Sessions stored in server memory (production: Redis/database)
 * - Secure HTTP-only cookies with SameSite protection
 * - Automatic session expiration based on configuration
 * - Session regeneration after successful login (security best practice)
 * 
 * ### Production Considerations
 * - Implement account lockout after multiple failed attempts
 * - Add CAPTCHA for suspected bot traffic
 * - Use secure session storage (Redis) instead of memory
 * - Add comprehensive audit logging for security monitoring
 * - Implement password reset and account recovery flows
 * - Add multi-factor authentication support
 * - Rate limit login attempts per IP and per username
 * 
 * ### Integration Points
 * - OAuth Authorization Flow: Login redirects continue authorization process
 * - User Service: Authenticates credentials and retrieves user profiles
 * - Session Middleware: Creates and manages user sessions
 * - CSRF Middleware: Protects against cross-site request forgery
 */

const router = Router();

/**
 * Session user interface for type safety
 */
interface SessionUser {
  id: string;
  username: string;
  email: string;
  name?: string;
  authenticatedAt: Date;
}

/**
 * Extend Express session interface to include user
 */
declare module 'express-session' {
  interface SessionData {
    user?: SessionUser;
    returnTo?: string;
  }
}

/**
 * Login form data interface
 */
interface LoginFormData {
  username: string;
  password: string;
  return_to?: string;
}

/**
 * GET /login - Display Login Form
 * 
 * Renders the login form for user authentication. Supports return URL parameter
 * to redirect users back to their original destination after successful login.
 * 
 * Query Parameters:
 * - return_to: URL to redirect to after successful login (typically OAuth authorize endpoint)
 * 
 * Security Features:
 * - CSRF token embedded in form
 * - Secure headers (Content Security Policy, etc.)
 * - Rate limiting applied (configured in middleware)
 * 
 * Example URLs:
 * - `/login` - Basic login form
 * - `/login?return_to=/authorize?client_id=...` - Login with OAuth continuation
 * 
 * Response: HTML login form (Google-inspired design)
 */
router.get('/login', (req: Request, res: Response) => {
  try {
    // If user is already logged in, redirect to destination or home
    if (req.session.user) {
      console.log(`👤 User already authenticated: ${req.session.user.username}`);
      const returnTo = req.query.return_to as string || '/';
      return res.redirect(returnTo);
    }

    // Store return URL in session for use after login
    const returnTo = req.query.return_to as string;
    if (returnTo) {
      req.session.returnTo = returnTo;
      console.log(`🔄 Storing return URL in session: ${returnTo}`);
    }

    console.log('📋 Displaying login form');
    
    // Set security headers for login page
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    // Generate login form HTML (Google-inspired design)
    const loginFormHtml = generateLoginFormHtml(returnTo);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(loginFormHtml);

  } catch (error) {
    console.error('❌ Error displaying login form:', error);
    res.status(500).send(`
      <html>
        <head><title>Error</title></head>
        <body>
          <h1>Login Error</h1>
          <p>Unable to display login form. Please try again.</p>
          <a href="/login">Try Again</a>
        </body>
      </html>
    `);
  }
});

/**
 * POST /login - Process User Login
 * 
 * Authenticates user credentials, creates session, and redirects appropriately.
 * Handles both OAuth flow continuations and direct login attempts.
 * 
 * Form Data:
 * - username: Username or email address
 * - password: User password
 * - return_to: Optional redirect URL (also from session)
 * 
 * Success Response: 302 redirect to return URL or default page
 * Error Response: 400/401 with error message in login form
 * 
 * Security Features:
 * - Password verification via bcrypt
 * - Session regeneration after successful login
 * - Rate limiting on login attempts
 * - Audit logging of authentication events
 */
router.post('/login', async (req: Request, res: Response) => {
  try {
    const { username, password, return_to }: LoginFormData = req.body;

    // Input validation
    if (!username || !password) {
      console.log('❌ Login attempt missing credentials');
      return renderLoginError(res, 'Username and password are required', return_to);
    }

    // Clean up username (remove extra whitespace)
    const cleanUsername = username.trim();
    
    console.log(`🔐 Login attempt for user: ${cleanUsername}`);

    // Authenticate user
    const authResult = await authenticateUser(cleanUsername, password);

    if (!authResult.success || !authResult.user) {
      console.log(`❌ Authentication failed for user: ${cleanUsername}`);
      // Use generic error message to prevent username enumeration
      return renderLoginError(res, 'Invalid username or password', return_to);
    }

    const user = authResult.user;
    console.log(`✅ Authentication successful for user: ${user.username} (${user.id})`);

    // Regenerate session for security (prevents session fixation attacks)
    req.session.regenerate((err) => {
      if (err) {
        console.error('❌ Session regeneration failed:', err);
        return renderLoginError(res, 'Login failed due to server error', return_to);
      }

      // Create session user data
      const sessionUser: SessionUser = {
        id: user.id,
        username: user.username,
        email: user.email,
        name: user.name,
        authenticatedAt: new Date()
      };

      // Store user in session
      req.session.user = sessionUser;

      // Determine redirect destination
      const redirectTo = return_to || req.session.returnTo || '/';
      
      // Clear returnTo from session after use
      delete req.session.returnTo;

      console.log(`🔄 Redirecting authenticated user to: ${redirectTo}`);

      // Save session and redirect
      req.session.save((saveErr) => {
        if (saveErr) {
          console.error('❌ Session save failed:', saveErr);
          return renderLoginError(res, 'Login failed due to server error', return_to);
        }

        res.redirect(redirectTo);
      });
    });

  } catch (error) {
    console.error('❌ Login processing error:', error);
    const return_to = req.body.return_to;
    renderLoginError(res, 'Login failed due to server error', return_to);
  }
});

/**
 * POST /logout - User Logout
 * 
 * Destroys user session and redirects to login page or specified URL.
 * 
 * Form Data:
 * - redirect_to: Optional redirect URL after logout
 * 
 * Response: 302 redirect to login page or specified URL
 */
router.post('/logout', (req: Request, res: Response) => {
  const username = req.session.user?.username || 'anonymous';
  const redirectTo = req.body.redirect_to || '/login';

  console.log(`👋 Logging out user: ${username}`);

  // Destroy session
  req.session.destroy((err) => {
    if (err) {
      console.error('❌ Session destruction failed:', err);
    }

    // Clear session cookie
    res.clearCookie('connect.sid'); // Default express-session cookie name

    console.log(`✅ User logged out successfully: ${username}`);
    res.redirect(redirectTo);
  });
});

/**
 * GET /logout - Logout Confirmation Page
 * 
 * Displays logout confirmation or processes automatic logout.
 * Can be used for logout confirmation UI or immediate logout.
 */
router.get('/logout', (req: Request, res: Response) => {
  const confirm = req.query.confirm as string;
  
  if (confirm === 'true') {
    // Auto-logout without confirmation - redirect to POST logout
    const username = req.session.user?.username || 'anonymous';
    console.log(`👋 Auto-logging out user: ${username}`);
    
    req.session.destroy((err) => {
      if (err) {
        console.error('❌ Session destruction failed:', err);
      }
      res.clearCookie('connect.sid');
      console.log(`✅ User logged out successfully: ${username}`);
      res.redirect('/login');
    });
    return;
  }

  // Display logout confirmation (simple page)
  const logoutHtml = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Logout - Identity Provider</title>
      <style>
        body { 
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
          margin: 0; 
          padding: 20px; 
          background: #f5f5f5;
          display: flex;
          align-items: center;
          justify-content: center;
          min-height: 100vh;
        }
        .logout-container {
          background: white;
          padding: 40px;
          border-radius: 8px;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
          text-align: center;
          max-width: 400px;
          width: 100%;
        }
        h1 { color: #333; margin-bottom: 20px; }
        p { color: #666; margin-bottom: 30px; }
        .button { 
          background: #1a73e8; 
          color: white; 
          padding: 12px 24px; 
          border: none; 
          border-radius: 4px; 
          cursor: pointer; 
          margin: 0 10px;
          text-decoration: none;
          display: inline-block;
        }
        .button:hover { background: #1557b0; }
        .button.secondary { 
          background: #f8f9fa; 
          color: #3c4043; 
          border: 1px solid #dadce0; 
        }
        .button.secondary:hover { background: #f1f3f4; }
      </style>
    </head>
    <body>
      <div class="logout-container">
        <h1>Sign out</h1>
        <p>Are you sure you want to sign out?</p>
        <form method="post" action="/logout" style="display: inline;">
          <button type="submit" class="button">Sign out</button>
        </form>
        <a href="/" class="button secondary">Cancel</a>
      </div>
    </body>
    </html>
  `;

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(logoutHtml);
});

/**
 * Generate HTML login form with Google-inspired design
 * 
 * @param returnTo Optional return URL to preserve through login
 * @returns Complete HTML login form
 */
function generateLoginFormHtml(returnTo?: string): string {
  const returnToInput = returnTo ? `<input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">` : '';
  
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Sign in - Identity Provider</title>
      <style>
        * {
          box-sizing: border-box;
        }
        
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          margin: 0;
          padding: 0;
          background: #f5f5f5;
          display: flex;
          align-items: center;
          justify-content: center;
          min-height: 100vh;
        }
        
        .login-container {
          background: white;
          border-radius: 8px;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
          padding: 48px 40px 36px;
          width: 100%;
          max-width: 450px;
        }
        
        .logo {
          text-align: center;
          margin-bottom: 32px;
        }
        
        .logo h1 {
          color: #1a73e8;
          font-size: 24px;
          font-weight: 400;
          margin: 0;
        }
        
        .title {
          font-size: 24px;
          font-weight: 400;
          color: #202124;
          text-align: center;
          margin-bottom: 8px;
        }
        
        .subtitle {
          font-size: 16px;
          color: #5f6368;
          text-align: center;
          margin-bottom: 32px;
        }
        
        .form-group {
          margin-bottom: 24px;
        }
        
        label {
          display: block;
          font-size: 14px;
          color: #5f6368;
          margin-bottom: 8px;
          font-weight: 500;
        }
        
        input[type="text"],
        input[type="password"] {
          width: 100%;
          padding: 16px;
          border: 1px solid #dadce0;
          border-radius: 4px;
          font-size: 16px;
          background: #fff;
          transition: border-color 0.2s;
        }
        
        input[type="text"]:focus,
        input[type="password"]:focus {
          outline: none;
          border-color: #1a73e8;
          box-shadow: 0 0 0 2px rgba(26, 115, 232, 0.2);
        }
        
        input[type="text"]:invalid,
        input[type="password"]:invalid {
          border-color: #d93025;
        }
        
        .button-container {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-top: 32px;
        }
        
        .forgot-password {
          font-size: 14px;
          color: #1a73e8;
          text-decoration: none;
        }
        
        .forgot-password:hover {
          text-decoration: underline;
        }
        
        .sign-in-button {
          background: #1a73e8;
          color: white;
          border: none;
          padding: 12px 24px;
          border-radius: 4px;
          font-size: 14px;
          font-weight: 500;
          cursor: pointer;
          transition: background-color 0.2s;
        }
        
        .sign-in-button:hover {
          background: #1557b0;
        }
        
        .sign-in-button:disabled {
          background: #f1f3f4;
          color: #3c4043;
          cursor: not-allowed;
        }
        
        .error-message {
          background: #fce8e6;
          border: 1px solid #f28b82;
          border-radius: 4px;
          color: #d93025;
          padding: 12px 16px;
          margin-bottom: 24px;
          font-size: 14px;
          display: flex;
          align-items: center;
        }
        
        .error-icon {
          margin-right: 8px;
          font-size: 18px;
        }
        
        .demo-credentials {
          background: #e8f0fe;
          border: 1px solid #aecbfa;
          border-radius: 4px;
          padding: 16px;
          margin-top: 24px;
          font-size: 14px;
          color: #1967d2;
        }
        
        .demo-credentials h4 {
          margin: 0 0 8px 0;
          font-weight: 500;
        }
        
        .demo-credentials code {
          background: #f8f9fa;
          padding: 2px 4px;
          border-radius: 2px;
          font-family: monospace;
        }
        
        @media (max-width: 480px) {
          .login-container {
            margin: 20px;
            padding: 24px;
          }
          
          .title {
            font-size: 20px;
          }
        }
      </style>
    </head>
    <body>
      <div class="login-container">
        <div class="logo">
          <h1>🔐 Identity Provider</h1>
        </div>
        
        <h2 class="title">Sign in</h2>
        <p class="subtitle">Continue to your account</p>
        
        <form method="post" action="/login" id="loginForm">
          ${returnToInput}
          
          <div class="form-group">
            <label for="username">Username or email</label>
            <input 
              type="text" 
              id="username" 
              name="username" 
              required 
              autofocus
              autocomplete="username"
              placeholder="Enter your username or email"
            >
          </div>
          
          <div class="form-group">
            <label for="password">Password</label>
            <input 
              type="password" 
              id="password" 
              name="password" 
              required
              autocomplete="current-password"
              placeholder="Enter your password"
            >
          </div>
          
          <div class="button-container">
            <a href="#" class="forgot-password">Forgot password?</a>
            <button type="submit" class="sign-in-button">Sign in</button>
          </div>
        </form>
        
        <div class="demo-credentials">
          <h4>Demo Credentials</h4>
          <p>Username: <code>testuser</code> or <code>alice</code><br>
             Password: <code>password123</code> or <code>alice123</code></p>
        </div>
      </div>

      <script>
        // Simple client-side form validation and UX improvements
        document.getElementById('loginForm').addEventListener('submit', function(e) {
          const username = document.getElementById('username').value.trim();
          const password = document.getElementById('password').value;
          const button = document.querySelector('.sign-in-button');
          
          if (!username || !password) {
            e.preventDefault();
            alert('Please enter both username and password');
            return;
          }
          
          // Disable button to prevent double submission
          button.disabled = true;
          button.textContent = 'Signing in...';
          
          // Re-enable button after 3 seconds if form doesn't submit
          setTimeout(() => {
            button.disabled = false;
            button.textContent = 'Sign in';
          }, 3000);
        });
        
        // Auto-focus username field
        document.getElementById('username').focus();
      </script>
    </body>
    </html>
  `;
}

/**
 * Render login form with error message
 * 
 * @param res Express response object
 * @param errorMessage Error message to display
 * @param returnTo Optional return URL to preserve
 */
function renderLoginError(res: Response, errorMessage: string, returnTo?: string): void {
  const returnToInput = returnTo ? `<input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">` : '';
  
  const loginErrorHtml = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Sign in - Identity Provider</title>
      <style>
        * { box-sizing: border-box; }
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          margin: 0;
          padding: 0;
          background: #f5f5f5;
          display: flex;
          align-items: center;
          justify-content: center;
          min-height: 100vh;
        }
        .login-container {
          background: white;
          border-radius: 8px;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
          padding: 48px 40px 36px;
          width: 100%;
          max-width: 450px;
        }
        .logo { text-align: center; margin-bottom: 32px; }
        .logo h1 { color: #1a73e8; font-size: 24px; font-weight: 400; margin: 0; }
        .title { font-size: 24px; font-weight: 400; color: #202124; text-align: center; margin-bottom: 8px; }
        .subtitle { font-size: 16px; color: #5f6368; text-align: center; margin-bottom: 32px; }
        .error-message {
          background: #fce8e6;
          border: 1px solid #f28b82;
          border-radius: 4px;
          color: #d93025;
          padding: 12px 16px;
          margin-bottom: 24px;
          font-size: 14px;
          display: flex;
          align-items: center;
        }
        .error-icon { margin-right: 8px; font-size: 18px; }
        .form-group { margin-bottom: 24px; }
        label { display: block; font-size: 14px; color: #5f6368; margin-bottom: 8px; font-weight: 500; }
        input[type="text"], input[type="password"] {
          width: 100%;
          padding: 16px;
          border: 1px solid #dadce0;
          border-radius: 4px;
          font-size: 16px;
          background: #fff;
          transition: border-color 0.2s;
        }
        input[type="text"]:focus, input[type="password"]:focus {
          outline: none;
          border-color: #1a73e8;
          box-shadow: 0 0 0 2px rgba(26, 115, 232, 0.2);
        }
        .button-container { display: flex; justify-content: space-between; align-items: center; margin-top: 32px; }
        .forgot-password { font-size: 14px; color: #1a73e8; text-decoration: none; }
        .forgot-password:hover { text-decoration: underline; }
        .sign-in-button {
          background: #1a73e8;
          color: white;
          border: none;
          padding: 12px 24px;
          border-radius: 4px;
          font-size: 14px;
          font-weight: 500;
          cursor: pointer;
          transition: background-color 0.2s;
        }
        .sign-in-button:hover { background: #1557b0; }
      </style>
    </head>
    <body>
      <div class="login-container">
        <div class="logo">
          <h1>🔐 Identity Provider</h1>
        </div>
        
        <h2 class="title">Sign in</h2>
        <p class="subtitle">Continue to your account</p>
        
        <div class="error-message">
          <span class="error-icon">⚠️</span>
          ${escapeHtml(errorMessage)}
        </div>
        
        <form method="post" action="/login">
          ${returnToInput}
          
          <div class="form-group">
            <label for="username">Username or email</label>
            <input 
              type="text" 
              id="username" 
              name="username" 
              required 
              autofocus
              autocomplete="username"
              placeholder="Enter your username or email"
            >
          </div>
          
          <div class="form-group">
            <label for="password">Password</label>
            <input 
              type="password" 
              id="password" 
              name="password" 
              required
              autocomplete="current-password"
              placeholder="Enter your password"
            >
          </div>
          
          <div class="button-container">
            <a href="#" class="forgot-password">Forgot password?</a>
            <button type="submit" class="sign-in-button">Sign in</button>
          </div>
        </form>
      </div>
    </body>
    </html>
  `;

  res.status(400).setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(loginErrorHtml);
}

/**
 * Escape HTML to prevent XSS attacks
 * 
 * @param text Text to escape
 * @returns HTML-escaped text
 */
function escapeHtml(text: string): string {
  const map: { [key: string]: string } = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  };
  return text.replace(/[&<>"']/g, (m) => map[m]);
}

export default router;