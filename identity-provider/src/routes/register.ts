/**
 * User Registration Endpoint
 * 
 * Provides user registration functionality for the Identity Provider.
 * Allows creation of new user accounts for testing purposes.
 * 
 * Security Note:
 * This is a development/testing endpoint. Production systems should:
 * - Hash passwords with bcrypt or similar
 * - Implement rate limiting
 * - Add email verification
 * - Validate password strength
 * - Add CAPTCHA protection
 * - Implement proper input sanitization
 */

import { Router, Request, Response } from 'express';
import { userStore } from '../storage/memory';
import { User } from '../storage/models';
import { randomBytes } from 'crypto';
import { debugLog } from '../config';

const router = Router();

/**
 * Registration Request Interface
 */
interface RegisterRequest {
  username: string;
  email: string;
  password: string;
  confirmPassword?: string;
}

/**
 * POST /register - Create new user account
 * 
 * Allows registration of new user accounts for testing.
 * Validates input and creates user with file-based storage.
 */
router.post('/', async (req: Request, res: Response) => {
  debugLog('REGISTER', 'Registration request received');
  
  try {
    const { username, email, password, confirmPassword } = req.body as RegisterRequest;
    
    // Validate required fields
    if (!username || !email || !password) {
      return res.status(400).json({
        error: 'missing_fields',
        message: 'Username, email, and password are required'
      });
    }
    
    // Basic validation
    if (username.length < 3) {
      return res.status(400).json({
        error: 'invalid_username',
        message: 'Username must be at least 3 characters long'
      });
    }
    
    if (!email.includes('@')) {
      return res.status(400).json({
        error: 'invalid_email',
        message: 'Please provide a valid email address'
      });
    }
    
    if (password.length < 6) {
      return res.status(400).json({
        error: 'weak_password',
        message: 'Password must be at least 6 characters long'
      });
    }
    
    if (confirmPassword && password !== confirmPassword) {
      return res.status(400).json({
        error: 'password_mismatch',
        message: 'Password and confirmation do not match'
      });
    }
    
    // Generate user ID
    const userId = `user-${randomBytes(8).toString('hex')}`;
    
    // Create user object
    const newUser: User = {
      id: userId,
      username: username.trim().toLowerCase(),
      email: email.trim().toLowerCase(),
      passwordHash: password, // Plain text for development (should be hashed in production)
      isActive: true,
      createdAt: new Date()
    };
    
    // Attempt to create user
    userStore.create(newUser);
    
    debugLog('REGISTER', `User registered successfully: ${newUser.username}`);
    
    // Return success (without password)
    return res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        isActive: newUser.isActive,
        createdAt: newUser.createdAt
      }
    });
    
  } catch (error) {
    debugLog('REGISTER', `Registration failed: ${error}`);
    
    if (error instanceof Error) {
      // Handle specific errors
      if (error.message.includes('already exists')) {
        return res.status(409).json({
          error: 'user_exists',
          message: error.message
        });
      }
    }
    
    // Generic error
    return res.status(500).json({
      error: 'registration_failed',
      message: 'Failed to create user account'
    });
  }
});

/**
 * GET /register - Show registration form (for testing)
 * 
 * Simple HTML form for manual testing of registration endpoint.
 */
router.get('/', (req: Request, res: Response) => {
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>AlexIdP - User Registration</title>
      <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input { width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        button { background: #667eea; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; width: 100%; }
        button:hover { background: #5a67d8; }
        .error { color: #e53e3e; margin-top: 10px; }
        .success { color: #38a169; margin-top: 10px; }
        .info { background: #f7fafc; padding: 15px; border-radius: 4px; margin-bottom: 20px; color: #4a5568; }
      </style>
    </head>
    <body>
      <h1>🔐 AlexIdP User Registration</h1>
      
      <div class="info">
        <strong>Development Mode:</strong> This registration form creates user accounts for testing OAuth flows. 
        Passwords are stored in plain text in <code>src/data/users.txt</code>.
      </div>
      
      <form id="registerForm">
        <div class="form-group">
          <label for="username">Username:</label>
          <input type="text" id="username" name="username" required minlength="3">
        </div>
        
        <div class="form-group">
          <label for="email">Email:</label>
          <input type="email" id="email" name="email" required>
        </div>
        
        <div class="form-group">
          <label for="password">Password:</label>
          <input type="password" id="password" name="password" required minlength="6">
        </div>
        
        <div class="form-group">
          <label for="confirmPassword">Confirm Password:</label>
          <input type="password" id="confirmPassword" name="confirmPassword" required>
        </div>
        
        <button type="submit">Create Account</button>
      </form>
      
      <div id="message"></div>
      
      <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e2e8f0;">
        <h3>Existing Users (for testing):</h3>
        <p>You can also log in with these pre-created accounts:</p>
        <ul>
          <li><strong>alice</strong> / password123</li>
          <li><strong>bob</strong> / secret456</li>
          <li><strong>charlie</strong> / mypassword</li>
        </ul>
      </div>
      
      <script>
        document.getElementById('registerForm').addEventListener('submit', async (e) => {
          e.preventDefault();
          
          const messageDiv = document.getElementById('message');
          const formData = new FormData(e.target);
          const data = Object.fromEntries(formData.entries());
          
          try {
            const response = await fetch('/register', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(data)
            });
            
            const result = await response.json();
            
            if (response.ok) {
              messageDiv.innerHTML = '<div class="success">✅ ' + result.message + '</div>';
              document.getElementById('registerForm').reset();
            } else {
              messageDiv.innerHTML = '<div class="error">❌ ' + result.message + '</div>';
            }
          } catch (error) {
            messageDiv.innerHTML = '<div class="error">❌ Registration failed: ' + error.message + '</div>';
          }
        });
      </script>
    </body>
    </html>
  `;
  
  res.send(html);
});

export default router;