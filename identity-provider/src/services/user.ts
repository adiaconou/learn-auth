import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { User } from '../storage/models';
import { userStore } from '../storage/memory';

/**
 * User Management Service for OAuth 2.0 + OIDC Identity Provider
 * 
 * This module handles user authentication, registration, and profile management.
 * It provides the core user identity functions that power the OIDC Identity Provider.
 * 
 * Key Security Concepts:
 * - Password Hashing: bcrypt with salt rounds for secure password storage
 * - Account Validation: Email format validation, username requirements
 * - Authentication: Secure password verification with timing attack protection
 * - Profile Management: OIDC-compliant user claims and profile updates
 * 
 * Authentication Flow:
 * ```
 * ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
 * │   Login Form    │    │  User Service   │    │  User Storage   │
 * │                 │    │  (This Module)  │    │   (Memory)      │
 * └─────────────────┘    └─────────────────┘    └─────────────────┘
 *          │                       │                       │
 *          │ 1. Login Request      │                       │
 *          │ {username, password}  │                       │
 *          ├──────────────────────►│                       │
 *          │                       │                       │
 *          │                       │ 2. findByUsername()   │
 *          │                       ├──────────────────────►│
 *          │                       │                       │
 *          │                       │ 3. User + passwordHash│
 *          │                       │◄──────────────────────┤
 *          │                       │                       │
 *          │                       │ 4. bcrypt.compare()   │
 *          │                       │    (verify password)  │
 *          │                       │                       │
 *          │                       │ 5. updateLastLogin()  │
 *          │                       ├──────────────────────►│
 *          │                       │                       │
 *          │ 6. Authentication     │                       │
 *          │    Result             │                       │
 *          │    ✅ Success: User   │                       │
 *          │    ❌ Failure: null   │                       │
 *          │◄──────────────────────┤                       │
 * ```
 * 
 * Password Security Flow:
 * ```
 * [Registration] ──► [Password] ──► [bcrypt.hash()] ──► [Store Hash]
 *                                        ↓
 *                                  [Salt Rounds: 12]
 *                                        ↓
 *                               [Secure Hash Storage]
 * 
 * [Login] ──► [Password] ──► [bcrypt.compare()] ──► [Verification]
 *                                 ↑                      ↓
 *                          [Stored Hash]           [✅ or ❌]
 * ```
 * 
 * ## API Summary
 * 
 * ### Authentication Functions
 * - `authenticateUser(username, password)` - Verify user credentials and return user data
 * - `validatePassword(password)` - Check password meets security requirements
 * - `hashPassword(password)` - Generate secure bcrypt hash for storage
 * 
 * ### User Registration
 * - `registerUser(userData)` - Create new user account with validation
 * - `isUsernameAvailable(username)` - Check if username is not taken
 * - `isEmailAvailable(email)` - Check if email is not taken
 * 
 * ### Profile Management
 * - `getUserProfile(userId)` - Get user profile for OIDC claims
 * - `updateUserProfile(userId, updates)` - Update user profile information
 * - `getUserById(userId)` - Get user by ID for token generation
 * 
 * ### Security & Validation
 * - `validateUserInput(userData)` - Validate user registration data
 * - `sanitizeUserProfile(user)` - Remove sensitive data from user object
 * - `logSecurityEvent(userId, event)` - Log security events for monitoring
 * 
 * ### Development Utilities
 * - `createTestUsers()` - Create hardcoded test users for development
 * - `getAllUsers()` - Get all users for admin/debug purposes
 * - `deleteUser(userId)` - Remove user account (admin only)
 * 
 * ### Production Considerations
 * - Use stronger password requirements in production
 * - Implement account lockout after failed attempts
 * - Add email verification for new registrations
 * - Use database with proper indexing for performance
 * - Add audit logging for all authentication events
 * - Implement password reset functionality
 * - Add two-factor authentication support
 */

/**
 * Password security configuration
 */
const PASSWORD_CONFIG = {
  // bcrypt salt rounds (12 = ~250ms, good balance of security vs performance)
  saltRounds: 12,
  
  // Password requirements (production should be stricter)
  minLength: 6,
  maxLength: 128,
  requireUppercase: false,  // Relaxed for development
  requireLowercase: false,  // Relaxed for development
  requireNumbers: false,    // Relaxed for development
  requireSpecialChars: false // Relaxed for development
};

/**
 * Username validation configuration
 */
const USERNAME_CONFIG = {
  minLength: 3,
  maxLength: 30,
  allowedPattern: /^[a-zA-Z0-9_-]+$/,  // Alphanumeric, underscore, hyphen only
};

/**
 * Email validation pattern (basic validation)
 */
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * User registration input interface
 */
export interface UserRegistrationInput {
  username: string;
  email: string;
  password: string;
  name?: string;
}

/**
 * User profile update interface
 */
export interface UserProfileUpdate {
  name?: string;
  email?: string;
  // Add other profile fields as needed
}

/**
 * Authentication result interface
 */
export interface AuthenticationResult {
  success: boolean;
  user?: User;
  error?: string;
}

/**
 * Validation result interface
 */
export interface ValidationResult {
  isValid: boolean;
  errors: string[];
}

/**
 * Hash a password using bcrypt
 * 
 * Uses bcrypt with configurable salt rounds for secure password storage.
 * Never store plaintext passwords - always hash before storing.
 * 
 * @param password Plain text password to hash
 * @returns Promise resolving to bcrypt hash
 */
export async function hashPassword(password: string): Promise<string> {
  try {
    const hash = await bcrypt.hash(password, PASSWORD_CONFIG.saltRounds);
    console.log('🔐 Password hashed successfully');
    return hash;
  } catch (error) {
    console.error('❌ Password hashing failed:', error);
    throw new Error('Failed to hash password');
  }
}

/**
 * Verify a password against its hash
 * 
 * Uses bcrypt.compare() for secure password verification with timing attack protection.
 * 
 * @param password Plain text password to verify
 * @param hash Stored bcrypt hash
 * @returns Promise resolving to true if password matches
 */
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  try {
    const isValid = await bcrypt.compare(password, hash);
    console.log(`🔐 Password verification: ${isValid ? '✅ Valid' : '❌ Invalid'}`);
    return isValid;
  } catch (error) {
    console.error('❌ Password verification failed:', error);
    return false;
  }
}

/**
 * Validate password meets security requirements
 * 
 * Checks password against configured security policy.
 * In production, use stronger requirements (length, complexity, etc.).
 * 
 * @param password Password to validate
 * @returns Validation result with specific errors
 */
export function validatePassword(password: string): ValidationResult {
  const errors: string[] = [];
  
  // Check length
  if (password.length < PASSWORD_CONFIG.minLength) {
    errors.push(`Password must be at least ${PASSWORD_CONFIG.minLength} characters`);
  }
  
  if (password.length > PASSWORD_CONFIG.maxLength) {
    errors.push(`Password must be no more than ${PASSWORD_CONFIG.maxLength} characters`);
  }
  
  // Additional requirements (currently relaxed for development)
  if (PASSWORD_CONFIG.requireUppercase && !/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  
  if (PASSWORD_CONFIG.requireLowercase && !/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  
  if (PASSWORD_CONFIG.requireNumbers && !/\d/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  
  if (PASSWORD_CONFIG.requireSpecialChars && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
}

/**
 * Validate username meets requirements
 * 
 * @param username Username to validate
 * @returns Validation result with specific errors
 */
export function validateUsername(username: string): ValidationResult {
  const errors: string[] = [];
  
  // Check length
  if (username.length < USERNAME_CONFIG.minLength) {
    errors.push(`Username must be at least ${USERNAME_CONFIG.minLength} characters`);
  }
  
  if (username.length > USERNAME_CONFIG.maxLength) {
    errors.push(`Username must be no more than ${USERNAME_CONFIG.maxLength} characters`);
  }
  
  // Check pattern
  if (!USERNAME_CONFIG.allowedPattern.test(username)) {
    errors.push('Username can only contain letters, numbers, underscores, and hyphens');
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
}

/**
 * Validate email format
 * 
 * @param email Email to validate
 * @returns Validation result
 */
export function validateEmail(email: string): ValidationResult {
  const errors: string[] = [];
  
  if (!email || email.trim().length === 0) {
    errors.push('Email is required');
  } else if (!EMAIL_PATTERN.test(email)) {
    errors.push('Email format is invalid');
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
}

/**
 * Validate complete user registration input
 * 
 * @param userData User registration data to validate
 * @returns Combined validation result
 */
export function validateUserInput(userData: UserRegistrationInput): ValidationResult {
  const allErrors: string[] = [];
  
  // Validate username
  const usernameValidation = validateUsername(userData.username);
  allErrors.push(...usernameValidation.errors);
  
  // Validate email
  const emailValidation = validateEmail(userData.email);
  allErrors.push(...emailValidation.errors);
  
  // Validate password
  const passwordValidation = validatePassword(userData.password);
  allErrors.push(...passwordValidation.errors);
  
  return {
    isValid: allErrors.length === 0,
    errors: allErrors
  };
}

/**
 * Check if username is available (not taken)
 * 
 * @param username Username to check
 * @returns True if username is available
 */
export function isUsernameAvailable(username: string): boolean {
  const existingUser = userStore.findByUsername(username);
  return !existingUser;
}

/**
 * Check if email is available (not taken)
 * 
 * @param email Email to check
 * @returns True if email is available
 */
export function isEmailAvailable(email: string): boolean {
  const existingUser = userStore.findByEmail(email);
  return !existingUser;
}

/**
 * Register a new user account
 * 
 * Validates input, checks for duplicates, hashes password, and creates user account.
 * 
 * @param userData User registration data
 * @returns Promise resolving to created user (without password hash)
 * @throws Error if validation fails or user already exists
 */
export async function registerUser(userData: UserRegistrationInput): Promise<User> {
  console.log(`👤 Registering new user: ${userData.username}`);
  
  // Validate input data
  const validation = validateUserInput(userData);
  if (!validation.isValid) {
    throw new Error(`Validation failed: ${validation.errors.join(', ')}`);
  }
  
  // Check username availability
  if (!isUsernameAvailable(userData.username)) {
    throw new Error(`Username '${userData.username}' is already taken`);
  }
  
  // Check email availability
  if (!isEmailAvailable(userData.email)) {
    throw new Error(`Email '${userData.email}' is already registered`);
  }
  
  // Hash password
  const passwordHash = await hashPassword(userData.password);
  
  // Create user object
  const user: User = {
    id: uuidv4(),
    username: userData.username.toLowerCase(), // Store lowercase for consistency
    email: userData.email.toLowerCase(),       // Store lowercase for consistency
    passwordHash,
    name: userData.name || userData.username,  // Default name to username
    createdAt: new Date(),
    isActive: true
  };
  
  // Store user
  userStore.create(user);
  
  console.log(`✅ User registered successfully: ${user.username} (${user.id})`);
  return user;
}

/**
 * Authenticate user with username and password
 * 
 * Finds user by username, verifies password, and updates last login timestamp.
 * Uses bcrypt for secure password comparison with timing attack protection.
 * 
 * @param username Username or email for login
 * @param password Plain text password
 * @returns Promise resolving to authentication result
 */
export async function authenticateUser(username: string, password: string): Promise<AuthenticationResult> {
  console.log(`🔐 Authentication attempt for: ${username}`);
  
  try {
    // Find user by username or email
    let user = userStore.findByUsername(username.toLowerCase());
    if (!user) {
      // Try finding by email if username lookup failed
      user = userStore.findByEmail(username.toLowerCase());
    }
    
    // User not found
    if (!user) {
      console.log(`❌ Authentication failed: User not found - ${username}`);
      return {
        success: false,
        error: 'Invalid username or password'
      };
    }
    
    // Check if user account is active
    if (!user.isActive) {
      console.log(`❌ Authentication failed: Account disabled - ${username}`);
      return {
        success: false,
        error: 'Account is disabled'
      };
    }
    
    // Verify password
    const isPasswordValid = await verifyPassword(password, user.passwordHash);
    
    if (!isPasswordValid) {
      console.log(`❌ Authentication failed: Invalid password - ${username}`);
      return {
        success: false,
        error: 'Invalid username or password'
      };
    }
    
    // Update last login timestamp
    const updatedUser = userStore.update(user.id, { 
      lastLoginAt: new Date() 
    });
    
    console.log(`✅ Authentication successful: ${username} (${user.id})`);
    return {
      success: true,
      user: updatedUser || user
    };
    
  } catch (error) {
    console.error('❌ Authentication error:', error);
    return {
      success: false,
      error: 'Authentication failed due to server error'
    };
  }
}

/**
 * Get user by ID
 * 
 * @param userId User identifier
 * @returns User or undefined if not found
 */
export function getUserById(userId: string): User | undefined {
  return userStore.findById(userId);
}

/**
 * Get user profile for OIDC claims
 * 
 * Returns user profile information suitable for OIDC ID tokens and UserInfo endpoint.
 * Excludes sensitive information like password hash.
 * 
 * @param userId User identifier
 * @returns User profile or undefined if not found
 */
export function getUserProfile(userId: string): Omit<User, 'passwordHash'> | undefined {
  const user = userStore.findById(userId);
  if (!user) return undefined;
  
  // Return user without password hash
  const { passwordHash, ...profile } = user;
  return profile;
}

/**
 * Update user profile information
 * 
 * @param userId User identifier
 * @param updates Profile updates to apply
 * @returns Updated user profile or undefined if not found
 */
export async function updateUserProfile(
  userId: string, 
  updates: UserProfileUpdate
): Promise<Omit<User, 'passwordHash'> | undefined> {
  console.log(`👤 Updating profile for user: ${userId}`);
  
  // Validate email if provided
  if (updates.email) {
    const emailValidation = validateEmail(updates.email);
    if (!emailValidation.isValid) {
      throw new Error(`Email validation failed: ${emailValidation.errors.join(', ')}`);
    }
    
    // Check email availability (exclude current user)
    const existingUser = userStore.findByEmail(updates.email.toLowerCase());
    if (existingUser && existingUser.id !== userId) {
      throw new Error(`Email '${updates.email}' is already registered`);
    }
    
    // Normalize email
    updates.email = updates.email.toLowerCase();
  }
  
  // Update user
  const updatedUser = userStore.update(userId, updates);
  if (!updatedUser) return undefined;
  
  // Return without password hash
  const { passwordHash, ...profile } = updatedUser;
  console.log(`✅ Profile updated for user: ${userId}`);
  return profile;
}

/**
 * Delete user account
 * 
 * @param userId User identifier
 * @returns True if deleted, false if not found
 */
export function deleteUser(userId: string): boolean {
  console.log(`🗑️  Deleting user: ${userId}`);
  return userStore.delete(userId);
}

/**
 * Get all users (for admin/debug purposes)
 * 
 * @returns Array of all users (without password hashes)
 */
export function getAllUsers(): Omit<User, 'passwordHash'>[] {
  return userStore.getAll().map(user => {
    const { passwordHash, ...profile } = user;
    return profile;
  });
}

/**
 * Create test users for development
 * 
 * Creates hardcoded test users with known credentials for development and testing.
 * Should not be used in production.
 */
export async function createTestUsers(): Promise<void> {
  console.log('👥 Creating test users for development...');
  
  const testUsers = [
    {
      username: 'testuser',
      email: 'test@example.com',
      password: 'password123',
      name: 'Test User'
    },
    {
      username: 'alice',
      email: 'alice@example.com', 
      password: 'alice123',
      name: 'Alice Johnson'
    },
    {
      username: 'bob',
      email: 'bob@example.com',
      password: 'bob123', 
      name: 'Bob Smith'
    },
    {
      username: 'admin',
      email: 'admin@example.com',
      password: 'admin123',
      name: 'Administrator'
    }
  ];
  
  for (const userData of testUsers) {
    try {
      // Check if user already exists
      if (!isUsernameAvailable(userData.username)) {
        console.log(`👤 Test user already exists: ${userData.username}`);
        continue;
      }
      
      await registerUser(userData);
      console.log(`👤 Created test user: ${userData.username} / ${userData.email}`);
    } catch (error) {
      console.error(`❌ Failed to create test user ${userData.username}:`, error);
    }
  }
  
  console.log('✅ Test users setup complete');
}

/**
 * Log security event (placeholder for production audit logging)
 * 
 * In production, this would write to audit logs for security monitoring.
 * 
 * @param userId User identifier
 * @param event Security event description
 * @param metadata Additional event metadata
 */
export function logSecurityEvent(
  userId: string, 
  event: string, 
  metadata?: Record<string, any>
): void {
  // In production, write to audit log system
  console.log(`🔒 Security Event - User: ${userId}, Event: ${event}`, metadata);
}

/**
 * Initialize user service
 * 
 * Creates test users in development environment.
 */
export async function initializeUserService(): Promise<void> {
  if (process.env.NODE_ENV === 'development') {
    await createTestUsers();
  }
}