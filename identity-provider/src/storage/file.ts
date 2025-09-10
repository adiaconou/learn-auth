/**
 * File-Based User Storage for OAuth 2.0 + OIDC Identity Provider
 * 
 * Simple file-based storage implementation for user accounts during development.
 * Uses plain text format for easy inspection and manual account creation.
 * 
 * File Format (filesystem/users.txt):
 * ```
 * # Users Database - Plain Text Format
 * # Format: id|username|email|passwordHash|isActive|createdAt
 * user1|alice|alice@example.com|password123|true|2024-01-01T00:00:00.000Z
 * user2|bob|bob@example.com|secret456|true|2024-01-01T00:00:00.000Z
 * ```
 * 
 * Security Note:
 * This is for development/learning only. Production systems should:
 * - Use proper databases (PostgreSQL, MongoDB, etc.)
 * - Hash passwords with bcrypt or similar
 * - Implement proper validation and sanitization
 * - Use encrypted storage
 * - Add audit logging
 */

import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join } from 'path';
import { User } from './models';

const USERS_FILE_PATH = join(__dirname, '../../filesystem/users.txt');

/**
 * Load users from text file
 * 
 * Reads the users.txt file and parses each line into User objects.
 * Skips empty lines and comments (lines starting with #).
 * 
 * @returns Array of User objects from file
 */
function loadUsersFromFile(): User[] {
  try {
    if (!existsSync(USERS_FILE_PATH)) {
      console.log('📄 No users file found, starting with empty user database');
      return [];
    }

    const fileContent = readFileSync(USERS_FILE_PATH, 'utf-8');
    const lines = fileContent.split('\n').filter(line => line.trim() && !line.startsWith('#'));
    
    const users: User[] = [];
    
    for (const line of lines) {
      const parts = line.split('|');
      if (parts.length !== 6) {
        console.warn(`⚠️ Skipping invalid line in users.txt: ${line}`);
        continue;
      }
      
      const [id, username, email, passwordHash, isActive, createdAt] = parts;
      
      users.push({
        id: id.trim(),
        username: username.trim(),
        email: email.trim(),
        passwordHash: passwordHash.trim(), // Plain text for development (should be hashed in production)
        isActive: isActive.trim() === 'true',
        createdAt: new Date(createdAt.trim())
      });
    }
    
    console.log(`📄 Loaded ${users.length} users from file storage`);
    return users;
    
  } catch (error) {
    console.error('❌ Failed to load users from file:', error);
    return [];
  }
}

/**
 * Save users to text file
 * 
 * Writes the current user array to the users.txt file in the specified format.
 * Creates the data directory if it doesn't exist.
 * 
 * @param users Array of User objects to save
 */
function saveUsersToFile(users: User[]): void {
  try {
    // Ensure filesystem directory exists
    const filesystemDir = join(__dirname, '../../filesystem');
    if (!existsSync(filesystemDir)) {
      require('fs').mkdirSync(filesystemDir, { recursive: true });
    }
    
    // Create file content with header
    const lines = [
      '# Users Database - Plain Text Format',
      '# Format: id|username|email|passwordHash|isActive|createdAt',
      '# WARNING: This is for development only - passwords are stored in plain text!',
      ''
    ];
    
    // Add user lines
    for (const user of users) {
      const line = [
        user.id,
        user.username,
        user.email,
        user.passwordHash, // Plain text for development (should be hashed in production)
        user.isActive.toString(),
        user.createdAt.toISOString()
      ].join('|');
      
      lines.push(line);
    }
    
    writeFileSync(USERS_FILE_PATH, lines.join('\n'), 'utf-8');
    console.log(`💾 Saved ${users.length} users to file storage`);
    
  } catch (error) {
    console.error('❌ Failed to save users to file:', error);
    throw new Error('Failed to save users to file storage');
  }
}

/**
 * File-Based User Storage Operations
 * 
 * Provides the same interface as the in-memory userStore but persists
 * data to a text file for development and testing purposes.
 */
export const fileUserStore = {
  /**
   * Create a new user account
   * 
   * @param user User data to store
   * @throws Error if username or email already exists
   */
  create(user: User): void {
    const users = loadUsersFromFile();
    
    // Check for duplicate username
    if (users.some(u => u.username === user.username)) {
      throw new Error(`Username '${user.username}' already exists`);
    }
    
    // Check for duplicate email
    if (users.some(u => u.email === user.email)) {
      throw new Error(`Email '${user.email}' already exists`);
    }
    
    // Add new user
    users.push(user);
    saveUsersToFile(users);
    
    console.log(`👤 Created user: ${user.username} (${user.id})`);
  },
  
  /**
   * Find user by ID
   * 
   * @param userId User identifier
   * @returns User or undefined if not found
   */
  findById(userId: string): User | undefined {
    const users = loadUsersFromFile();
    return users.find(user => user.id === userId);
  },
  
  /**
   * Find user by username (for login)
   * 
   * @param username Username to search for
   * @returns User or undefined if not found
   */
  findByUsername(username: string): User | undefined {
    const users = loadUsersFromFile();
    return users.find(user => user.username === username);
  },
  
  /**
   * Find user by email address
   * 
   * @param email Email to search for  
   * @returns User or undefined if not found
   */
  findByEmail(email: string): User | undefined {
    const users = loadUsersFromFile();
    return users.find(user => user.email === email);
  },
  
  /**
   * Update user information
   * 
   * @param userId User ID to update
   * @param updates Partial user data to update
   * @returns Updated user or undefined if not found
   */
  update(userId: string, updates: Partial<User>): User | undefined {
    const users = loadUsersFromFile();
    const userIndex = users.findIndex(user => user.id === userId);
    
    if (userIndex === -1) return undefined;
    
    const updatedUser = { ...users[userIndex], ...updates };
    users[userIndex] = updatedUser;
    
    saveUsersToFile(users);
    
    console.log(`👤 Updated user: ${updatedUser.username} (${userId})`);
    return updatedUser;
  },
  
  /**
   * Get all users (for admin/debug purposes)
   * 
   * @returns Array of all users
   */
  getAll(): User[] {
    return loadUsersFromFile();
  },
  
  /**
   * Delete user account
   * 
   * @param userId User ID to delete
   * @returns True if deleted, false if not found
   */
  delete(userId: string): boolean {
    const users = loadUsersFromFile();
    const userIndex = users.findIndex(user => user.id === userId);
    
    if (userIndex === -1) return false;
    
    const deletedUser = users[userIndex];
    users.splice(userIndex, 1);
    
    saveUsersToFile(users);
    
    console.log(`👤 Deleted user: ${deletedUser.username} (${userId})`);
    return true;
  }
};