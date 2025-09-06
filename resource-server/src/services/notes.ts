/**
 * Notes Business Logic Service
 * 
 * Implements business rules, validation, and orchestration for notes management
 * in the OAuth 2.0 resource server. Provides a clean separation between
 * HTTP handling (routes) and data operations (storage).
 * 
 * Business Logic Architecture:
 * 
 *    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
 *    │  Notes Routes   │───→│ Notes Service   │───→│ Memory Storage  │
 *    │ (HTTP Layer)    │    │ (Business Logic)│    │ (Data Layer)    │
 *    │                 │    │                 │    │                 │
 *    │ • Request       │    │ • Validation    │    │ • CRUD Ops      │
 *    │   parsing       │    │ • User isolation│    │ • Data persist  │
 *    │ • Response      │    │ • Business rules│    │ • Query methods │
 *    │   formatting    │    │ • Error handling│    │                 │
 *    │ • HTTP status   │    │ • Permissions   │    │                 │
 *    │   codes         │    │   checking      │    │                 │
 *    └─────────────────┘    └─────────────────┘    └─────────────────┘
 * 
 * Key Responsibilities:
 * 
 * 1. **Input Validation**: Ensure note data meets business requirements
 * 2. **User Isolation**: Enforce data ownership (users can only access their notes)
 * 3. **Business Rules**: Apply domain-specific logic and constraints
 * 4. **Error Handling**: Convert storage errors to meaningful business errors
 * 5. **Data Sanitization**: Clean and normalize user input
 * 
 * OAuth 2.0 Integration:
 * 
 * This service uses the `sub` (subject) claim from validated JWT tokens to:
 * - Isolate user data (notes belong to specific users)
 * - Enforce ownership rules (users can only modify their own notes)
 * - Audit operations (track which user performed which action)
 * 
 * The service assumes authentication has already occurred and user ID
 * is provided as a parameter from the authenticated request context.
 */

import storage, { Note } from '../storage/memory';

/**
 * Business validation errors with specific error codes
 * for consistent error handling across the application
 */
class NotesBusinessError extends Error {
  constructor(
    public code: 'VALIDATION_ERROR' | 'NOT_FOUND' | 'UNAUTHORIZED' | 'CONSTRAINT_VIOLATION',
    public message: string,
    public field?: string
  ) {
    super(message);
    this.name = 'NotesBusinessError';
  }
}

/**
 * Input validation interface for creating notes
 */
interface CreateNoteInput {
  title: string;
  content: string;
}

/**
 * Input validation interface for updating notes
 */
interface UpdateNoteInput {
  title?: string;
  content?: string;
}

/**
 * Service response wrapper for consistent API responses
 */
interface ServiceResponse<T> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    field?: string;
  };
}

/**
 * Notes business logic service implementing domain rules and validation.
 * 
 * This service layer provides:
 * - Input validation and sanitization
 * - Business rule enforcement
 * - User data isolation
 * - Consistent error handling
 * - Data transformation
 * 
 * All methods require a `userId` parameter (from JWT `sub` claim) to ensure
 * proper user isolation and data ownership validation.
 */
class NotesService {
  
  /**
   * Creates a new note with validation and user ownership.
   * 
   * Business Rules:
   * - Title: Required, 1-200 characters, no HTML
   * - Content: Required, 1-10000 characters, basic sanitization
   * - User: Must be authenticated (userId from JWT sub claim)
   * - Timestamps: Auto-generated
   * 
   * @param userId - User ID from JWT 'sub' claim (ensures data ownership)
   * @param input - Note creation data
   * @returns Created note or error details
   */
  async createNote(userId: string, input: CreateNoteInput): Promise<ServiceResponse<Note>> {
    try {
      // Step 1: Validate user ID (should come from authenticated request)
      if (!userId || typeof userId !== 'string' || userId.trim().length === 0) {
        throw new NotesBusinessError('VALIDATION_ERROR', 'Valid user ID is required', 'userId');
      }

      // Step 2: Validate and sanitize input data
      const validatedInput = this.validateCreateInput(input);
      
      // Step 3: Apply business rules and constraints
      this.applyBusinessRules(validatedInput);
      
      // Step 4: Create note with user ownership
      const note = storage.create({
        title: validatedInput.title,
        content: validatedInput.content,
        userId: userId.trim()
      });

      return {
        success: true,
        data: note
      };

    } catch (error) {
      return this.handleServiceError(error);
    }
  }

  /**
   * Retrieves all notes for a specific user.
   * 
   * User Isolation:
   * Only returns notes where note.userId === provided userId.
   * This ensures users can only see their own notes, implementing
   * proper data isolation for multi-tenant OAuth 2.0 resource server.
   * 
   * @param userId - User ID from JWT 'sub' claim
   * @returns Array of user's notes
   */
  async getUserNotes(userId: string): Promise<ServiceResponse<Note[]>> {
    try {
      if (!userId || typeof userId !== 'string' || userId.trim().length === 0) {
        throw new NotesBusinessError('VALIDATION_ERROR', 'Valid user ID is required', 'userId');
      }

      // Use storage method that filters by user ID for data isolation
      const notes = storage.findByUserId(userId.trim());
      
      return {
        success: true,
        data: notes
      };

    } catch (error) {
      return this.handleServiceError(error);
    }
  }

  /**
   * Retrieves a specific note by ID with user ownership validation.
   * 
   * Security: Ensures users can only access notes they own.
   * Even if a user knows another user's note ID, they cannot access it.
   * 
   * @param userId - User ID from JWT 'sub' claim
   * @param noteId - Note identifier
   * @returns Note if found and owned by user, error otherwise
   */
  async getNoteById(userId: string, noteId: string): Promise<ServiceResponse<Note>> {
    try {
      if (!userId || typeof userId !== 'string' || userId.trim().length === 0) {
        throw new NotesBusinessError('VALIDATION_ERROR', 'Valid user ID is required', 'userId');
      }

      if (!noteId || typeof noteId !== 'string' || noteId.trim().length === 0) {
        throw new NotesBusinessError('VALIDATION_ERROR', 'Valid note ID is required', 'noteId');
      }

      // Step 1: Find note by ID
      const note = storage.findById(noteId.trim());
      
      if (!note) {
        throw new NotesBusinessError('NOT_FOUND', 'Note not found');
      }

      // Step 2: Verify user ownership (critical security check)
      if (note.userId !== userId.trim()) {
        // Return "not found" instead of "unauthorized" to prevent information leakage
        // This prevents users from discovering if note IDs exist for other users
        throw new NotesBusinessError('NOT_FOUND', 'Note not found');
      }

      return {
        success: true,
        data: note
      };

    } catch (error) {
      return this.handleServiceError(error);
    }
  }

  /**
   * Updates a note with validation and ownership verification.
   * 
   * Business Rules:
   * - User can only update their own notes
   * - At least one field must be provided for update
   * - Same validation rules as creation apply to updated fields
   * - updatedAt timestamp is automatically set
   * 
   * @param userId - User ID from JWT 'sub' claim
   * @param noteId - Note identifier
   * @param input - Partial note data to update
   * @returns Updated note or error details
   */
  async updateNote(userId: string, noteId: string, input: UpdateNoteInput): Promise<ServiceResponse<Note>> {
    try {
      if (!userId || typeof userId !== 'string' || userId.trim().length === 0) {
        throw new NotesBusinessError('VALIDATION_ERROR', 'Valid user ID is required', 'userId');
      }

      if (!noteId || typeof noteId !== 'string' || noteId.trim().length === 0) {
        throw new NotesBusinessError('VALIDATION_ERROR', 'Valid note ID is required', 'noteId');
      }

      // Step 1: Verify note exists and user owns it  
      const existingNoteResult = await this.getNoteById(userId, noteId);
      if (!existingNoteResult.success) {
        return {
          success: false,
          error: existingNoteResult.error
        };
      }

      // Step 2: Validate update input
      const validatedInput = this.validateUpdateInput(input);
      
      if (Object.keys(validatedInput).length === 0) {
        throw new NotesBusinessError('VALIDATION_ERROR', 'At least one field (title or content) must be provided for update');
      }

      // Step 3: Apply business rules to update data
      this.applyBusinessRules(validatedInput);

      // Step 4: Perform update (storage handles immutable update + timestamp)
      const updatedNote = storage.update(noteId.trim(), validatedInput);
      
      if (!updatedNote) {
        // This should not happen if getNoteById succeeded, but handle gracefully
        throw new NotesBusinessError('NOT_FOUND', 'Note not found during update');
      }

      return {
        success: true,
        data: updatedNote
      };

    } catch (error) {
      return this.handleServiceError(error);
    }
  }

  /**
   * Deletes a note with ownership verification.
   * 
   * Security: Users can only delete their own notes.
   * Soft delete could be implemented here for audit trails if needed.
   * 
   * @param userId - User ID from JWT 'sub' claim
   * @param noteId - Note identifier
   * @returns Success status or error details
   */
  async deleteNote(userId: string, noteId: string): Promise<ServiceResponse<void>> {
    try {
      if (!userId || typeof userId !== 'string' || userId.trim().length === 0) {
        throw new NotesBusinessError('VALIDATION_ERROR', 'Valid user ID is required', 'userId');
      }

      if (!noteId || typeof noteId !== 'string' || noteId.trim().length === 0) {
        throw new NotesBusinessError('VALIDATION_ERROR', 'Valid note ID is required', 'noteId');
      }

      // Step 1: Verify note exists and user owns it
      const existingNoteResult = await this.getNoteById(userId, noteId);
      if (!existingNoteResult.success) {
        return {
          success: false,
          error: existingNoteResult.error
        };
      }

      // Step 2: Perform deletion
      const deleted = storage.delete(noteId.trim());
      
      if (!deleted) {
        throw new NotesBusinessError('NOT_FOUND', 'Note not found during deletion');
      }

      return {
        success: true
      };

    } catch (error) {
      return this.handleServiceError(error);
    }
  }

  /**
   * Validates input for note creation.
   * Applies business rules for data quality and security.
   */
  private validateCreateInput(input: CreateNoteInput): CreateNoteInput {
    if (!input || typeof input !== 'object') {
      throw new NotesBusinessError('VALIDATION_ERROR', 'Note data is required');
    }

    // Validate title
    if (!input.title || typeof input.title !== 'string') {
      throw new NotesBusinessError('VALIDATION_ERROR', 'Title is required and must be a string', 'title');
    }

    const trimmedTitle = input.title.trim();
    if (trimmedTitle.length === 0) {
      throw new NotesBusinessError('VALIDATION_ERROR', 'Title cannot be empty', 'title');
    }

    if (trimmedTitle.length > 200) {
      throw new NotesBusinessError('VALIDATION_ERROR', 'Title must be 200 characters or less', 'title');
    }

    // Validate content
    if (!input.content || typeof input.content !== 'string') {
      throw new NotesBusinessError('VALIDATION_ERROR', 'Content is required and must be a string', 'content');
    }

    const trimmedContent = input.content.trim();
    if (trimmedContent.length === 0) {
      throw new NotesBusinessError('VALIDATION_ERROR', 'Content cannot be empty', 'content');
    }

    if (trimmedContent.length > 10000) {
      throw new NotesBusinessError('VALIDATION_ERROR', 'Content must be 10,000 characters or less', 'content');
    }

    return {
      title: trimmedTitle,
      content: trimmedContent
    };
  }

  /**
   * Validates input for note updates.
   * Similar to create validation but allows partial updates.
   */
  private validateUpdateInput(input: UpdateNoteInput): UpdateNoteInput {
    if (!input || typeof input !== 'object') {
      throw new NotesBusinessError('VALIDATION_ERROR', 'Update data is required');
    }

    const validated: UpdateNoteInput = {};

    // Validate title if provided
    if (input.title !== undefined) {
      if (typeof input.title !== 'string') {
        throw new NotesBusinessError('VALIDATION_ERROR', 'Title must be a string', 'title');
      }

      const trimmedTitle = input.title.trim();
      if (trimmedTitle.length === 0) {
        throw new NotesBusinessError('VALIDATION_ERROR', 'Title cannot be empty', 'title');
      }

      if (trimmedTitle.length > 200) {
        throw new NotesBusinessError('VALIDATION_ERROR', 'Title must be 200 characters or less', 'title');
      }

      validated.title = trimmedTitle;
    }

    // Validate content if provided
    if (input.content !== undefined) {
      if (typeof input.content !== 'string') {
        throw new NotesBusinessError('VALIDATION_ERROR', 'Content must be a string', 'content');
      }

      const trimmedContent = input.content.trim();
      if (trimmedContent.length === 0) {
        throw new NotesBusinessError('VALIDATION_ERROR', 'Content cannot be empty', 'content');
      }

      if (trimmedContent.length > 10000) {
        throw new NotesBusinessError('VALIDATION_ERROR', 'Content must be 10,000 characters or less', 'content');
      }

      validated.content = trimmedContent;
    }

    return validated;
  }

  /**
   * Applies additional business rules and constraints.
   * Extensible for future business requirements.
   */
  private applyBusinessRules(input: CreateNoteInput | UpdateNoteInput): void {
    // Business Rule: No HTML content allowed (basic XSS prevention)
    if (input.title && this.containsHtml(input.title)) {
      throw new NotesBusinessError('VALIDATION_ERROR', 'Title cannot contain HTML', 'title');
    }

    if (input.content && this.containsHtml(input.content)) {
      throw new NotesBusinessError('VALIDATION_ERROR', 'Content cannot contain HTML', 'content');
    }

    // Business Rule: No profanity (placeholder for future implementation)
    // if (this.containsProfanity(input.title) || this.containsProfanity(input.content)) {
    //   throw new NotesBusinessError('CONSTRAINT_VIOLATION', 'Content violates community guidelines');
    // }

    // Business Rule: Rate limiting could be implemented here
    // Business Rule: Content filtering could be implemented here
    // Business Rule: Duplicate detection could be implemented here
  }

  /**
   * Basic HTML detection for security (prevents XSS in note content)
   */
  private containsHtml(text: string): boolean {
    const htmlPattern = /<[^>]*>/;
    return htmlPattern.test(text);
  }

  /**
   * Converts internal errors to standardized service responses
   */
  private handleServiceError(error: unknown): ServiceResponse<never> {
    if (error instanceof NotesBusinessError) {
      return {
        success: false,
        error: {
          code: error.code,
          message: error.message,
          field: error.field
        }
      };
    }

    // Handle unexpected errors (log them but don't expose internals)
    console.error('Unexpected error in NotesService:', error);
    
    return {
      success: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: 'An unexpected error occurred'
      }
    };
  }
}

// Export singleton instance for consistent usage across the application
export default new NotesService();
export { CreateNoteInput, UpdateNoteInput, ServiceResponse };
export type { NotesBusinessError };