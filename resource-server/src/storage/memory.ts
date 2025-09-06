/**
 * In-Memory Notes Storage
 * 
 * Simple in-memory storage for notes using JavaScript Map. Implements CRUD operations
 * with user isolation for OAuth 2.0 resource server. In production, replace with
 * proper database (PostgreSQL, MongoDB, etc.).
 */

/**
 * Note data model for OAuth 2.0 resource server
 */
interface Note {
  id: string;           // Unique identifier
  title: string;        // Note title (max 200 chars)
  content: string;      // Note content (max 10k chars)  
  createdAt: Date;      // Creation timestamp
  updatedAt: Date;      // Last modified timestamp
  userId: string;       // Owner ID (from JWT 'sub' claim)
}

/**
 * Repository pattern implementation for note storage.
 * Features: user isolation, automatic timestamps, immutable updates.
 */
class MemoryNotesStorage {
  private notes: Map<string, Note> = new Map();

  /**
   * Creates a new note with auto-generated ID and timestamps
   */
  create(noteData: Omit<Note, 'id' | 'createdAt' | 'updatedAt'>): Note {
    const now = new Date();
    const note: Note = {
      ...noteData,
      id: this.generateId(),
      createdAt: now,
      updatedAt: now
    };
    
    this.notes.set(note.id, note);
    return note;
  }

  /**
   * Returns all notes (no filtering - use findByUserId for user isolation)
   */
  findAll(): Note[] {
    return Array.from(this.notes.values());
  }

  /**
   * Finds note by ID
   */
  findById(id: string): Note | undefined {
    return this.notes.get(id);
  }

  /**
   * Updates note with immutable approach (creates new object)
   */
  update(id: string, updates: Partial<Pick<Note, 'title' | 'content'>>): Note | undefined {
    const existingNote = this.notes.get(id);
    if (!existingNote) {
      return undefined;
    }

    const updatedNote: Note = {
      ...existingNote,
      ...updates,
      updatedAt: new Date()
    };

    this.notes.set(id, updatedNote);
    return updatedNote;
  }

  /**
   * Deletes note by ID
   */
  delete(id: string): boolean {
    return this.notes.delete(id);
  }

  /**
   * Finds all notes for a specific user (implements OAuth 2.0 user isolation)
   */
  findByUserId(userId: string): Note[] {
    return Array.from(this.notes.values())
      .filter(note => note.userId === userId);
  }

  /**
   * Generates simple unique ID (production: use UUID v4 or database auto-increment)
   */
  private generateId(): string {
    return Math.random().toString(36).substring(2) + Date.now().toString(36);
  }
}

// Export a singleton instance of the storage class
// This ensures all parts of the application use the same storage instance
// and share the same in-memory data
export default new MemoryNotesStorage();

// Export the Note interface so other modules can use it for type checking
export { Note };