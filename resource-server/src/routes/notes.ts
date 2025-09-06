/**
 * Notes API Routes
 * 
 * Express router implementing CRUD endpoints for notes management in OAuth 2.0 resource server.
 * Provides RESTful API with proper authentication, authorization, and error handling.
 * 
 * Middleware Chain Architecture:
 * 
 *   HTTP Request
 *        │
 *        ▼
 *   ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
 *   │ CORS Middleware │───→│ Auth Middleware │───→│ Scope Middleware│───→│  Route Handler  │
 *   │                 │    │                 │    │                 │    │                 │
 *   │ • Cross-origin  │    │ • JWT validation│    │ • Scope check   │    │ • Business      │
 *   │   requests      │    │ • Token decode  │    │ • notes:read    │    │   logic call    │
 *   │ • Preflight     │    │ • User context  │    │ • notes:write   │    │ • Response      │
 *   │   handling      │    │   attachment    │    │ • 403 on fail   │    │   formatting    │
 *   │                 │    │ • 401 on fail   │    │                 │    │ • Error         │
 *   │                 │    │                 │    │                 │    │   handling      │
 *   └─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
 *                                   │                       │                       │
 *                                   ▼                       ▼                       ▼
 *                            req.user = {              Validates:              Calls:
 *                              sub: "user123"          • notes:read            • notesService
 *                              scope: "notes:read..."  • notes:write           • Returns JSON
 *                              iss: "http://..."       • Blocks unauthorized   • HTTP status
 *                              aud: "notes-api"        
 *                            }
 * 
 * API Endpoints & Required Scopes:
 * 
 * GET    /notes           - List all user's notes          (Scope: notes:read)
 * POST   /notes           - Create new note                (Scope: notes:write)  
 * GET    /notes/:id       - Get specific note by ID        (Scope: notes:read)
 * PUT    /notes/:id       - Update existing note           (Scope: notes:write)
 * DELETE /notes/:id       - Delete note                    (Scope: notes:write)
 * 
 * OAuth 2.0 Integration:
 * 
 * 1. **Authentication**: All endpoints require valid JWT Bearer token
 * 2. **Authorization**: Each endpoint enforces specific OAuth 2.0 scopes
 * 3. **User Isolation**: Operations are restricted to authenticated user's data
 * 4. **Error Handling**: Returns proper OAuth 2.0 error responses (401/403)
 * 
 * Request/Response Flow Example:
 * 
 * POST /notes
 * Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
 * Content-Type: application/json
 * 
 * {
 *   "title": "Meeting Notes",
 *   "content": "Discussed OAuth 2.0 implementation..."
 * }
 * 
 * ↓ Auth Middleware validates JWT and extracts user
 * ↓ Scope Middleware checks for "notes:write" scope  
 * ↓ Route Handler calls notesService.createNote(userId, data)
 * 
 * Response:
 * HTTP 201 Created
 * Content-Type: application/json
 * 
 * {
 *   "id": "abc123",
 *   "title": "Meeting Notes", 
 *   "content": "Discussed OAuth 2.0 implementation...",
 *   "userId": "user123",
 *   "createdAt": "2024-01-15T10:30:00Z",
 *   "updatedAt": "2024-01-15T10:30:00Z"
 * }
 */

import { Request, Router, Response } from 'express';
import { AuthenticatedRequest } from '../middleware/auth';
import { requireScope } from '../middleware/scope';
import notesService, { CreateNoteInput, UpdateNoteInput, ServiceResponse } from '../services/notes';
import type { Note } from '../storage/memory';

/**
 * HTTP error response for API endpoints
 */
interface ApiErrorResponse {
  error: string;
  error_description: string;
  field?: string;
}

/**
 * HTTP success response wrapper for consistent API responses
 */
interface ApiSuccessResponse<T> {
  data: T;
}

const router = Router();

/**
 * GET /notes - Retrieve all notes for authenticated user
 * 
 * Requires: notes:read scope
 * Returns: Array of user's notes
 * 
 * Security: Only returns notes owned by the authenticated user (req.user.sub)
 * 
 * Example Response:
 * {
 *   "data": [
 *     {
 *       "id": "abc123",
 *       "title": "My Note",
 *       "content": "Note content...", 
 *       "userId": "user123",
 *       "createdAt": "2024-01-15T10:30:00Z",
 *       "updatedAt": "2024-01-15T10:30:00Z"
 *     }
 *   ]
 * }
 */
router.get(
  '/', 
  requireScope(['notes:read']), 
  async (req: Request, res: Response): Promise<void> => {
    try {
      // Cast to AuthenticatedRequest to access user property
      const authReq = req as AuthenticatedRequest;
      // Extract user ID from authenticated JWT token
      const userId = authReq.user.sub;
      
      // Call business logic service
      const result = await notesService.getUserNotes(userId);
      
      if (!result.success) {
        handleServiceError(res, result);
        return;
      }
      
      // Return successful response with user's notes
      res.status(200).json({
        data: result.data || []
      });
      
    } catch (error) {
      console.error('Error in GET /notes:', error);
      res.status(500).json({
        error: 'internal_server_error',
        error_description: 'An unexpected error occurred while retrieving notes'
      });
    }
  }
);

/**
 * POST /notes - Create new note
 * 
 * Requires: notes:write scope
 * Body: { title: string, content: string }
 * Returns: Created note with generated ID and timestamps
 * 
 * Validation:
 * - Title: Required, 1-200 characters, no HTML
 * - Content: Required, 1-10000 characters, no HTML
 * - User: Automatically set from JWT sub claim
 * 
 * Example Request:
 * {
 *   "title": "Meeting Notes",
 *   "content": "Discussed API implementation..."
 * }
 * 
 * Example Response:
 * HTTP 201 Created
 * {
 *   "data": {
 *     "id": "def456",
 *     "title": "Meeting Notes",
 *     "content": "Discussed API implementation...",
 *     "userId": "user123", 
 *     "createdAt": "2024-01-15T10:30:00Z",
 *     "updatedAt": "2024-01-15T10:30:00Z"
 *   }
 * }
 */
router.post(
  '/',
  requireScope(['notes:write']),
  async (req: Request, res: Response): Promise<void> => {
    try {
      // Cast to AuthenticatedRequest to access user property
      const authReq = req as AuthenticatedRequest;
      // Extract user ID from authenticated JWT token
      const userId = authReq.user.sub;
      
      // Validate request body structure
      if (!req.body || typeof req.body !== 'object') {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'Request body must be a valid JSON object'
        });
        return;
      }
      
      // Extract note data from request body
      const noteInput: CreateNoteInput = {
        title: req.body.title,
        content: req.body.content
      };
      
      // Call business logic service
      const result = await notesService.createNote(userId, noteInput);
      
      if (!result.success) {
        handleServiceError(res, result);
        return;
      }
      
      // Return created note with 201 Created status
      res.status(201).json({
        data: result.data!
      });
      
    } catch (error) {
      console.error('Error in POST /notes:', error);
      res.status(500).json({
        error: 'internal_server_error', 
        error_description: 'An unexpected error occurred while creating the note'
      });
    }
  }
);

/**
 * GET /notes/:id - Retrieve specific note by ID
 * 
 * Requires: notes:read scope
 * Params: id (note identifier)
 * Returns: Single note if found and owned by user
 * 
 * Security: 
 * - Validates note ownership (note.userId === req.user.sub)
 * - Returns 404 if note doesn't exist OR user doesn't own it
 * - This prevents information leakage about other users' note IDs
 * 
 * Example Response:
 * {
 *   "data": {
 *     "id": "abc123", 
 *     "title": "My Note",
 *     "content": "Content...",
 *     "userId": "user123",
 *     "createdAt": "2024-01-15T10:30:00Z", 
 *     "updatedAt": "2024-01-15T11:45:00Z"
 *   }
 * }
 */
router.get(
  '/:id',
  requireScope(['notes:read']),
  async (req: Request, res: Response): Promise<void> => {
    try {
      // Cast to AuthenticatedRequest to access user property
      const authReq = req as AuthenticatedRequest;
      // Extract user ID and note ID
      const userId = authReq.user.sub;
      const noteId = req.params.id;
      
      // Validate note ID parameter
      if (!noteId || noteId.trim().length === 0) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'Note ID is required'
        });
        return;
      }
      
      // Call business logic service
      const result = await notesService.getNoteById(userId, noteId);
      
      if (!result.success) {
        handleServiceError(res, result);
        return;
      }
      
      // Return found note
      res.status(200).json({
        data: result.data!
      });
      
    } catch (error) {
      console.error('Error in GET /notes/:id:', error);
      res.status(500).json({
        error: 'internal_server_error',
        error_description: 'An unexpected error occurred while retrieving the note'
      });
    }
  }
);

/**
 * PUT /notes/:id - Update existing note
 * 
 * Requires: notes:write scope
 * Params: id (note identifier)
 * Body: { title?: string, content?: string } (partial update)
 * Returns: Updated note with new updatedAt timestamp
 * 
 * Security:
 * - Validates note ownership before allowing updates
 * - Only allows updating title and/or content fields
 * - Preserves original createdAt, id, and userId
 * 
 * Validation:
 * - At least one field (title or content) must be provided
 * - Same validation rules as POST apply to provided fields
 * 
 * Example Request:
 * {
 *   "title": "Updated Meeting Notes",
 *   "content": "Added more details about OAuth 2.0..."
 * }
 * 
 * Example Response:
 * {
 *   "data": {
 *     "id": "abc123",
 *     "title": "Updated Meeting Notes", 
 *     "content": "Added more details about OAuth 2.0...",
 *     "userId": "user123",
 *     "createdAt": "2024-01-15T10:30:00Z",
 *     "updatedAt": "2024-01-15T14:20:00Z"  // Updated timestamp
 *   }
 * }
 */
router.put(
  '/:id',
  requireScope(['notes:write']),
  async (req: Request, res: Response): Promise<void> => {
    try {
      // Cast to AuthenticatedRequest to access user property
      const authReq = req as AuthenticatedRequest;
      // Extract user ID and note ID
      const userId = authReq.user.sub;
      const noteId = req.params.id;
      
      // Validate note ID parameter
      if (!noteId || noteId.trim().length === 0) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'Note ID is required'
        });
        return;
      }
      
      // Validate request body structure
      if (!req.body || typeof req.body !== 'object') {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'Request body must be a valid JSON object'
        });
        return;
      }
      
      // Extract update data from request body (partial update)
      const updateInput: UpdateNoteInput = {};
      
      if (req.body.title !== undefined) {
        updateInput.title = req.body.title;
      }
      
      if (req.body.content !== undefined) {
        updateInput.content = req.body.content;
      }
      
      // Call business logic service
      const result = await notesService.updateNote(userId, noteId, updateInput);
      
      if (!result.success) {
        handleServiceError(res, result);
        return;
      }
      
      // Return updated note
      res.status(200).json({
        data: result.data!
      });
      
    } catch (error) {
      console.error('Error in PUT /notes/:id:', error);
      res.status(500).json({
        error: 'internal_server_error',
        error_description: 'An unexpected error occurred while updating the note'
      });
    }
  }
);

/**
 * DELETE /notes/:id - Delete note
 * 
 * Requires: notes:write scope
 * Params: id (note identifier)  
 * Returns: 204 No Content on successful deletion
 * 
 * Security:
 * - Validates note ownership before allowing deletion
 * - Returns 404 if note doesn't exist OR user doesn't own it
 * - Permanent deletion (soft delete could be implemented for audit trails)
 * 
 * Example Response:
 * HTTP 204 No Content
 * (empty body)
 */
router.delete(
  '/:id',
  requireScope(['notes:write']),
  async (req: Request, res: Response): Promise<void> => {
    try {
      // Cast to AuthenticatedRequest to access user property
      const authReq = req as AuthenticatedRequest;
      // Extract user ID and note ID
      const userId = authReq.user.sub;
      const noteId = req.params.id;
      
      // Validate note ID parameter
      if (!noteId || noteId.trim().length === 0) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'Note ID is required'
        });
        return;
      }
      
      // Call business logic service
      const result = await notesService.deleteNote(userId, noteId);
      
      if (!result.success) {
        handleServiceError(res, result);
        return;
      }
      
      // Return 204 No Content (successful deletion, no response body)
      res.status(204).send();
      
    } catch (error) {
      console.error('Error in DELETE /notes/:id:', error);
      res.status(500).json({
        error: 'internal_server_error',
        error_description: 'An unexpected error occurred while deleting the note'
      });
    }
  }
);

/**
 * Converts service layer errors to appropriate HTTP responses.
 * 
 * Maps business logic error codes to HTTP status codes:
 * - VALIDATION_ERROR → 400 Bad Request
 * - NOT_FOUND → 404 Not Found  
 * - UNAUTHORIZED → 403 Forbidden
 * - CONSTRAINT_VIOLATION → 400 Bad Request
 * - INTERNAL_ERROR → 500 Internal Server Error
 * 
 * @param res - Express response object
 * @param serviceResult - Failed service result with error details
 */
function handleServiceError(
  res: Response<ApiErrorResponse>, 
  serviceResult: ServiceResponse<any>
): Response<ApiErrorResponse> {
  
  if (!serviceResult.error) {
    // Fallback for malformed service errors
    return res.status(500).json({
      error: 'internal_server_error',
      error_description: 'An unexpected error occurred'
    });
  }
  
  const { code, message, field } = serviceResult.error;
  
  switch (code) {
    case 'VALIDATION_ERROR':
      return res.status(400).json({
        error: 'invalid_request',
        error_description: message,
        field: field
      });
      
    case 'NOT_FOUND':
      return res.status(404).json({
        error: 'not_found', 
        error_description: message
      });
      
    case 'UNAUTHORIZED':
      return res.status(403).json({
        error: 'forbidden',
        error_description: message
      });
      
    case 'CONSTRAINT_VIOLATION':
      return res.status(400).json({
        error: 'constraint_violation',
        error_description: message
      });
      
    case 'INTERNAL_ERROR':
    default:
      return res.status(500).json({
        error: 'internal_server_error',
        error_description: 'An unexpected error occurred'
      });
  }
}

export default router;