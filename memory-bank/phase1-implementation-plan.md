# Phase 1: Resource Server Implementation Plan

## High-Level Design

### Overview
Build a REST API that serves as an OAuth 2.0 Resource Server, protecting a simple `/notes` resource with JWT access token validation and scope-based authorization. Implements PKCE (Proof Key for Code Exchange) flow for enhanced security in public clients.

### Core Components
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Client App    │───→│  Resource Server │───→│  Notes Storage  │
│                 │    │                  │    │   (in-memory)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌──────────────────┐
                       │  JWT Validation  │
                       │   + JWKS Check   │
                       └──────────────────┘
```

### Key Responsibilities
1. **Token Validation**: Verify JWT signature, issuer, audience, expiration
2. **Scope Authorization**: Enforce `notes:read` and `notes:write` permissions
3. **Resource Protection**: Secure CRUD operations on `/notes` endpoints
4. **Error Handling**: Return proper HTTP status codes (401 vs 403)
5. **PKCE Support**: Validate PKCE code verifiers for authorization code exchange

### OAuth 2.0 + PKCE Concepts

#### PKCE (Proof Key for Code Exchange) - RFC 7636
PKCE enhances OAuth 2.0 security for public clients (SPAs, mobile apps) that cannot securely store client secrets.

**Problem PKCE Solves:**
- Public clients can't store secrets securely
- Authorization codes can be intercepted (deep links, referrer headers)
- Malicious apps could steal authorization codes

**PKCE Flow:**
1. **Code Challenge Generation**: Client generates random `code_verifier` (43-128 chars)
2. **Code Challenge**: Client creates `code_challenge = SHA256(code_verifier)` 
3. **Authorization Request**: Client sends `code_challenge` + `code_challenge_method=S256`
4. **Authorization Code**: IdP returns code tied to the code_challenge
5. **Token Exchange**: Client sends `authorization_code` + original `code_verifier`
6. **Verification**: IdP verifies `SHA256(code_verifier) === stored_code_challenge`
7. **Token Issued**: If match, IdP issues access token

**Security Benefits:**
- Even if authorization code is stolen, attacker needs the `code_verifier`
- `code_verifier` never transmitted during authorization step
- Works without client secrets (perfect for SPAs/mobile apps)
- Backward compatible with confidential clients

**PKCE Parameters:**
- `code_verifier`: Random string (43-128 chars, unreguessable)
- `code_challenge`: SHA256 hash of code_verifier (Base64 URL-encoded)  
- `code_challenge_method`: Always "S256" (SHA256 hashing)

**Example PKCE Values:**
```javascript
// Client generates (never sent during authorization)
code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

// Client calculates and sends in authorization request
code_challenge = SHA256(code_verifier) = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
code_challenge_method = "S256"

// Later, client sends both code + verifier in token request
authorization_code = "abc123..."
code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
```

---

## Low-Level Design

### API Endpoints
```
GET    /notes           - List all notes (requires: notes:read)
POST   /notes           - Create note (requires: notes:write) 
GET    /notes/:id       - Get specific note (requires: notes:read)
PUT    /notes/:id       - Update note (requires: notes:write)
DELETE /notes/:id       - Delete note (requires: notes:write)
GET    /health          - Health check (no auth required)
```

### Middleware Stack
```
Request → CORS → Auth Middleware → Scope Middleware → Route Handler
```

### Data Models
```javascript
// Note
{
  id: string,
  title: string,
  content: string,
  createdAt: Date,
  updatedAt: Date,
  userId: string  // from token 'sub' claim
}

// JWT Access Token Claims (PKCE-issued)
{
  iss: "http://localhost:3001",  // IdP issuer
  aud: "notes-api",              // this resource server
  sub: "user123",                // user identifier
  scope: "notes:read notes:write",
  exp: 1234567890,
  iat: 1234567890,
  cnf: {                         // PKCE confirmation (optional)
    "x5t#S256": "code_challenge_hash"
  }
}
```

### Multi-Component Project Structure
```
auth/                           # Root project
├── package.json               # Shared dependencies
├── memory-bank/               # Project documentation
├── resource-server/           # Phase 1: OAuth 2.0 Resource Server
│   ├── app.js                # Express app entry point
│   └── src/
│       ├── config/
│       │   └── index.js      # Configuration
│       ├── middleware/
│       │   ├── auth.js       # JWT validation middleware
│       │   └── scope.js      # Scope authorization middleware
│       ├── routes/
│       │   └── notes.js      # Notes CRUD endpoints
│       ├── services/
│       │   ├── jwt.js        # JWT validation logic
│       │   └── notes.js      # Notes business logic
│       └── storage/
│           └── memory.js     # In-memory data store
├── identity-provider/         # Phase 2: Custom IdP (future)
│   ├── app.js
│   └── src/
│       ├── config/
│       ├── routes/
│       │   ├── authorize.js  # Authorization endpoint
│       │   ├── token.js      # Token endpoint
│       │   ├── userinfo.js   # UserInfo endpoint
│       │   └── discovery.js  # .well-known endpoints
│       └── services/
└── frontend/                  # Phase 3: React SPA (future)
    ├── package.json          # Frontend-specific deps
    ├── src/
    └── public/
```

### JWT Validation Flow
1. Extract `Bearer` token from `Authorization` header
2. Decode JWT header to get `kid` (key ID)
3. Fetch public key from JWKS endpoint using `kid`
4. Verify JWT signature with public key
5. Validate claims: `iss`, `aud`, `exp`, `iat`
6. Extract `scope` and `sub` for authorization

### Scope Authorization Logic
```javascript
const requiredScopes = {
  'GET /notes': ['notes:read'],
  'POST /notes': ['notes:write'],
  'GET /notes/:id': ['notes:read'],
  'PUT /notes/:id': ['notes:write'],
  'DELETE /notes/:id': ['notes:write']
}
```

### Error Responses
```javascript
// 401 Unauthorized (invalid/missing token)
{
  error: "invalid_token",
  error_description: "The access token is invalid or expired"
}

// 403 Forbidden (insufficient scope)
{
  error: "insufficient_scope",
  error_description: "The request requires higher privileges than provided"
}

// 404 Not Found
{
  error: "not_found",
  error_description: "Note not found"
}
```

### Configuration
```javascript
{
  resourceServer: {
    port: 3000,
    audience: "notes-api",
    corsOrigin: "http://localhost:5173"  // Future frontend
  },
  identityProvider: {
    port: 3001,  // Future Phase 2
    issuer: "http://localhost:3001",
    jwksUri: "http://localhost:3001/.well-known/jwks.json"
  }
}
```

### Development Dependencies
- `express` - Web framework
- `cors` - CORS middleware
- `jsonwebtoken` - JWT handling
- `jwks-rsa` - JWKS fetching and caching (supports PKCE)
- `uuid` - Generate note IDs
- `crypto` - Built-in Node.js crypto for PKCE code challenge/verifier generation

---

## Implementation Todo List

### Step 1: Initialize Package Dependencies
- [x] **File**: `package.json`
- [x] **Action**: Create/update package.json with Express, CORS, jsonwebtoken, jwks-client, and uuid dependencies
- [x] **Details**: Add resource server dependencies to existing auth project, set main entry "resource-server/app.js", add start script

### Step 2: Configuration Management
- [x] **File**: `resource-server/src/config/index.ts`
- [x] **Action**: Create TypeScript configuration module with environment variables and defaults (creates src/config/ folder)
- [x] **Details**: Export typed config object with port, JWKS URI, issuer, audience, and CORS origin settings

### Step 3: In-Memory Data Storage
- [x] **File**: `resource-server/src/storage/memory.ts`
- [x] **Action**: Create TypeScript in-memory notes storage with CRUD operations (creates src/storage/ folder)
- [x] **Details**: Implement Map-based storage with typed methods: create, findAll, findById, update, delete, findByUserId

### Step 4: JWT Validation Service
- [x] **File**: `resource-server/src/services/jwt.ts`
- [x] **Action**: Create TypeScript JWT validation service with JWKS client integration (creates src/services/ folder)
- [x] **Details**: Implement typed verifyToken function that validates JWT signature, claims (iss, aud, exp), and returns decoded payload

### Step 5: Authentication Middleware
- [x] **File**: `resource-server/src/middleware/auth.ts`
- [x] **Action**: Create TypeScript Express middleware for JWT token validation (creates src/middleware/ folder)
- [x] **Details**: Extract Bearer token, validate using jwt service, attach user info to req object, handle 401 errors

### Step 6: Scope Authorization Middleware
- [x] **File**: `resource-server/src/middleware/scope.ts`
- [x] **Action**: Create TypeScript Express middleware for scope-based authorization
- [x] **Details**: Check required scopes against token scopes, return 403 if insufficient, allow request if authorized

### Step 7: Notes Business Logic
- [x] **File**: `resource-server/src/services/notes.ts`
- [x] **Action**: Create TypeScript notes service with business logic and validation
- [x] **Details**: Implement typed createNote, getAllNotes, getNoteById, updateNote, deleteNote with user ownership checks

### Step 8: Notes API Routes
- [x] **File**: `resource-server/src/routes/notes.ts`
- [x] **Action**: Create TypeScript Express router with CRUD endpoints for notes (creates src/routes/ folder)
- [x] **Details**: Implement GET/POST /notes, GET/PUT/DELETE /notes/:id with proper middleware chain and types

### Step 9: Main Application
- [x] **File**: `resource-server/src/app.ts`
- [x] **Action**: Create main TypeScript Express application with all middleware and routes
- [x] **Details**: Set up CORS, health endpoint, notes routes, error handling, and server startup

### Step 10: Test JWT Generation Script (with PKCE)
- [x] **File**: `test/test-jwt.js` (moved to test folder)
- [x] **Action**: Create script to generate test JWT tokens for development with PKCE support
- [x] **Details**: Generate valid and invalid tokens with different scopes, include PKCE code verifier/challenge generation utilities

### Step 11: Basic Testing (with PKCE)
- [x] **File**: `test/test-requests.http` (moved to test folder) 
- [x] **Action**: Create HTTP request file for manual testing of all endpoints with PKCE flow examples
- [x] **Details**: Include requests with valid tokens, invalid tokens, missing tokens, insufficient scopes, and PKCE code challenge/verifier examples