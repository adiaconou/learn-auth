# Phase 2: Custom Identity Provider Implementation Plan

## High-Level Design

### Overview
Build a complete OAuth 2.0 Authorization Server + OIDC Identity Provider that issues access tokens and ID tokens for the Resource Server built in Phase 1. This IdP will handle user authentication, authorization code flows with PKCE, consent management, and token issuance.

### Key Definitions

#### OAuth 2.0 Authorization Server
An **Authorization Server** is the OAuth 2.0 component responsible for:
- **Authorization**: Determining what a client/user can access
- **Access Token Issuance**: Creating tokens that grant specific permissions (scopes)
- **Client Authentication**: Validating OAuth client credentials
- **Consent Management**: Managing user permission grants to applications
- **Scope Enforcement**: Controlling what resources clients can access

The Authorization Server answers: *"What can this client do on behalf of this user?"*

#### OIDC Identity Provider (IdP)
An **Identity Provider** extends the Authorization Server with OpenID Connect capabilities for:
- **Authentication**: Verifying who the user is
- **ID Token Issuance**: Creating tokens that contain user identity information
- **User Information**: Providing standardized user profile data
- **Session Management**: Handling user login/logout sessions
- **Identity Claims**: Delivering user attributes (name, email, etc.)

The Identity Provider answers: *"Who is this user and what do we know about them?"*

#### Combined System (What We're Building)
Our Phase 2 implementation combines both roles into a single service that provides:
- **OAuth 2.0 Authorization Server**: Issues access tokens for API authorization
- **OIDC Identity Provider**: Issues ID tokens for user authentication
- **Unified User Experience**: Single login for both authentication and authorization
- **Token Coordination**: Access tokens and ID tokens issued together in OIDC flows

**Key Distinction:**
- **Authorization Server** → Access Tokens → *"Can you access the notes API?"*
- **Identity Provider** → ID Tokens → *"You are John Doe (john@example.com)"*
- **Combined System** → Both Token Types → *"You are John Doe AND you can read/write notes"*

### Core Components
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Frontend      │───→│  Identity        │───→│  User & Client  │
│   SPA Client    │    │  Provider        │    │  Storage        │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌──────────────────┐
                       │  Resource Server │
                       │  (Phase 1)       │
                       └──────────────────┘
```

### Key Responsibilities
1. **Discovery & Metadata**: Publish OIDC configuration and JWKS endpoints
2. **User Authentication**: Login system with session management
3. **Authorization Flow**: Handle Authorization Code + PKCE flow
4. **Consent Management**: User consent screens for scope authorization
5. **Token Issuance**: Generate JWT access tokens and ID tokens
6. **Client Management**: Register and validate OAuth clients
7. **Security**: PKCE, state validation, nonce handling, CSRF protection

### OAuth 2.0 + OIDC Flow Implementation

#### Complete Authorization Code + PKCE Flow
```
┌─────────┐                 ┌─────────┐                 ┌─────────┐
│ Client  │                 │   IdP   │                 │Resource │
│   SPA   │                 │(Phase 2)│                 │Server   │
└─────────┘                 └─────────┘                 │(Phase 1)│
     │                           │                      └─────────┘
     │ 1. Generate PKCE          │
     │    code_verifier +        │
     │    code_challenge         │
     │                           │
     │ 2. Authorization Request  │
     │ /authorize?response_type= │
     │ code&client_id=spa&       │
     │ redirect_uri=...&scope=   │
     │ openid+notes:read&state=  │
     │ xyz&nonce=abc&code_       │
     │ challenge=...&code_       │
     │ challenge_method=S256     │
     ├──────────────────────────→│
     │                           │
     │ 3. User Login + Consent   │
     │    (IdP handles UI)       │
     │                           │
     │ 4. Authorization Code     │
     │ ?code=auth123&state=xyz   │
     │←──────────────────────────┤
     │                           │
     │ 5. Token Exchange         │
     │ POST /token               │
     │ grant_type=authorization_ │
     │ code&code=auth123&        │
     │ code_verifier=...&        │
     │ client_id=spa&redirect_   │
     │ uri=...                   │
     ├──────────────────────────→│
     │                           │
     │ 6. Access + ID Tokens     │
     │ {                         │
     │   access_token: "JWT",    │
     │   id_token: "JWT",        │
     │   token_type: "Bearer",   │
     │   expires_in: 3600        │
     │ }                         │
     │←──────────────────────────┤
     │                           │
     │ 7. API Request            │
     │ Authorization: Bearer JWT │
     │                           ├──────────────────────→
     │                           │                      │
     │                           │ 8. JWT Validation    │
     │                           │    (JWKS from IdP)   │
     │                           │                      │
     │ 9. API Response           │                      │
     │←──────────────────────────┼──────────────────────┤
```

---

## Low-Level Design

### API Endpoints
```
# Discovery & Metadata
GET    /.well-known/openid-configuration  - OIDC discovery document
GET    /.well-known/jwks.json             - JSON Web Key Set

# OAuth 2.0 Core Endpoints  
GET    /authorize                         - Authorization endpoint
POST   /token                            - Token exchange endpoint
GET    /userinfo                         - User info endpoint (OIDC)

# Authentication & User Management
GET    /login                            - User login form
POST   /login                            - Process login
GET    /consent                          - Consent screen
POST   /consent                          - Process consent
POST   /logout                           - Logout endpoint
GET    /logout                           - Logout confirmation

# Administrative
GET    /health                           - Health check
GET    /admin/clients                    - Client management (dev only)
POST   /admin/clients                    - Register new client
```

### Project Structure
```
auth/                           # Root project
├── identity-provider/          # Phase 2: OAuth 2.0 + OIDC IdP
│   ├── package.json           # IdP-specific dependencies
│   ├── src/
│   │   ├── app.ts            # Main Express application
│   │   ├── config/
│   │   │   └── index.ts      # Configuration management
│   │   ├── middleware/
│   │   │   ├── session.ts    # Session middleware
│   │   │   ├── csrf.ts       # CSRF protection
│   │   │   └── auth.ts       # Authentication middleware
│   │   ├── routes/
│   │   │   ├── discovery.ts  # .well-known endpoints
│   │   │   ├── authorize.ts  # Authorization endpoint
│   │   │   ├── token.ts      # Token endpoint
│   │   │   ├── userinfo.ts   # UserInfo endpoint
│   │   │   ├── login.ts      # Login endpoints
│   │   │   ├── consent.ts    # Consent endpoints
│   │   │   ├── logout.ts     # Logout endpoints
│   │   │   └── admin.ts      # Admin/client management
│   │   ├── services/
│   │   │   ├── user.ts       # User management
│   │   │   ├── client.ts     # Client validation
│   │   │   ├── token.ts      # JWT token generation
│   │   │   ├── pkce.ts       # PKCE validation
│   │   │   ├── authorization.ts # Authorization code management
│   │   │   └── consent.ts    # Consent management
│   │   ├── storage/
│   │   │   ├── memory.ts     # In-memory stores
│   │   │   └── models.ts     # Data models/types
│   │   ├── crypto/
│   │   │   ├── keys.ts       # Key management (RSA/ECDSA)
│   │   │   └── jwks.ts       # JWKS generation
│   │   └── views/           # HTML templates (EJS/Handlebars)
│   │       ├── login.html   
│   │       ├── consent.html
│   │       ├── logout.html
│   │       └── error.html
│   └── test/
│       ├── test-flow.js     # End-to-end flow testing
│       └── test-endpoints.http # Manual endpoint testing
```

### Data Models
```typescript
// User
interface User {
  id: string;
  username: string;
  email: string;
  passwordHash: string;
  name?: string;
  createdAt: Date;
}

// OAuth Client
interface OAuthClient {
  id: string;
  name: string;
  type: 'public' | 'confidential';  // SPA = public
  redirectUris: string[];
  allowedScopes: string[];
  secret?: string;  // Only for confidential clients
  requirePkce: boolean;
  createdAt: Date;
}

// Authorization Code
interface AuthorizationCode {
  code: string;
  clientId: string;
  userId: string;
  redirectUri: string;
  scope: string;
  nonce?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  expiresAt: Date;
  used: boolean;
}

// Refresh Token
interface RefreshToken {
  id: string;
  userId: string;
  clientId: string;
  scope: string;
  expiresAt: Date;
  revoked: boolean;
}

// Consent Grant
interface ConsentGrant {
  userId: string;
  clientId: string;
  scope: string;
  grantedAt: Date;
}

// JWT Access Token Claims
interface AccessTokenClaims {
  iss: string;           // "http://localhost:3001"
  aud: string;           // "notes-api" 
  sub: string;           // User ID
  scope: string;         // "notes:read notes:write"
  exp: number;           // Expiration timestamp
  iat: number;           // Issued at timestamp
  jti: string;           // JWT ID (for revocation)
  client_id: string;     // OAuth client ID
}

// JWT ID Token Claims (OIDC)
interface IdTokenClaims {
  iss: string;           // "http://localhost:3001"
  aud: string;           // Client ID
  sub: string;           // User ID  
  exp: number;           // Expiration timestamp
  iat: number;           // Issued at timestamp
  nonce?: string;        // Nonce from auth request
  email?: string;        // User email
  name?: string;         // User display name
  auth_time?: number;    // Authentication timestamp
}
```

### Security Configuration
```typescript
interface SecurityConfig {
  // JWT Settings
  accessTokenTtl: number;        // 15 minutes
  idTokenTtl: number;           // 1 hour  
  refreshTokenTtl: number;      // 30 days
  authorizationCodeTtl: number; // 10 minutes
  
  // PKCE Settings
  codeVerifierLength: number;   // 43-128 characters
  codeChallengeMethod: string;  // "S256"
  
  // Security Headers
  sessionSecret: string;        // For session encryption
  csrfSecret: string;          // For CSRF protection
  
  // Cryptographic Keys
  privateKey: string;          // RSA private key (PEM format)
  publicKey: string;           // RSA public key (PEM format)
  keyId: string;               // Key ID for JWKS
  
  // Client Settings
  allowedOrigins: string[];    // CORS origins
  requireHttps: boolean;       // HTTPS enforcement
}
```

### Required Endpoints Implementation

#### 1. Discovery Document (`/.well-known/openid-configuration`)
```typescript
interface DiscoveryDocument {
  issuer: "http://localhost:3001";
  authorization_endpoint: "http://localhost:3001/authorize";
  token_endpoint: "http://localhost:3001/token";
  userinfo_endpoint: "http://localhost:3001/userinfo";
  jwks_uri: "http://localhost:3001/.well-known/jwks.json";
  response_types_supported: ["code"];
  subject_types_supported: ["public"];
  id_token_signing_alg_values_supported: ["RS256"];
  scopes_supported: ["openid", "notes:read", "notes:write"];
  code_challenge_methods_supported: ["S256"];
  grant_types_supported: ["authorization_code", "refresh_token"];
}
```

#### 2. Authorization Endpoint (`GET /authorize`)
**Query Parameters:**
- `response_type`: Must be "code"
- `client_id`: Registered client identifier
- `redirect_uri`: Must match registered redirect URI exactly
- `scope`: Requested scopes (e.g., "openid notes:read notes:write")
- `state`: CSRF protection parameter
- `nonce`: Replay protection parameter (OIDC)
- `code_challenge`: PKCE challenge (Base64 URL-encoded SHA256)
- `code_challenge_method`: Must be "S256"

**Flow:**
1. Validate all parameters
2. Check if user is authenticated (session)
3. If not authenticated, redirect to login
4. Check existing consent for client + scopes
5. If no consent, show consent screen
6. Generate authorization code with PKCE challenge
7. Redirect to client with authorization code

#### 3. Token Endpoint (`POST /token`)
**Form Parameters:**
- `grant_type`: "authorization_code" or "refresh_token"
- `code`: Authorization code from /authorize
- `redirect_uri`: Must match authorization request
- `client_id`: OAuth client identifier
- `code_verifier`: PKCE verifier (original random string)

**Flow:**
1. Validate authorization code exists and not expired/used
2. Verify PKCE: SHA256(code_verifier) === stored code_challenge
3. Mark authorization code as used
4. Generate JWT access token and ID token
5. Optional: Generate refresh token
6. Return token response

#### 4. UserInfo Endpoint (`GET /userinfo`)
**Headers:**
- `Authorization: Bearer <access_token>`

**Flow:**
1. Validate access token signature and claims
2. Check `openid` scope is present
3. Return user claims based on scopes

---

## Implementation Todo List

### Step 1: Project Setup
- [x] **File**: `identity-provider/package.json`
- [x] **Action**: Create IdP package.json with dependencies (Express, session middleware, crypto, templates)
- [x] **Details**: Add express, express-session, jsonwebtoken, bcrypt, uuid, ejs/handlebars, cookie-parser, helmet

### Step 2: Configuration Management
- [x] **File**: `identity-provider/src/config/index.ts`
- [x] **Action**: Create comprehensive configuration with security settings (creates src/config/ folder)
- [x] **Details**: JWT settings, PKCE config, session secrets, CORS, key management, environment variables

### Step 3: Cryptographic Key Management
- [x] **File**: `identity-provider/src/crypto/keys.ts`
- [x] **Action**: Generate and manage RSA key pairs for JWT signing (creates src/crypto/ folder)
- [x] **Details**: Key generation, PEM format handling, key ID management, JWKS formatting

### Step 4: JWKS Endpoint  
- [x] **File**: `identity-provider/src/crypto/jwks.ts` + `identity-provider/src/routes/discovery.ts`
- [x] **Action**: Implement JWKS endpoint and discovery document (creates src/routes/ folder)
- [x] **Details**: Publish public keys in JWKS format, OIDC discovery metadata

### Step 5: Data Storage & Models
- [x] **File**: `identity-provider/src/storage/memory.ts` + `identity-provider/src/storage/models.ts`
- [x] **Action**: Implement in-memory stores for users, clients, codes, consent (creates src/storage/ folder)
- [x] **Details**: User store, client store, authorization code store, consent store, refresh token store

### Step 6: User Management Service
- [x] **File**: `identity-provider/src/services/user.ts`
- [x] **Action**: User authentication, registration, and profile management (creates src/services/ folder)
- [x] **Details**: Password hashing (bcrypt), user validation, profile retrieval, hardcoded test users initially

### Step 7: Client Management Service
- [ ] **File**: `identity-provider/src/services/client.ts`
- [ ] **Action**: OAuth client validation and management
- [ ] **Details**: Client registration, redirect URI validation, scope validation, PKCE requirements

### Step 8: PKCE Service
- [ ] **File**: `identity-provider/src/services/pkce.ts`
- [ ] **Action**: PKCE code challenge/verifier validation
- [ ] **Details**: SHA256 hashing, Base64 URL encoding/decoding, verifier validation

### Step 9: Session & CSRF Middleware
- [ ] **File**: `identity-provider/src/middleware/session.ts` + `identity-provider/src/middleware/csrf.ts`
- [ ] **Action**: Session management and CSRF protection (creates src/middleware/ folder)
- [ ] **Details**: Express session config, CSRF token generation/validation, secure cookies

### Step 10: Authentication Middleware
- [ ] **File**: `identity-provider/src/middleware/auth.ts`
- [ ] **Action**: Authentication middleware for protected routes
- [ ] **Details**: Session-based auth checking, user context, login redirects

### Step 11: Login Endpoints
- [x] **File**: `identity-provider/src/routes/login.ts` + `identity-provider/src/views/login.html`
- [x] **Action**: User login form and processing (creates src/views/ folder)
- [x] **Details**: Login form HTML, POST processing, session creation, password validation

### Step 12: Authorization Code Service
- [ ] **File**: `identity-provider/src/services/authorization.ts`
- [ ] **Action**: Authorization code generation and validation
- [ ] **Details**: Code generation, PKCE challenge storage, expiration handling, one-time use

### Step 13: Authorization Endpoint
- [ ] **File**: `identity-provider/src/routes/authorize.ts`
- [ ] **Action**: OAuth 2.0 authorization endpoint with PKCE
- [ ] **Details**: Parameter validation, authentication check, consent flow, code generation

### Step 14: Consent Management
- [ ] **File**: `identity-provider/src/services/consent.ts` + `identity-provider/src/routes/consent.ts` + `identity-provider/src/views/consent.html`
- [ ] **Action**: User consent screens and consent management
- [ ] **Details**: Consent UI, scope descriptions, consent storage, skip logic for trusted clients

### Step 15: JWT Token Service
- [ ] **File**: `identity-provider/src/services/token.ts`
- [ ] **Action**: JWT access token and ID token generation
- [ ] **Details**: Access token claims, ID token claims, JWT signing, token expiration, refresh tokens

### Step 16: Token Endpoint
- [ ] **File**: `identity-provider/src/routes/token.ts`
- [ ] **Action**: OAuth 2.0 token endpoint with PKCE validation
- [ ] **Details**: Authorization code exchange, PKCE validation, token generation, refresh token handling

### Step 17: UserInfo Endpoint
- [ ] **File**: `identity-provider/src/routes/userinfo.ts`
- [ ] **Action**: OIDC UserInfo endpoint
- [ ] **Details**: Bearer token validation, user claim retrieval, scope-based claim filtering

### Step 18: Logout Endpoints
- [ ] **File**: `identity-provider/src/routes/logout.ts` + `identity-provider/src/views/logout.html`
- [ ] **Action**: Logout functionality with session cleanup
- [ ] **Details**: Session destruction, logout confirmation, redirect handling

### Step 19: Main Application
- [ ] **File**: `identity-provider/src/app.ts`
- [ ] **Action**: Main Express app with all middleware and routes
- [ ] **Details**: Session setup, CORS, security headers, route mounting, error handling

### Step 20: Client Pre-registration
- [ ] **File**: `identity-provider/src/routes/admin.ts`
- [ ] **Action**: Administrative endpoint to register OAuth clients
- [ ] **Details**: Pre-register SPA client and API client for testing, client management endpoints

### Step 21: Integration Testing
- [ ] **File**: `identity-provider/test/test-flow.js`
- [ ] **Action**: End-to-end OAuth 2.0 + OIDC flow testing (creates test/ folder)
- [ ] **Details**: Full authorization code + PKCE flow, token validation, integration with Phase 1 Resource Server

### Step 22: Manual Testing Suite
- [ ] **File**: `identity-provider/test/test-endpoints.http`
- [ ] **Action**: HTTP requests for manual testing of all endpoints
- [ ] **Details**: Discovery, authorization, token exchange, userinfo, admin endpoints

---

## Acceptance Criteria

### Core Functionality
- [ ] **OIDC Discovery**: `/.well-known/openid-configuration` returns valid OIDC discovery document
- [ ] **JWKS Endpoint**: `/.well-known/jwks.json` publishes RSA public keys for JWT verification
- [ ] **User Authentication**: Login system authenticates users with username/password
- [ ] **Authorization Code Flow**: Complete OAuth 2.0 authorization code flow with PKCE
- [ ] **Token Issuance**: Issues valid JWT access tokens and ID tokens
- [ ] **UserInfo Endpoint**: Returns user claims based on access token and scopes

### Security Requirements
- [ ] **PKCE Validation**: Validates code_challenge/code_verifier pairs correctly
- [ ] **State Parameter**: Validates state parameter to prevent CSRF attacks
- [ ] **Nonce Handling**: Includes nonce in ID tokens for replay protection
- [ ] **Redirect URI Validation**: Exact matching of registered redirect URIs
- [ ] **JWT Security**: Properly signed JWTs with RSA keys and secure claims
- [ ] **Session Management**: Secure session handling with proper expiration

### Integration Requirements
- [ ] **Resource Server Integration**: Phase 1 Resource Server can validate tokens from this IdP
- [ ] **JWKS Integration**: Resource Server fetches and caches JWKS from this IdP
- [ ] **Token Validation**: Access tokens contain correct `iss`, `aud`, `scope`, `sub` claims
- [ ] **Scope Enforcement**: Issued tokens contain only consented scopes

### User Experience
- [ ] **Login Flow**: Intuitive login form with error handling
- [ ] **Consent Screen**: Clear consent screen showing requested permissions
- [ ] **Error Handling**: Proper error messages and HTTP status codes
- [ ] **Logout Flow**: Clean logout with session termination

### Development & Testing
- [ ] **Pre-registered Clients**: SPA client and API client pre-configured for testing
- [ ] **Test Users**: Hardcoded test users for development
- [ ] **Health Checks**: Health endpoint for monitoring
- [ ] **Comprehensive Tests**: End-to-end flow testing and endpoint validation

### Standards Compliance
- [ ] **OAuth 2.0 RFC 6749**: Compliant authorization code flow
- [ ] **PKCE RFC 7636**: Proper PKCE implementation for public clients
- [ ] **OIDC Core**: Compliant OpenID Connect implementation
- [ ] **JWT RFC 7519**: Properly formatted and signed JWT tokens
- [ ] **JWKS RFC 7517**: Valid JSON Web Key Set format

---

## Phase 2 Summary

**Objective**: Implement a complete OAuth 2.0 Authorization Server + OIDC Identity Provider that handles user authentication, consent management, and secure token issuance using the Authorization Code + PKCE flow.

**Key Deliverables**:
1. **Discovery & Metadata Endpoints** - OIDC discovery document and JWKS publication
2. **User Authentication System** - Login/logout with secure session management  
3. **Authorization Code Flow** - Complete OAuth 2.0 flow with PKCE security extension
4. **Token Issuance** - JWT access tokens and ID tokens with proper claims
5. **Consent Management** - User consent screens for scope authorization
6. **Client Management** - OAuth client registration and validation
7. **Integration Ready** - Full compatibility with Phase 1 Resource Server

**Security Features**:
- PKCE (Proof Key for Code Exchange) for public client security
- State parameter validation for CSRF protection  
- Nonce handling for ID token replay protection
- Secure JWT token signing with RSA keys
- Session-based authentication with secure cookies
- Exact redirect URI matching for authorization security

**Learning Outcomes**:
- Understand complete OAuth 2.0 + OIDC implementation
- Learn token lifecycle management and security
- Practice cryptographic key management and JWT handling
- Implement user consent and authorization flows
- Gain experience with session management and CSRF protection
- See how authorization servers and resource servers integrate

This phase transforms the project from a simple JWT-validating API into a complete identity and authorization system, providing the foundation for the frontend SPA integration in Phase 3.