# Key Concepts for OIDC + OAuth 2.0 Learning Project

## Table of Contents
1. [OAuth 2.0](#oauth-20)
2. [OpenID Connect (OIDC)](#openid-connect-oidc)
3. [Resource Server](#resource-server)
4. [PKCE (Proof Key for Code Exchange)](#pkce-proof-key-for-code-exchange)
5. [JWT (JSON Web Tokens)](#jwt-json-web-tokens)
6. [JWKS (JSON Web Key Set)](#jwks-json-web-key-set)
7. [Authorization Code Flow with PKCE](#authorization-code-flow-with-pkce)
8. [Scopes](#scopes)
9. [Access Tokens vs ID Tokens](#access-tokens-vs-id-tokens)
10. [Authorization Server vs Resource Server](#authorization-server-vs-resource-server)
11. [Discovery Document](#discovery-document)
12. [Claims](#claims)
13. [Redirect URIs](#redirect-uris)
14. [State Parameter](#state-parameter)
15. [Nonce](#nonce)
16. [HTTP Status Codes (401 vs 403)](#http-status-codes-401-vs-403)

---

## OAuth 2.0

### High-Level Points
- Authorization framework for delegated access
- Enables third-party applications to access user resources
- Uses access tokens instead of sharing passwords
- Defines roles: client, authorization server, resource server, resource owner

### Summary
OAuth 2.0 is an authorization framework that allows applications to obtain limited access to user accounts without exposing user credentials. It works by redirecting users to an authorization server where they authenticate and grant permission, then the application receives an access token to make API calls on the user's behalf. This solves the problem of password sharing between applications.

### Complete OAuth 2.0 System Implementation Requirements

#### 1. Authorization Server (Identity Provider) Components

**Core Endpoints:**
- `GET /.well-known/openid-configuration` - Discovery document with server metadata
- `GET /authorize` - Authorization endpoint for login/consent flows
- `POST /token` - Token endpoint for exchanging codes/refresh tokens
- `GET /.well-known/jwks.json` - JSON Web Key Set for token verification
- `GET /userinfo` - User information endpoint (OIDC extension)
- `POST /revoke` - Token revocation endpoint (optional)
- `POST /introspect` - Token introspection endpoint (optional)

**Authentication & User Management:**
- User registration and login system
- Password hashing and validation (bcrypt/scrypt/argon2)
- Multi-factor authentication support
- User profile management
- Session management and logout

**Client Management:**
- Client registration (dynamic or static)
- Client authentication (client_secret, private_key_jwt, etc.)
- Redirect URI validation and management
- Client scope limitations and permissions
- Client metadata storage

**Authorization & Consent:**
- Authorization request validation
- User consent screen and management
- Scope-based permission system
- Authorization code generation and storage
- State parameter validation (CSRF protection)
- PKCE support (code_challenge/code_verifier)

**Token Management:**
- JWT/opaque access token generation
- Refresh token generation and rotation
- Token expiration and cleanup
- Token binding and validation
- Cryptographic key management and rotation

#### 2. Resource Server Components

**Token Validation:**
- JWT signature verification using JWKS
- Token claim validation (iss, aud, exp, iat)
- Token introspection for opaque tokens
- JWKS caching and key rotation handling
- Token blacklist/revocation checking

**Authorization & Access Control:**
- Scope-based authorization middleware
- Fine-grained permission checking
- User context extraction from tokens
- Resource ownership validation
- Rate limiting and abuse protection

**API Security:**
- Bearer token extraction from headers
- CORS configuration for cross-origin requests
- Input validation and sanitization
- Error handling without information leakage
- Audit logging and monitoring

#### 3. Client Application Components

**Authentication Flow:**
- Authorization request generation
- PKCE code_verifier/code_challenge generation
- State parameter generation and validation
- Authorization code handling
- Token exchange and storage

**Token Management:**
- Secure token storage (httpOnly cookies/secure storage)
- Automatic token refresh handling
- Token expiration detection
- Logout and token cleanup
- Token binding and validation

**API Integration:**
- Bearer token injection in API requests
- Error handling (401/403 responses)
- Token refresh on expiration
- Retry logic with fresh tokens
- Request signing (optional)

#### 4. Security Implementation Requirements

**PKCE (For Public Clients):**
- Code verifier generation (43-128 random characters)
- Code challenge creation (SHA256 hash, base64url encoded)
- Challenge method specification (S256)
- Verifier validation in token exchange

**CSRF Protection:**
- State parameter in authorization requests
- State validation in callbacks
- Nonce for ID token binding (OIDC)
- Same-site cookies where applicable

**Token Security:**
- Short-lived access tokens (15min - 1hr)
- Longer-lived refresh tokens with rotation
- Secure token transmission (HTTPS only)
- Token binding to client/session
- Proper token audience validation

**Key Management:**
- RSA/ECDSA key pair generation
- Key rotation procedures
- JWKS publication and caching
- Key ID (kid) management
- Secure key storage

#### 5. Data Storage Requirements

**Authorization Server Storage:**
- User accounts and credentials
- Client registrations and secrets
- Authorization codes (short-lived)
- Access tokens and refresh tokens
- User consent records
- Session data

**Resource Server Storage:**
- JWKS cache with TTL
- Token blacklists (if required)
- Rate limiting counters
- Audit logs
- Resource data with user ownership

#### 6. Configuration Requirements

**Environment Variables:**
- Cryptographic keys and secrets
- Database connection strings
- Redis/cache connection details
- Allowed CORS origins
- Token expiration times

**Security Settings:**
- HTTPS enforcement
- Cookie security attributes
- Content Security Policy headers
- Rate limiting thresholds
- Key rotation schedules

#### 7. Production Considerations

**Scalability:**
- Stateless token validation
- Distributed session storage (Redis)
- Load balancer session affinity
- Database connection pooling
- Horizontal scaling support

**Monitoring & Logging:**
- Authentication success/failure rates
- Token validation metrics
- API request/error rates
- Security event logging (failed logins, etc.)
- Performance monitoring

**High Availability:**
- Database replication and failover
- Cache clustering (Redis Cluster)
- Health check endpoints
- Graceful shutdown handling
- Circuit breaker patterns

**Compliance & Auditing:**
- GDPR/privacy regulation compliance
- Security audit trails
- Data retention policies
- User consent management
- Penetration testing preparation

---

## OpenID Connect (OIDC)

### High-Level Points
- Authentication layer built on top of OAuth 2.0
- Adds identity information via ID tokens
- Provides standardized user info endpoint
- Includes discovery and session management

### Summary
OIDC extends OAuth 2.0 to add authentication capabilities. While OAuth 2.0 only handles authorization (what you can access), OIDC adds authentication (who you are) by introducing ID tokens that contain user identity information. It's essentially OAuth 2.0 + identity, providing a complete solution for both authentication and authorization in web applications.

---

## Resource Server

### High-Level Points
- Server hosting protected resources (APIs)
- Validates access tokens on each request
- Enforces authorization based on token scopes
- Returns 401/403 errors for invalid/insufficient access

### Summary
The resource server is the API that holds the protected resources (like your notes API). It doesn't handle user login - instead, it validates access tokens sent by clients and enforces what actions are allowed based on the token's scopes. It's the "bouncer" that checks your credentials before letting you access resources.

---

## PKCE (Proof Key for Code Exchange)

### High-Level Points
- Security extension for OAuth 2.0 Authorization Code flow
- Prevents authorization code interception attacks
- Uses code_challenge and code_verifier parameters
- Required for public clients like SPAs and mobile apps

### Summary
PKCE solves the security problem of authorization codes being intercepted in public clients. The client generates a random code_verifier and sends a hashed code_challenge when requesting authorization. When exchanging the authorization code for tokens, the client must provide the original code_verifier. This ensures only the client that initiated the flow can complete it, even if the authorization code is intercepted.

---


---

## JWT (JSON Web Tokens)

### High-Level Points
- Self-contained tokens with header, payload, and signature
- Can be verified without calling the issuer
- Contains claims (key-value pairs) about the user/client
- Signed with cryptographic keys for tamper-proof validation

### Summary
JWTs are the token format used for both access tokens and ID tokens in this project. They're base64-encoded JSON objects that contain claims about the user or authorization. The signature ensures the token hasn't been tampered with and came from a trusted issuer. Resource servers can validate JWTs locally without network calls to the authorization server.

---

## JWKS (JSON Web Key Set)

### High-Level Points
- Public keys published by the authorization server
- Used to verify JWT signatures
- Accessible via `/.well-known/jwks.json` endpoint
- Supports key rotation for security

### Summary
JWKS is how authorization servers publish their public keys so resource servers can verify JWT signatures. When a resource server receives a JWT, it looks up the correct public key using the `kid` (key ID) from the JWT header, then verifies the signature. This allows decentralized token validation without shared secrets.

---

## Authorization Code Flow with PKCE

### High-Level Points
- Secure flow for single-page applications (SPAs)
- Uses authorization codes exchanged for tokens
- PKCE prevents code interception attacks
- Involves browser redirects and backend token exchange

### Summary
The Authorization Code flow is the most secure OAuth 2.0 flow for web applications. The client redirects users to the authorization server, which returns an authorization code after login/consent. PKCE (Proof Key for Code Exchange) adds security by requiring a code verifier that only the original client knows, preventing code interception attacks in public clients like SPAs.

---

## Scopes

### High-Level Points
- Define what permissions an access token grants
- Format: space-separated strings (e.g., "notes:read notes:write")
- Requested during authorization, granted via consent
- Enforced by resource servers

### Summary
Scopes are the OAuth 2.0 mechanism for fine-grained permissions. They define what actions a client can perform on behalf of a user. In this project, `notes:read` allows reading notes while `notes:write` allows creating/updating notes. Users must consent to requested scopes, and resource servers enforce these permissions when validating access tokens.

---

## Access Tokens vs ID Tokens

### High-Level Points
- Access tokens: Authorization for API access (audience: resource server)
- ID tokens: User authentication information (audience: client application)
- Access tokens contain scopes and permissions
- ID tokens contain user claims (sub, email, name)

### Summary
These serve different purposes in OIDC/OAuth 2.0. Access tokens are like keycards - they grant access to specific resources and are consumed by resource servers. ID tokens are like driver's licenses - they prove identity and are consumed by client applications. Never use ID tokens for API authorization or access tokens for user identity.

---

## Authorization Server vs Resource Server

### High-Level Points
- Authorization Server: Issues tokens, handles login/consent
- Resource Server: Protects APIs, validates tokens
- Different audiences and responsibilities
- Can be separate services or combined

### Summary
The authorization server (Identity Provider) handles user authentication and issues tokens after login and consent. The resource server protects actual resources (like the notes API) and validates tokens on each request. This separation allows one authorization server to protect multiple resource servers, and enables token validation without network calls.

---

## Discovery Document

### High-Level Points
- Published at `/.well-known/openid-configuration`
- Contains all OIDC/OAuth endpoints and capabilities
- Allows clients to auto-configure
- Standard way to advertise authorization server metadata

### Summary
The discovery document is like a phone book for your authorization server. It tells clients where to find the authorization endpoint, token endpoint, JWKS endpoint, and what features are supported. This allows OIDC clients to automatically configure themselves just by knowing the issuer URL.

---

## Claims

### High-Level Points
- Key-value pairs inside JWT tokens
- Standard claims: `iss`, `aud`, `sub`, `exp`, `iat`
- Custom claims for application-specific data
- ID tokens have user claims, access tokens have authorization claims

### Summary
Claims are the structured data inside JWT tokens. Standard claims like `iss` (issuer) and `exp` (expiration) provide security information, while `sub` (subject) identifies the user. Custom claims can add application-specific information. Resource servers validate standard claims for security and use authorization claims (like `scope`) for access control.

---

## Redirect URIs

### High-Level Points
- Where the authorization server sends users after login
- Must be pre-registered with exact matching
- Security boundary - prevents token theft
- Different URIs for different environments

### Summary
Redirect URIs are the return addresses after OAuth flows. They must be exactly registered in advance to prevent authorization code injection attacks. When a malicious site tries to steal codes by using their own redirect URI, the authorization server rejects it because it doesn't match the registered URI for that client.

---

## State Parameter

### High-Level Points
- Prevents CSRF attacks in OAuth flows
- Opaque value maintained between request and callback
- Client generates unique state per authorization request
- Must match between authorize and callback

### Summary
The state parameter is OAuth's CSRF protection. The client generates a random value before redirecting to the authorization server, then verifies the same value comes back in the callback. This prevents attackers from tricking users into authorizing their malicious applications by ensuring the authorization request originated from the legitimate client.

---

## Nonce

### High-Level Points
- Prevents replay attacks in OIDC flows
- Included in ID token to bind it to the client session
- One-time use value
- Different from state (nonce is for replay protection, state is for CSRF)

### Summary
Nonce (number used once) prevents ID token replay attacks in OIDC. The client includes a unique nonce in the authorization request, and the authorization server includes it in the ID token. This binds the ID token to the specific client session and prevents attackers from reusing intercepted ID tokens in different contexts.

---

## HTTP Status Codes (401 vs 403)

### High-Level Points
- 401 Unauthorized: Invalid or missing authentication
- 403 Forbidden: Valid authentication, insufficient permissions  
- 401 means "who are you?" - authentication problem
- 403 means "you can't do that" - authorization problem

### Summary
These status codes have specific meanings in OAuth 2.0 APIs. Return 401 when the access token is missing, expired, or invalid - the client needs to authenticate again. Return 403 when the token is valid but lacks the required scopes - the client is authenticated but not authorized for this action. This distinction helps clients handle errors appropriately.