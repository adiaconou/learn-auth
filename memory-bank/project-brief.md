# Project Brief: Full-Stack OIDC + OAuth 2.0 Learning Application

## Larger Objective
The goal of this project is to **understand and implement OpenID Connect (OIDC) and OAuth 2.0 end-to-end by building every component from scratch**. Unlike using a hosted Identity Provider (Auth0/Okta/Cognito), this project includes implementing a **custom Identity Provider (IdP)** alongside a Resource Server and a frontend SPA.  

This application will never be used in production or exposed to real users — it exists purely as a learning exercise. By building each piece yourself, you’ll see how tokens are minted, validated, and consumed, and how the OIDC/OAuth 2.0 flows tie the system together.

At the end, you’ll have a functioning full-stack app with:
- **Custom Identity Provider** that issues ID tokens and access tokens, handles login + consent, publishes discovery docs and JWKS.
- **Resource Server (API)** that enforces authorization via access tokens.
- **Frontend SPA** (React/Vite) that integrates the OIDC Authorization Code + PKCE flow, displays ID token claims, and calls the protected API.

---

## Phase 1: Resource Server (Start Here)
### Scope
- Build a simple REST API (`/notes`) with CRUD-like endpoints.
- Require a valid **access token** for every request.
- Validate JWT access tokens (initially mocked, then from your IdP).
- Enforce **scope-based authorization** (`notes:read`, `notes:write`).
- Return proper HTTP errors: `401` (invalid/missing token) vs `403` (insufficient scope).

### Deliverables
- Express/FastAPI server with `/notes` endpoints.
- JWT validation middleware:
  - Signature check against JWKS.
  - Verify `iss`, `aud`, `exp`, `scope`.
- Scope-based access control.
- In-memory or SQLite datastore for notes.

---

## Phase 2: Custom Identity Provider
### Scope
Implement a minimal OAuth 2.0 Authorization Server + OIDC Provider:

1. **Discovery + Metadata**
   - `/.well-known/openid-configuration` with endpoint URLs.
   - `/.well-known/jwks.json` exposing signing keys (RS256 or ES256).

2. **Authorization Endpoint**
   - `GET /authorize`
   - Accepts `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`, `nonce`, `code_challenge`.
   - Displays login (hardcoded users at first), then consent screen for scopes.
   - Issues an **authorization code** if login + consent succeed.

3. **Token Endpoint**
   - `POST /token`
   - Exchanges code + `code_verifier` for:
     - **Access Token (JWT)** with scopes and audience.
     - **ID Token (JWT)** with `sub`, `iss`, `aud`, `exp`, `nonce`, and user claims.
     - **Refresh Token** (optional, with rotation).

4. **User Info Endpoint**
   - `GET /userinfo` returns profile claims (`sub`, `email`, `name`).

5. **User & Client Store**
   - Simple DB or in-memory store for:
     - Users (id, username, password hash).
     - Registered clients (SPA + API).
     - Consent grants (client + scopes).

6. **Security Features**
   - PKCE required for SPA clients.
   - Exact redirect URI matching.
   - Validate `state` and `nonce`.
   - Sign all tokens with rotating keys published in JWKS.

---

## Phase 3: Frontend SPA (React/Vite)
### Scope
- Provide **Login** button → redirect to your IdP `/authorize`.
- Handle redirect back with `code` and `state`.
- Exchange code for tokens (directly, or via a small backend-for-frontend).
- Store ID token in memory; display user profile claims.
- Call `/notes` API with `Authorization: Bearer <access_token>`.
- Handle error responses (401/403) gracefully.

---

## Success Criteria
- **Resource Server** rejects/accepts requests based on valid JWTs and scopes.
- **Identity Provider** issues real authorization codes, ID tokens, and access tokens that your Resource Server validates correctly.
- **Frontend SPA** demonstrates the OIDC login flow, displays ID token claims, and successfully accesses the API with valid access tokens.
- All three components communicate strictly via OIDC/OAuth standards.

---

## Learning Goals
- Distinguish between **authentication** (OIDC, ID token) and **authorization** (OAuth 2.0, access token).
- Implement JWT signing/validation, JWKS publishing, and claim enforcement yourself.
- Understand redirect flows, PKCE, `state`, `nonce`, and consent.
- Observe real-world security boundaries (401 vs 403, scope vs role).
- Gain confidence by breaking flows on purpose (wrong `nonce`, expired token, bad signature) and debugging why they fail.

---

## Tech Stack
- **Backend (Resource Server + IdP)**: Node.js + Express (or Python + FastAPI).
- **Token Signing**: `jsonwebtoken` (Node) or `python-jose` (Python).
- **Frontend**: React + Vite.
- **DB**: In-memory store (start) → SQLite/Postgres (later).

---

## Roadmap
1. **Phase 1**: Resource Server with mocked JWTs (JWT validation + scope enforcement).  
2. **Phase 2**: Custom Identity Provider with Authorization Code + PKCE, token issuing, JWKS, discovery, and consent.  
3. **Phase 3**: Frontend SPA with OIDC login, token exchange, and API calls.  
4. **Stretch Goals**: Refresh token rotation, logout flows, opaque tokens with introspection, role-based authorization, key rotation.  
