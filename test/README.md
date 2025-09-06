# Test Scripts Directory

This directory contains testing utilities and scripts for the OAuth 2.0 + OIDC learning application.

## Overview

The test scripts help validate different components of our authentication system:
- **Phase 1**: Resource Server JWT validation and scope authorization
- **Phase 2**: Identity Provider token generation and PKCE flows (future)
- **Phase 3**: Frontend SPA integration testing (future)

## Available Test Scripts

### `test-jwt.js` - JWT Token Generator & PKCE Utilities

Generates JWT access tokens and PKCE data for testing the OAuth 2.0 resource server.

#### Prerequisites
```bash
# Install dependencies (run from project root)
npm install
```

#### Usage

**Basic Commands:**
```bash
# Generate basic CRUD testing tokens
node test/test-jwt.js basic

# Generate PKCE testing data and utilities
node test/test-jwt.js pkce

# Generate tokens for error testing (401/403 scenarios)
node test/test-jwt.js errors

# Generate all test tokens at once
node test/test-jwt.js all
```

**Custom Token Generation:**
```bash
# Create custom token for specific user and scopes
node test/test-jwt.js custom alice notes:read notes:write
node test/test-jwt.js custom bob notes:read
node test/test-jwt.js custom admin notes:read notes:write
```

**Token Analysis:**
```bash
# Decode and inspect any JWT token
node test/test-jwt.js decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Help:**
```bash
# Show all available commands
node test/test-jwt.js
```

#### Example Outputs

**Basic Tokens (`node test/test-jwt.js basic`):**
```
📝 Basic CRUD Tokens:

✅ Read-only token (notes:read):
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5LTEifQ...

✅ Write-only token (notes:write):
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5LTEifQ...

✅ Full access token (notes:read notes:write):
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5LTEifQ...

❌ No scopes token:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5LTEifQ...
```

**PKCE Data (`node test/test-jwt.js pkce`):**
```
🔒 PKCE Testing Data:

📋 PKCE Pairs:
Pair 1:
  Code Verifier: dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
  Code Challenge: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  Method: S256

🎫 PKCE Token with Confirmation:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5LTEifQ...

✅ PKCE Verification Example:
Verifier matches challenge: true
```

## Testing Workflows

### 1. Resource Server Testing (Phase 1 - Current)

**Step 1: Start the Resource Server**
```bash
# From project root
npm run dev
# Server starts on http://localhost:3000
```

**Step 2: Generate Test Tokens**
```bash
# Generate tokens for different scenarios
node test/test-jwt.js basic
```

**Step 3: Test API Endpoints**

Using the generated tokens, test the `/notes` API:

```bash
# Test with read-only token
curl -H "Authorization: Bearer <read-only-token>" \
     http://localhost:3000/notes

# Test with write token  
curl -X POST \
     -H "Authorization: Bearer <full-access-token>" \
     -H "Content-Type: application/json" \
     -d '{"title":"Test Note","content":"Hello World"}' \
     http://localhost:3000/notes

# Test with no token (should get 401)
curl http://localhost:3000/notes

# Test with insufficient scope (should get 403)
curl -X POST \
     -H "Authorization: Bearer <read-only-token>" \
     -H "Content-Type: application/json" \
     -d '{"title":"Test Note","content":"Hello World"}' \
     http://localhost:3000/notes
```

### 2. PKCE Flow Testing (Phase 2 - Future)

When the Identity Provider is implemented in Phase 2, use the PKCE utilities:

**Step 1: Generate PKCE Pair**
```bash
node test/test-jwt.js pkce
# Save the code_verifier and code_challenge
```

**Step 2: Authorization Request (Future)**
```
GET /authorize?
  response_type=code&
  client_id=test-spa-client&
  redirect_uri=http://localhost:5173/callback&
  scope=openid notes:read notes:write&
  state=abc123&
  nonce=xyz789&
  code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&
  code_challenge_method=S256
```

**Step 3: Token Exchange (Future)**
```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=<authorization_code>&
client_id=test-spa-client&
redirect_uri=http://localhost:5173/callback&
code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

### 3. Error Testing Scenarios

**Test Invalid Tokens:**
```bash
# Generate error tokens
node test/test-jwt.js errors

# Test expired token (401)
curl -H "Authorization: Bearer <expired-token>" \
     http://localhost:3000/notes

# Test invalid signature (401)  
curl -H "Authorization: Bearer <invalid-signature-token>" \
     http://localhost:3000/notes

# Test wrong issuer (401)
curl -H "Authorization: Bearer <wrong-issuer-token>" \
     http://localhost:3000/notes
```

## Token Structure

### Access Token Claims
```json
{
  "iss": "http://localhost:3001",        // Token issuer (IdP)
  "aud": "notes-api",                    // Intended audience (resource server)
  "sub": "user123",                      // Subject (user identifier)
  "scope": "notes:read notes:write",     // Space-separated scopes
  "exp": 1234567890,                     // Expiration timestamp
  "iat": 1234567890,                     // Issued at timestamp
  "jti": "uuid-here",                    // Unique token ID
  "client_id": "test-spa-client",        // Client that requested token
  "cnf": {                               // PKCE confirmation (optional)
    "x5t#S256": "code_challenge_hash"
  }
}
```

### PKCE Parameters
- **Code Verifier**: 43-128 character random string (Base64url encoded)
- **Code Challenge**: SHA256 hash of code verifier (Base64url encoded)
- **Code Challenge Method**: Always "S256" (SHA256)

## Security Testing

### Valid Token Scenarios
- ✅ Valid signature with correct secret
- ✅ Current timestamp (not expired)
- ✅ Correct issuer (`http://localhost:3001`)
- ✅ Correct audience (`notes-api`)
- ✅ Required scopes for endpoint

### Invalid Token Scenarios (401 Unauthorized)
- ❌ Expired token (`exp` claim in past)
- ❌ Invalid signature (wrong secret)
- ❌ Wrong issuer (`iss` claim)
- ❌ Wrong audience (`aud` claim)
- ❌ Missing or malformed token

### Insufficient Authorization Scenarios (403 Forbidden)
- ❌ Valid token but missing required scope
- ❌ `notes:read` scope trying to POST/PUT/DELETE
- ❌ No scopes in token

## Future Test Scripts

As we implement more phases, additional test scripts will be added:

- **`test-idp.js`** (Phase 2): Identity Provider endpoint testing
- **`test-oidc-flow.js`** (Phase 2): Full OIDC authorization flow testing  
- **`test-frontend.js`** (Phase 3): SPA integration and E2E testing
- **`test-security.js`** (All Phases): Security vulnerability testing

## Tips

1. **Save Tokens**: Generated tokens are valid for 1 hour by default
2. **Copy Carefully**: JWT tokens are long - use copy/paste to avoid errors
3. **Check Expiration**: Use `decode` command to verify token expiration
4. **Test Systematically**: Test both success and failure scenarios
5. **Monitor Logs**: Watch resource server logs for detailed error messages

## Troubleshooting

**Common Issues:**

```bash
# Token expired
# Solution: Generate new tokens
node test/test-jwt.js basic

# Invalid JSON response
# Check: Is the resource server running?
npm run dev

# 401 even with valid token  
# Check: Token signature and claims
node test/test-jwt.js decode <your-token>

# 403 with valid token
# Check: Token has required scopes
# notes:read for GET, notes:write for POST/PUT/DELETE
```

**Debug Token Contents:**
```bash
# Decode any token to inspect claims
node test/test-jwt.js decode eyJhbGciOiJIUzI1NiIs...
```