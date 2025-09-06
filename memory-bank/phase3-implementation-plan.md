# Phase 3: Frontend SPA Implementation Plan

## High-Level Design

### Overview
Build a React Single Page Application (SPA) that demonstrates the complete OIDC + OAuth 2.0 flow by integrating with the Identity Provider (Phase 2) and consuming the protected Notes API (Phase 1). This SPA will implement the Authorization Code + PKCE flow, handle token management, and provide a complete user experience from login to API consumption.

### Key Definitions

#### Single Page Application (SPA)
A **Single Page Application** is a web application that:
- **Loads once**: Initial HTML/JS/CSS bundle loads completely
- **Dynamic updates**: Subsequent navigation updates content without full page reloads  
- **Client-side routing**: Uses browser history API for navigation
- **API-driven**: Fetches data via HTTP APIs rather than server-rendered pages
- **Stateful**: Maintains application state in browser memory

**Why SPA for OAuth 2.0/OIDC:**
- **Public client**: Cannot securely store client secrets (all code runs in browser)
- **PKCE required**: Uses PKCE flow for security without client secrets
- **Token storage**: Manages access tokens and ID tokens in browser
- **Redirect handling**: Handles OAuth callback redirects seamlessly
- **Session management**: Maintains user login state across navigation

#### OIDC Client Integration Challenges
**Security Challenges:**
- **Token storage**: Where to store tokens securely (memory vs localStorage vs httpOnly cookies)
- **XSS protection**: Prevent token theft via cross-site scripting
- **CSRF protection**: State parameter validation for authorization requests
- **Token leakage**: Prevent tokens from appearing in browser history/logs
- **Logout security**: Proper token cleanup and session termination

**User Experience Challenges:**  
- **Seamless login**: Minimize authentication friction
- **Auto-refresh**: Handle token expiration gracefully
- **Error handling**: Guide users through authentication errors
- **Loading states**: Provide feedback during OAuth flows
- **Deep linking**: Preserve navigation state across login flows

### Core Components
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   React SPA     │───→│  Identity        │───→│  User & Client  │
│   (Phase 3)     │    │  Provider        │    │  Storage        │
│                 │    │  (Phase 2)       │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │
         │                        ▼
         │               ┌──────────────────┐
         └──────────────→│  Resource Server │
                         │  (Phase 1)       │
                         └──────────────────┘
```

### Key Responsibilities
1. **OIDC Authentication**: Implement Authorization Code + PKCE flow
2. **Token Management**: Secure storage and automatic refresh of tokens
3. **User Interface**: Login, profile display, and logout functionality
4. **API Integration**: Consume protected Notes API with access tokens
5. **Error Handling**: Graceful handling of 401/403 responses and OAuth errors
6. **Security**: PKCE implementation, state validation, XSS protection
7. **User Experience**: Loading states, error messages, deep linking

### React SPA OAuth 2.0 + OIDC Flow

#### Complete Authorization Code + PKCE Flow (SPA Perspective)
```
┌─────────┐                 ┌─────────┐                 ┌─────────┐
│ React   │                 │   IdP   │                 │Resource │  
│  SPA    │                 │(Phase 2)│                 │Server   │
│(Phase 3)│                 └─────────┘                 │(Phase 1)│
└─────────┘                      │                      └─────────┘
     │                           │                           │
     │ 1. User clicks "Login"    │                           │
     │    SPA generates PKCE     │                           │
     │    code_verifier +        │                           │
     │    code_challenge +       │                           │
     │    state + nonce          │                           │
     │                           │                           │
     │ 2. Redirect to IdP        │                           │
     │ /authorize?response_type= │                           │
     │ code&client_id=spa&       │                           │
     │ redirect_uri=callback&    │                           │
     │ scope=openid+notes:read   │                           │
     │ +notes:write&state=xyz&   │                           │
     │ nonce=abc&code_challenge= │                           │
     │ ...&code_challenge_method │                           │
     │ =S256                     │                           │
     ├──────────────────────────→│                           │
     │                           │                           │
     │ 3. User authenticates     │                           │
     │    + grants consent       │                           │
     │    (IdP handles this)     │                           │
     │                           │                           │
     │ 4. Redirect back to SPA   │                           │
     │ /callback?code=auth123&   │                           │
     │ state=xyz                 │                           │
     │←──────────────────────────┤                           │
     │                           │                           │
     │ 5. SPA validates state,   │                           │
     │    then exchanges code    │                           │
     │    POST /token with       │                           │
     │    code + code_verifier   │                           │
     ├──────────────────────────→│                           │
     │                           │                           │
     │ 6. IdP returns tokens     │                           │
     │ {                         │                           │
     │   access_token: "JWT",    │                           │
     │   id_token: "JWT",        │                           │
     │   token_type: "Bearer",   │                           │
     │   expires_in: 3600,       │                           │
     │   refresh_token: "..."    │                           │
     │ }                         │                           │
     │←──────────────────────────┤                           │
     │                           │                           │
     │ 7. SPA stores tokens,     │                           │
     │    decodes ID token       │                           │
     │    claims, redirects to   │                           │
     │    main app               │                           │
     │                           │                           │
     │ 8. User navigates to      │                           │
     │    Notes page, SPA makes  │                           │
     │    API call with Bearer   │                           │
     │    token                  │                           │
     │                           │ Authorization: Bearer JWT │
     │                           │──────────────────────────→│
     │                           │                           │
     │                           │ 9. Resource Server        │
     │                           │    validates JWT via      │
     │                           │    IdP JWKS, checks      │
     │                           │    scopes                 │
     │                           │                           │
     │ 10. API response with     │                           │
     │     notes data           │                           │
     │←──────────────────────────────────────────────────────│
     │                           │                           │
     │ 11. If token expires,     │                           │
     │     SPA automatically     │                           │  
     │     refreshes using       │                           │
     │     refresh_token         │                           │
     ├──────────────────────────→│                           │
```

---

## Low-Level Design

### Project Structure
```
auth/                           # Root project
├── frontend/                  # Phase 3: React SPA
│   ├── package.json          # SPA dependencies
│   ├── vite.config.ts        # Vite configuration
│   ├── index.html            # SPA entry point
│   ├── src/
│   │   ├── main.tsx          # React app entry
│   │   ├── App.tsx           # Main app component
│   │   ├── components/       # Reusable UI components
│   │   │   ├── Layout.tsx    # App layout with navigation
│   │   │   ├── LoginButton.tsx # Login initiation
│   │   │   ├── LogoutButton.tsx # Logout handling
│   │   │   ├── UserProfile.tsx # User info display
│   │   │   ├── LoadingSpinner.tsx # Loading states
│   │   │   ├── ErrorMessage.tsx # Error display
│   │   │   └── ProtectedRoute.tsx # Auth-required routes
│   │   ├── pages/           # Route components
│   │   │   ├── Home.tsx     # Landing page
│   │   │   ├── Login.tsx    # Login page
│   │   │   ├── Callback.tsx # OAuth callback handler
│   │   │   ├── Notes.tsx    # Notes list/management
│   │   │   ├── Profile.tsx  # User profile page
│   │   │   └── NotFound.tsx # 404 page
│   │   ├── services/        # External API clients
│   │   │   ├── auth.ts      # OIDC/OAuth service
│   │   │   ├── notes.ts     # Notes API client
│   │   │   ├── pkce.ts      # PKCE utilities
│   │   │   └── storage.ts   # Token storage service
│   │   ├── hooks/           # React hooks
│   │   │   ├── useAuth.ts   # Authentication hook
│   │   │   ├── useNotes.ts  # Notes data hook
│   │   │   └── useLocalStorage.ts # Storage hook
│   │   ├── contexts/        # React contexts
│   │   │   └── AuthContext.tsx # Auth state management
│   │   ├── types/           # TypeScript types
│   │   │   ├── auth.ts      # Auth-related types
│   │   │   ├── notes.ts     # Notes types
│   │   │   └── api.ts       # API response types
│   │   ├── utils/           # Utility functions
│   │   │   ├── crypto.ts    # PKCE crypto helpers
│   │   │   ├── jwt.ts       # JWT decoding utilities
│   │   │   ├── url.ts       # URL manipulation
│   │   │   └── validation.ts # Input validation
│   │   └── styles/          # CSS/SCSS styles
│   │       ├── global.css   # Global styles
│   │       ├── components/  # Component-specific styles
│   │       └── pages/       # Page-specific styles
│   └── test/
│       ├── setup.ts         # Test configuration
│       ├── auth.test.ts     # Auth service tests
│       ├── pkce.test.ts     # PKCE utility tests
│       └── components/      # Component tests
```

### Core Data Models
```typescript
// Authentication State
interface AuthState {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: User | null;
  tokens: Tokens | null;
  error: string | null;
}

// User Information (from ID Token)
interface User {
  sub: string;           // User ID
  email?: string;        // Email address
  name?: string;         // Display name
  auth_time?: number;    // Authentication timestamp
}

// Token Set
interface Tokens {
  accessToken: string;   // JWT access token
  idToken: string;      // JWT ID token
  refreshToken?: string; // Refresh token
  tokenType: 'Bearer';  // Token type
  expiresAt: number;    // Access token expiration (timestamp)
  scope: string;        // Granted scopes
}

// PKCE Parameters
interface PKCEParams {
  codeVerifier: string;     // Random string (43-128 chars)
  codeChallenge: string;    // SHA256(codeVerifier) base64url
  codeChallengeMethod: 'S256';
}

// Authorization Request State
interface AuthRequest {
  state: string;         // CSRF protection
  nonce: string;         // Replay protection
  pkce: PKCEParams;      // PKCE parameters
  redirectUri: string;   // Callback URL
  scope: string;         // Requested scopes
}

// Notes API Models
interface Note {
  id: string;
  title: string;
  content: string;
  createdAt: string;    // ISO date string
  updatedAt: string;    // ISO date string
  userId: string;       // Owner user ID
}

interface CreateNoteRequest {
  title: string;
  content: string;
}

interface UpdateNoteRequest {
  title?: string;
  content?: string;
}

// API Error Response
interface ApiError {
  error: string;                    // Error code
  error_description?: string;       // Human readable description
  error_uri?: string;              // Documentation link
}
```

### Configuration & Environment
```typescript
interface AppConfig {
  // Identity Provider Settings
  identityProvider: {
    issuer: string;                 // "http://localhost:3001"
    clientId: string;               // "notes-spa"
    redirectUri: string;            // "http://localhost:5173/callback"
    scope: string;                  // "openid notes:read notes:write"
    responseType: 'code';           // Authorization code flow
    codeChallengeMethod: 'S256';    // PKCE method
  };
  
  // Resource Server Settings  
  resourceServer: {
    baseUrl: string;                // "http://localhost:3000"
    audience: string;               // "notes-api"
  };
  
  // Security Settings
  security: {
    tokenStorageType: 'memory' | 'localStorage' | 'sessionStorage';
    autoRefreshTokens: boolean;     // Automatic refresh before expiry
    refreshThresholdSec: number;    // Refresh when expires in X seconds
    logoutOnTokenExpiry: boolean;   // Force logout if refresh fails
  };
  
  // Development Settings
  development: {
    enableDebugLogs: boolean;       // Console logging
    mockAuthFlow: boolean;          // Skip real OAuth for testing
    bypassTokenValidation: boolean; // Skip JWT validation
  };
}

// Environment Variables
interface EnvironmentConfig {
  VITE_IDP_ISSUER: string;
  VITE_IDP_CLIENT_ID: string;
  VITE_RESOURCE_SERVER_URL: string;
  VITE_REDIRECT_URI: string;
  VITE_ENABLE_DEBUG: string;
}
```

### React Components Architecture

#### 1. App Component (`App.tsx`)
```tsx
// Main application component with routing
interface AppProps {}

const App: React.FC<AppProps> = () => {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Layout>
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/login" element={<Login />} />
            <Route path="/callback" element={<Callback />} />
            <Route path="/notes" element={
              <ProtectedRoute>
                <Notes />
              </ProtectedRoute>
            } />
            <Route path="/profile" element={
              <ProtectedRoute>
                <Profile />
              </ProtectedRoute>
            } />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </Layout>
      </BrowserRouter>
    </AuthProvider>
  );
};
```

#### 2. Authentication Context (`AuthContext.tsx`)
```tsx
interface AuthContextType {
  // State
  authState: AuthState;
  
  // Actions
  login: (redirectUri?: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshTokens: () => Promise<boolean>;
  
  // Utilities
  isTokenExpired: () => boolean;
  hasScope: (scope: string) => boolean;
  getAccessToken: () => string | null;
}

const AuthContext = createContext<AuthContextType | null>(null);
```

#### 3. OAuth Callback Handler (`Callback.tsx`)
```tsx
// Handles OAuth callback and token exchange
interface CallbackProps {}

const Callback: React.FC<CallbackProps> = () => {
  const { handleCallback } = useAuth();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  useEffect(() => {
    const processCallback = async () => {
      try {
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const state = urlParams.get('state');
        const error = urlParams.get('error');
        
        if (error) {
          throw new Error(urlParams.get('error_description') || error);
        }
        
        if (!code || !state) {
          throw new Error('Missing authorization code or state parameter');
        }
        
        await handleCallback(code, state);
        // Redirect to intended page or home
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Authentication failed');
      } finally {
        setLoading(false);
      }
    };
    
    processCallback();
  }, [handleCallback]);
  
  if (loading) return <LoadingSpinner message="Completing login..." />;
  if (error) return <ErrorMessage error={error} />;
  return null;
};
```

### Service Layer Implementation

#### 1. Auth Service (`services/auth.ts`)
```typescript
class AuthService {
  private config: AppConfig['identityProvider'];
  private storageService: StorageService;
  
  constructor(config: AppConfig['identityProvider']) {
    this.config = config;
    this.storageService = new StorageService();
  }
  
  // Initiate login flow
  async initiateLogin(redirectUri?: string): Promise<void> {
    const authRequest = await this.createAuthRequest(redirectUri);
    
    // Store request state for callback validation
    this.storageService.setAuthRequest(authRequest);
    
    // Build authorization URL
    const authUrl = this.buildAuthorizationUrl(authRequest);
    
    // Redirect to IdP
    window.location.href = authUrl;
  }
  
  // Handle OAuth callback
  async handleCallback(code: string, state: string): Promise<Tokens> {
    const authRequest = this.storageService.getAuthRequest();
    
    if (!authRequest || authRequest.state !== state) {
      throw new Error('Invalid state parameter - possible CSRF attack');
    }
    
    // Exchange authorization code for tokens
    const tokens = await this.exchangeCodeForTokens(code, authRequest);
    
    // Validate and decode ID token
    const user = await this.validateAndDecodeIdToken(tokens.idToken);
    
    // Store tokens securely
    this.storageService.setTokens(tokens);
    this.storageService.setUser(user);
    this.storageService.clearAuthRequest();
    
    return tokens;
  }
  
  // Refresh access token
  async refreshAccessToken(): Promise<Tokens | null> {
    const refreshToken = this.storageService.getRefreshToken();
    
    if (!refreshToken) {
      return null;
    }
    
    try {
      const response = await fetch(`${this.config.issuer}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
          client_id: this.config.clientId,
        }),
      });
      
      if (!response.ok) {
        throw new Error(`Token refresh failed: ${response.status}`);
      }
      
      const tokenResponse = await response.json();
      const tokens = this.parseTokenResponse(tokenResponse);
      
      this.storageService.setTokens(tokens);
      return tokens;
    } catch (error) {
      // Refresh failed - clear all auth data
      this.logout();
      return null;
    }
  }
  
  // Logout and cleanup
  async logout(): Promise<void> {
    // TODO: Call IdP logout endpoint if available
    
    // Clear local storage
    this.storageService.clearAll();
    
    // Redirect to home
    window.location.href = '/';
  }
  
  private async createAuthRequest(redirectUri?: string): Promise<AuthRequest> {
    const pkce = await PKCEService.generatePKCEParams();
    
    return {
      state: generateRandomString(32),
      nonce: generateRandomString(32),
      pkce,
      redirectUri: redirectUri || this.config.redirectUri,
      scope: this.config.scope,
    };
  }
  
  private buildAuthorizationUrl(authRequest: AuthRequest): string {
    const params = new URLSearchParams({
      response_type: this.config.responseType,
      client_id: this.config.clientId,
      redirect_uri: authRequest.redirectUri,
      scope: authRequest.scope,
      state: authRequest.state,
      nonce: authRequest.nonce,
      code_challenge: authRequest.pkce.codeChallenge,
      code_challenge_method: authRequest.pkce.codeChallengeMethod,
    });
    
    return `${this.config.issuer}/authorize?${params.toString()}`;
  }
  
  private async exchangeCodeForTokens(code: string, authRequest: AuthRequest): Promise<Tokens> {
    const response = await fetch(`${this.config.issuer}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: authRequest.redirectUri,
        client_id: this.config.clientId,
        code_verifier: authRequest.pkce.codeVerifier,
      }),
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error_description || 'Token exchange failed');
    }
    
    const tokenResponse = await response.json();
    return this.parseTokenResponse(tokenResponse);
  }
}
```

#### 2. Notes API Service (`services/notes.ts`)
```typescript
class NotesService {
  private baseUrl: string;
  private authService: AuthService;
  
  constructor(baseUrl: string, authService: AuthService) {
    this.baseUrl = baseUrl;
    this.authService = authService;
  }
  
  async getAllNotes(): Promise<Note[]> {
    const response = await this.authenticatedFetch('/notes');
    return response.json();
  }
  
  async getNote(id: string): Promise<Note> {
    const response = await this.authenticatedFetch(`/notes/${id}`);
    return response.json();
  }
  
  async createNote(note: CreateNoteRequest): Promise<Note> {
    const response = await this.authenticatedFetch('/notes', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(note),
    });
    return response.json();
  }
  
  async updateNote(id: string, note: UpdateNoteRequest): Promise<Note> {
    const response = await this.authenticatedFetch(`/notes/${id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(note),
    });
    return response.json();
  }
  
  async deleteNote(id: string): Promise<void> {
    await this.authenticatedFetch(`/notes/${id}`, {
      method: 'DELETE',
    });
  }
  
  private async authenticatedFetch(url: string, options: RequestInit = {}): Promise<Response> {
    let accessToken = this.authService.getAccessToken();
    
    // Auto-refresh token if expired
    if (this.authService.isTokenExpired()) {
      const refreshed = await this.authService.refreshAccessToken();
      if (!refreshed) {
        throw new Error('Authentication required');
      }
      accessToken = refreshed.accessToken;
    }
    
    const response = await fetch(`${this.baseUrl}${url}`, {
      ...options,
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${accessToken}`,
      },
    });
    
    // Handle 401 - token might be invalid, try refresh once
    if (response.status === 401 && !options.headers?.['X-Retry']) {
      const refreshed = await this.authService.refreshAccessToken();
      if (refreshed) {
        return this.authenticatedFetch(url, {
          ...options,
          headers: {
            ...options.headers,
            'X-Retry': 'true',
          },
        });
      }
    }
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new ApiError(
        error.error || `HTTP ${response.status}`,
        error.error_description || response.statusText
      );
    }
    
    return response;
  }
}
```

#### 3. PKCE Service (`services/pkce.ts`)
```typescript
class PKCEService {
  static async generatePKCEParams(): Promise<PKCEParams> {
    // Generate random code verifier (43-128 characters)
    const codeVerifier = generateRandomString(128);
    
    // Create code challenge (SHA256 hash, base64url encoded)
    const encoder = new TextEncoder();
    const data = encoder.encode(codeVerifier);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const codeChallenge = base64UrlEncode(new Uint8Array(hashBuffer));
    
    return {
      codeVerifier,
      codeChallenge,
      codeChallengeMethod: 'S256',
    };
  }
  
  static validateCodeVerifier(codeVerifier: string): boolean {
    // RFC 7636: 43-128 characters, [A-Z] [a-z] [0-9] "-" "." "_" "~"
    return /^[A-Za-z0-9\-._~]{43,128}$/.test(codeVerifier);
  }
}
```

---

## Implementation Todo List

**IMPORTANT**: Build one functional feature at a time. Each step delivers working functionality that can be tested immediately. Only create the minimal files needed for that specific feature to work.

### Step 1: Project Setup & Dependencies ✅
- [x] **File**: `frontend/package.json`  
- [x] **Action**: Create React SPA package.json with Vite, TypeScript, and OAuth dependencies
- [x] **Details**: Add React, TypeScript, Vite, React Router, crypto utilities, JWT decode library, testing framework

### Step 2: Vite Configuration & Entry Point ✅  
- [x] **File**: `frontend/vite.config.ts` + `frontend/index.html`
- [x] **Action**: Configure Vite build tool with TypeScript and development server settings
- [x] **Details**: TypeScript config, dev server port 5173, HMR, environment variable handling, build optimization

### Step 3: Application Entry Point ✅
- [x] **File**: `frontend/src/main.tsx`
- [x] **Action**: React application entry point and DOM rendering
- [x] **Details**: React DOM rendering, provider setup, error boundaries, development tools

### Step 4: Main App Component (Basic Structure) ✅
- [x] **File**: `frontend/src/App.tsx`
- [x] **Action**: Root application component with basic routing setup
- [x] **Details**: Basic React Router setup, placeholder routes, simple navigation

---

## Feature-Driven Implementation (Build One Working Feature at a Time)

### Step 5: 🎯 FEATURE - Basic Login Redirect ✅
**Goal**: User can click "Login" and be redirected to IdP with proper OAuth parameters
- [x] **Files**: `frontend/src/config/index.ts` + `frontend/src/utils/crypto.ts` + `frontend/src/services/auth.ts`
- [x] **Action**: Implement OAuth login initiation with PKCE
- [x] **Test**: Click login → redirects to http://localhost:3001/authorize with proper PKCE params
- [x] **Details**: Configuration management, PKCE generation, OAuth URL building

### Step 6: 🎯 FEATURE - OAuth Callback Handling ✅
**Goal**: Handle OAuth callback and exchange authorization code for tokens
- [x] **Files**: Update `frontend/src/services/auth.ts` + `frontend/src/pages/Callback.tsx`
- [x] **Action**: Process callback, validate state, exchange code for tokens
- [x] **Test**: Complete OAuth flow → get access & ID tokens → redirect to home page
- [x] **Details**: Token exchange, JWT parsing, secure storage

### Step 7: 🎯 FEATURE - Authentication State Management
**Goal**: App knows if user is logged in and shows user info
- [ ] **Files**: `frontend/src/contexts/AuthContext.tsx` + `frontend/src/hooks/useAuth.ts`
- [ ] **Action**: Global auth state with login/logout actions
- [ ] **Test**: After login → navigation shows "Welcome, [user]" + logout button
- [ ] **Details**: React context, JWT decoding, user profile display

### Step 8: 🎯 FEATURE - Protected Routes
**Goal**: Notes page requires login, redirects to login if not authenticated
- [ ] **Files**: `frontend/src/components/ProtectedRoute.tsx` + Update `frontend/src/App.tsx`
- [ ] **Action**: Route protection with authentication check
- [ ] **Test**: Access /notes → redirects to login if not authenticated
- [ ] **Details**: Route guards, authentication checking, redirect logic

### Step 9: 🎯 FEATURE - Logout Functionality  
**Goal**: User can logout and all tokens are cleared
- [ ] **Files**: Update auth service + `frontend/src/components/LogoutButton.tsx`
- [ ] **Action**: Complete logout with token cleanup
- [ ] **Test**: Click logout → tokens cleared → redirected to home → login required again
- [ ] **Details**: Token cleanup, storage clearing, navigation reset

### Step 10: 🎯 FEATURE - API Authentication (Notes List)
**Goal**: Fetch and display notes from Resource Server using access token
- [ ] **Files**: `frontend/src/services/notes.ts` + Update `frontend/src/pages/Notes.tsx`
- [ ] **Action**: Authenticated API calls with Bearer tokens
- [ ] **Test**: Visit /notes → displays list of notes from API
- [ ] **Details**: Bearer token auth, API client, error handling

### Step 11: 🎯 FEATURE - Token Auto-Refresh
**Goal**: Access tokens automatically refresh when expired
- [ ] **Files**: Update auth service with refresh logic
- [ ] **Action**: Automatic token refresh before expiration
- [ ] **Test**: Let token expire → API calls still work → tokens refreshed automatically
- [ ] **Details**: Token expiration checking, refresh token usage, automatic renewal

### Step 12: 🎯 FEATURE - Create/Edit Notes
**Goal**: User can create and edit notes through the UI
- [ ] **Files**: Update notes service + notes page with forms
- [ ] **Action**: Full CRUD operations for notes
- [ ] **Test**: Create note → appears in list, edit note → changes saved
- [ ] **Details**: Form handling, API operations, optimistic updates

### Step 13: 🎯 FEATURE - Error Handling & Recovery
**Goal**: Graceful handling of auth errors and API failures
- [ ] **Files**: Error components + enhanced error handling
- [ ] **Action**: Comprehensive error handling with user feedback
- [ ] **Test**: Network errors, auth failures, token refresh failures handled gracefully
- [ ] **Details**: Error boundaries, retry logic, user notifications

### Step 9: Token Storage Service
- [ ] **File**: `frontend/src/services/storage.ts`
- [ ] **Action**: Secure token storage with multiple backend options
- [ ] **Details**: Memory storage, localStorage, sessionStorage backends, token serialization, automatic cleanup

### Step 10: JWT Utilities
- [ ] **File**: `frontend/src/utils/jwt.ts`
- [ ] **Action**: JWT decoding and validation utilities
- [ ] **Details**: JWT payload decoding, expiration checking, claim extraction, token introspection

### Step 11: Authentication Service (Core)
- [ ] **File**: `frontend/src/services/auth.ts`
- [ ] **Action**: Core OAuth 2.0 + OIDC client implementation
- [ ] **Details**: Authorization URL generation, callback handling, token exchange, refresh logic, logout

### Step 12: Authentication Context
- [ ] **File**: `frontend/src/contexts/AuthContext.tsx`
- [ ] **Action**: React context for global authentication state management
- [ ] **Details**: Auth state provider, user info, token management, login/logout actions
- [ ] **Note**: This creates `frontend/src/contexts/` folder

### Step 13: Authentication Hook
- [ ] **File**: `frontend/src/hooks/useAuth.ts`
- [ ] **Action**: Custom React hook for authentication operations
- [ ] **Details**: Login initiation, callback processing, token refresh, logout, scope checking
- [ ] **Note**: This creates `frontend/src/hooks/` folder

### Step 14: OAuth Callback Page
- [ ] **File**: `frontend/src/pages/Callback.tsx`
- [ ] **Action**: Handle OAuth callback and complete authentication flow
- [ ] **Details**: URL parameter extraction, state validation, token exchange, error handling, redirect
- [ ] **Note**: This creates `frontend/src/pages/` folder

### Step 15: Basic UI Components (Loading & Error)
- [ ] **File**: `frontend/src/components/LoadingSpinner.tsx` + `frontend/src/components/ErrorMessage.tsx`
- [ ] **Action**: Create essential UI components for auth flow
- [ ] **Details**: Loading spinner, error display components
- [ ] **Note**: This creates `frontend/src/components/` folder

### Step 16: Login Button Component
- [ ] **File**: `frontend/src/components/LoginButton.tsx`
- [ ] **Action**: Login button with OAuth initiation
- [ ] **Details**: Login button with OAuth redirect handling

### Step 17: Home Page (Basic)
- [ ] **File**: `frontend/src/pages/Home.tsx`
- [ ] **Action**: Landing page with basic authentication state
- [ ] **Details**: Welcome message, login button, conditional rendering

### Step 18: Update App Component (Add Auth Provider)
- [ ] **File**: Update `frontend/src/App.tsx`
- [ ] **Action**: Integrate AuthProvider and callback route
- [ ] **Details**: Wrap app with AuthProvider, add callback route, update routing

### Step 19: User Profile Component
- [ ] **File**: `frontend/src/components/UserProfile.tsx`
- [ ] **Action**: User profile display component
- [ ] **Details**: Display user info from ID token, logout option

### Step 20: Logout Button Component  
- [ ] **File**: `frontend/src/components/LogoutButton.tsx`
- [ ] **Action**: Logout button with proper cleanup
- [ ] **Details**: Logout handling, token cleanup, redirect

### Step 21: Protected Route Component
- [ ] **File**: `frontend/src/components/ProtectedRoute.tsx`
- [ ] **Action**: Route protection for authenticated pages
- [ ] **Details**: Authentication check, redirect to login, loading states

### Step 22: Profile Page
- [ ] **File**: `frontend/src/pages/Profile.tsx`
- [ ] **Action**: User profile page displaying ID token claims
- [ ] **Details**: User info display, ID token claims, authentication details

### Step 23: Notes API Types
- [ ] **File**: `frontend/src/types/notes.ts`
- [ ] **Action**: Define Notes API TypeScript interfaces
- [ ] **Details**: Note models, API request/response types

### Step 24: Notes API Client
- [ ] **File**: `frontend/src/services/notes.ts`
- [ ] **Action**: Resource Server API client with automatic authentication
- [ ] **Details**: CRUD operations, Bearer token injection, auto-refresh, 401/403 handling

### Step 25: Notes Data Hook
- [ ] **File**: `frontend/src/hooks/useNotes.ts`
- [ ] **Action**: Custom React hook for notes data management
- [ ] **Details**: Fetch notes, create/update/delete operations, loading states, error handling

### Step 26: Notes Management Page
- [ ] **File**: `frontend/src/pages/Notes.tsx`
- [ ] **Action**: Complete notes CRUD interface with API integration
- [ ] **Details**: Notes list, create/edit forms, delete confirmation, API error handling, loading states

### Step 27: App Layout Component (Final)
- [ ] **File**: `frontend/src/components/Layout.tsx`
- [ ] **Action**: Main app layout with navigation
- [ ] **Details**: Header with user info, navigation menu, responsive design

### Step 28: Update App Component (Final Routing)
- [ ] **File**: Update `frontend/src/App.tsx`
- [ ] **Action**: Complete routing setup with all pages and layout
- [ ] **Details**: All routes, layout integration, 404 handling

### Step 29: Basic Styling
- [ ] **File**: `frontend/src/styles/global.css`
- [ ] **Action**: Basic styling for the application
- [ ] **Details**: Global CSS reset, basic component styles, responsive design
- [ ] **Note**: This creates `frontend/src/styles/` folder when needed

### Step 30: Development Testing (Core Auth)
- [ ] **File**: `frontend/test/auth.test.ts`
- [ ] **Action**: Unit tests for critical authentication functions
- [ ] **Details**: PKCE generation, JWT decoding, auth service tests
- [ ] **Note**: This creates `frontend/test/` folder when needed

### Step 31: PKCE Testing
- [ ] **File**: `frontend/test/pkce.test.ts`
- [ ] **Action**: Unit tests for PKCE implementation
- [ ] **Details**: PKCE parameter generation, validation, security tests

### Step 32: Integration Testing
- [ ] **File**: `frontend/test/integration.test.tsx`
- [ ] **Action**: Integration tests for complete OAuth flow
- [ ] **Details**: End-to-end auth flow, API integration, component integration

---

## Acceptance Criteria

### Core Authentication Flow
- [ ] **OAuth Initiation**: Login button redirects to IdP with proper PKCE parameters
- [ ] **Callback Handling**: OAuth callback processes authorization code and exchanges for tokens
- [ ] **State Validation**: State parameter prevents CSRF attacks during OAuth flow  
- [ ] **Token Storage**: Tokens stored securely with proper expiration handling
- [ ] **ID Token Display**: User profile page shows claims from ID token
- [ ] **Logout Flow**: Logout clears all tokens and redirects appropriately

### API Integration  
- [ ] **Bearer Token Auth**: Notes API calls include access token in Authorization header
- [ ] **Scope Validation**: Access restricted based on token scopes (notes:read vs notes:write)
- [ ] **Auto Refresh**: Expired access tokens automatically refreshed using refresh token
- [ ] **Error Handling**: 401/403 responses handled gracefully with user feedback
- [ ] **CRUD Operations**: Full notes create, read, update, delete functionality

### Security Requirements
- [ ] **PKCE Implementation**: Proper PKCE code verifier/challenge generation and validation
- [ ] **Nonce Validation**: ID token nonce matches authorization request nonce  
- [ ] **XSS Protection**: Tokens not exposed in URL, localStorage, or browser history
- [ ] **Token Expiration**: Access tokens automatically refreshed before expiration
- [ ] **Secure Storage**: Sensitive data stored securely (memory or httpOnly cookies)

### User Experience
- [ ] **Loading States**: Clear loading indicators during async operations
- [ ] **Error Messages**: Helpful error messages for authentication and API failures
- [ ] **Navigation**: Seamless navigation between authenticated and public routes
- [ ] **Deep Linking**: Authentication state preserved across page navigation
- [ ] **Responsive Design**: Mobile-friendly interface for all authentication flows

### Development & Testing
- [ ] **Environment Config**: Easy configuration for different environments (dev/prod)
- [ ] **Debug Logging**: Comprehensive logging for development and troubleshooting
- [ ] **Unit Tests**: Tests for crypto utilities, auth service, and API client
- [ ] **Integration Tests**: End-to-end OAuth flow testing
- [ ] **Error Simulation**: Ability to simulate and test error scenarios

### Standards Compliance
- [ ] **OAuth 2.0 RFC 6749**: Compliant Authorization Code flow implementation
- [ ] **PKCE RFC 7636**: Proper PKCE implementation for public client security
- [ ] **OIDC Core**: Compliant OpenID Connect client implementation
- [ ] **JWT RFC 7519**: Proper JWT handling and validation
- [ ] **Security Best Practices**: Following OAuth 2.0 security best practices

---

## Phase 3 Summary

**Objective**: Build a React Single Page Application that demonstrates the complete OIDC + OAuth 2.0 ecosystem by integrating with the Identity Provider (Phase 2) and consuming the protected Notes API (Phase 1) using the Authorization Code + PKCE flow.

**Key Deliverables**:
1. **OAuth 2.0 Client** - Complete PKCE-enabled authorization code flow implementation
2. **Token Management** - Secure storage, automatic refresh, and lifecycle management
3. **API Integration** - Bearer token authentication with the Notes Resource Server
4. **User Interface** - Login, profile, notes management, and logout functionality
5. **Security Implementation** - PKCE, state validation, XSS protection, secure storage
6. **Error Handling** - Graceful handling of authentication and API errors
7. **Testing Suite** - Unit and integration tests for critical functionality

**Security Features**:
- PKCE (Proof Key for Code Exchange) for secure public client authentication
- State parameter validation for CSRF protection during OAuth flows
- Nonce validation for ID token replay protection  
- Secure token storage to prevent XSS attacks
- Automatic token refresh to maintain session without user intervention
- Proper error handling that doesn't leak sensitive information

**Learning Outcomes**:
- Implement complete OAuth 2.0 + OIDC client from scratch
- Understand public client security challenges and PKCE solutions
- Learn secure token storage and management strategies
- Practice React state management for authentication workflows
- Experience real-world API integration with Bearer token authentication
- Gain understanding of SPA security considerations and best practices

**Integration Points**:
- **Phase 1 Resource Server**: Consumes Notes API with Bearer token authentication
- **Phase 2 Identity Provider**: Authenticates users via OAuth 2.0 + OIDC flows
- **Complete Ecosystem**: Demonstrates full-stack OIDC implementation

This phase completes the full-stack OIDC + OAuth 2.0 learning application, providing hands-on experience with every component of a modern authentication and authorization system from Identity Provider to Resource Server to client application.