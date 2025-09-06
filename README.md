# OAuth 2.0 + OIDC Learning Application

A complete, from-scratch implementation of OAuth 2.0 Authorization Server, OpenID Connect Identity Provider, and Resource Server for learning purposes.

## 🎯 Project Overview

This project implements a full OAuth 2.0 + OIDC ecosystem including:

- **Identity Provider** (Phase 2) - Custom OAuth 2.0 Authorization Server + OIDC IdP
- **Resource Server** (Phase 1) - JWT-secured Notes API with scope-based authorization  
- **Frontend SPA** (Phase 3) - React application with PKCE OAuth flow

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Frontend      │───→│  Identity        │───→│  Resource       │
│   React SPA     │    │  Provider        │    │  Server         │
│   (Phase 3)     │    │  (Phase 2)       │    │  (Phase 1)      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ 
- npm

### Installation
```bash
# Clone repository
git clone <repository-url>
cd auth

# Install dependencies
npm install

# Install frontend dependencies
cd frontend && npm install && cd ..

# Install identity provider dependencies  
cd identity-provider && npm install && cd ..
```

### Development

**Start Resource Server (Phase 1)**
```bash
cd resource-server
npm run dev  # Runs on http://localhost:3000
```

**Start Identity Provider (Phase 2)**  
```bash
cd identity-provider
npm run dev  # Runs on http://localhost:3001
```

**Start Frontend (Phase 3)**
```bash
cd frontend
npm run dev  # Runs on http://localhost:5173
```

## 🔐 Demo Credentials

**Test Users:**
- Username: `testuser` / Password: `password123`
- Username: `alice` / Password: `alice123`

## 📚 Learning Objectives

- Understand OAuth 2.0 Authorization Code + PKCE flow
- Learn OpenID Connect (OIDC) implementation
- Practice JWT token generation and validation
- Implement secure session management
- Build consent and authorization flows
- Create scope-based API authorization

## 🛠️ Technology Stack

- **Backend:** Node.js, Express.js, TypeScript
- **Frontend:** React, TypeScript, Vite
- **Security:** JWT, bcrypt, PKCE, CORS
- **Development:** nodemon, concurrently

## 📖 Documentation

See `memory-bank/` folder for detailed:
- Architecture decisions
- Implementation plans  
- Security considerations
- Phase-by-phase development guide

## 🔒 Security Features

- PKCE (Proof Key for Code Exchange) for public clients
- JWT access tokens with RSA signatures
- Secure session management with HTTP-only cookies
- CSRF protection on forms
- Scope-based API authorization
- State parameter validation

## 🧪 Testing

```bash
# Test Resource Server
cd resource-server && npm test

# Test Identity Provider  
cd identity-provider && npm test

# Test Frontend
cd frontend && npm test
```

## 📋 Current Status

- ✅ **Phase 1:** Resource Server (JWT validation, CRUD API)
- 🚧 **Phase 2:** Identity Provider (Login endpoints implemented)  
- ⏳ **Phase 3:** Frontend SPA (Pending)

## 🤝 Contributing

This is a learning project. Feel free to explore, modify, and experiment!

## 📄 License

MIT License - See LICENSE file for details