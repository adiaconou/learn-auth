# Project Instructions for Claude

## IMPORTANT: Project Context
**ALWAYS read the memory-bank folder first before starting any task.** This folder contains critical project context, documentation, and guidelines that are essential for understanding the codebase and making appropriate changes.

```
memory-bank/
```

Read all files in this directory to understand:
- Project architecture and design decisions
- Coding standards and conventions
- Business logic and requirements
- Known issues and constraints
- Development workflows and best practices

## Project Overview
Full-stack OIDC + OAuth 2.0 learning application built from scratch. Includes custom Identity Provider, Resource Server (notes API), and React SPA frontend. Currently implementing Phase 1: Resource Server.

## CRITICAL: Step-by-Step Implementation Rules
**DO NOT implement multiple steps at once.** This is a learning project that must be built step-by-step:

1. **WAIT for explicit user requests** - Only implement a step when the user specifically asks for it (e.g., "implement step 3")
2. **One step at a time** - Complete only the requested step, then STOP and wait for next instruction
3. **Never assume next steps** - Do not continue to subsequent steps without explicit user request
4. **Check off completed steps** - Mark steps as completed in the implementation plan after finishing each one
5. **Use TodoWrite tool** - Track current step progress during implementation

## Todo List Management  
**Follow this process for each step:**

1. **Read Implementation Plan**: Check appropriate implementation plan (phase1/phase2/phase3) for step details
2. **Create TodoWrite Entry**: Add current step to TodoWrite as `in_progress`
3. **Implement Single Step**: Create only the file(s) specified in that step
4. **Mark Complete in BOTH places**: 
   - Check off step `[x]` in the implementation plan markdown file
   - Mark TodoWrite as `completed`
5. **STOP and WAIT**: Do not proceed to next step until user explicitly requests it

**CRITICAL**: Always update the implementation plan checkboxes `[ ]` → `[x]` when completing steps!

## Key Commands
```bash
npm run build         # Compile TypeScript to JavaScript
npm start             # Start compiled resource server (port 3000)
npm run dev           # Development mode with TypeScript auto-reload
npm run build:watch   # Watch mode TypeScript compilation
npm test              # Run tests (when implemented)
```

## Development Guidelines
- Follow the exact file structure in `phase1-implementation-plan.md`
- Implement security-first: validate all JWT tokens and scopes
- Return proper HTTP codes: 401 (invalid token) vs 403 (insufficient scope)
- Keep it simple - this is for learning, not production
- Test each component before moving to the next

## Code Documentation Standards
- **Concise but detailed**: Explain key concepts without being verbose
- **Focus on learning**: Highlight OAuth 2.0/OIDC concepts and security patterns
- **Production notes**: Mention what would be different in production systems
- **Interface documentation**: Document function parameters and return types
- **Key concepts only**: Avoid over-explaining basic programming concepts

## Testing
- Test JWT validation with mocked tokens
- Verify 401/403 responses work correctly
- Test all CRUD operations with proper scopes
- Validate JWKS endpoint integration

## Current Phase
**Phase 2: Identity Provider** - Implement OAuth 2.0 Authorization Server + OIDC Identity Provider with user authentication, PKCE authorization flows, and JWT token issuance.
- always check to see if project-brief or implementation plans need to be updated after executing a command
- always add clear documentation to code to help me understand what the code does, and explain any concepts.
- always check if a new concept needs to be add to concepts.md in memory bank