/**
 * OAuth 2.0 Authorization Endpoint
 * 
 * Implements the OAuth 2.0 authorization endpoint as defined in RFC 6749.
 * This endpoint handles authorization requests from OAuth clients and initiates
 * the authorization code flow with PKCE (RFC 7636) for public clients.
 * 
 * Key OAuth 2.0 Flow Steps:
 * 1. Validate authorization request parameters
 * 2. Authenticate user (redirect to login if needed)
 * 3. Check for existing consent or show consent screen
 * 4. Generate authorization code with PKCE challenge
 * 5. Redirect back to client with authorization code
 * 
 * Security Features:
 * - Exact redirect URI matching
 * - State parameter validation (CSRF protection)
 * - PKCE requirement enforcement for public clients
 * - Scope validation and filtering
 * - Session-based user authentication
 * 
 * Required Parameters:
 * - response_type: Must be "code" (authorization code flow)
 * - client_id: Registered OAuth client identifier
 * - redirect_uri: Must match registered redirect URI exactly
 * - scope: Requested scopes (space-separated)
 * - state: CSRF protection parameter
 * - code_challenge: PKCE challenge (Base64 URL-encoded SHA256)
 * - code_challenge_method: Must be "S256"
 * 
 * Optional Parameters:
 * - nonce: OpenID Connect replay protection
 */

import { Router, Request, Response } from 'express';
import { clientService } from '../services/client';
import { pkceService } from '../services/pkce';
import { authorizationService } from '../services/authorization';
import { userStore, consentStore } from '../storage/memory';
import { debugLog } from '../config';

const router = Router();

/**
 * Authorization Request Interface
 * 
 * Defines the structure of incoming authorization requests with validation.
 */
interface AuthorizeRequest {
  response_type: string;
  client_id: string;
  redirect_uri: string;
  scope: string;
  state: string;
  code_challenge?: string;
  code_challenge_method?: string;
  nonce?: string;
}

/**
 * Authorization Error Response
 * 
 * Standard OAuth 2.0 error response format for authorization endpoint.
 */
interface AuthorizeError {
  error: string;
  error_description?: string;
  error_uri?: string;
  state?: string;
}

/**
 * GET /authorize - OAuth 2.0 Authorization Endpoint
 * 
 * Handles authorization requests from OAuth clients. This is the first step
 * in the OAuth 2.0 authorization code flow where the client redirects the
 * user to request authorization.
 * 
 * Flow:
 * 1. Validate all query parameters
 * 2. Validate client and PKCE requirements
 * 3. Check user authentication status
 * 4. Check existing consent or show consent screen
 * 5. Generate authorization code and redirect
 * 
 * Success Response: Redirect to client with authorization code
 * Error Response: Redirect to client with error parameters (if redirect_uri is valid)
 */
router.get('/', async (req: Request, res: Response) => {
  debugLog('AUTHORIZE', 'Authorization request received');
  debugLog('AUTHORIZE', `Query params: ${JSON.stringify(req.query)}`);
  
  try {
    // Step 1: Extract and validate query parameters
    const authRequest = extractAuthRequest(req);
    if (!authRequest.isValid) {
      return sendErrorResponse(res, authRequest.error!, authRequest.redirect_uri, authRequest.state);
    }
    
    const params = authRequest.params!;
    debugLog('AUTHORIZE', `Processing request for client: ${params.client_id}`);
    
    // Step 2: Validate OAuth client
    const clientValidation = clientService.validateClient(
      params.client_id,
      params.code_challenge,
      params.code_challenge_method
    );
    
    if (!clientValidation.isValid) {
      debugLog('AUTHORIZE', `Client validation failed: ${clientValidation.error}`);
      return sendErrorResponse(res, {
        error: clientValidation.error!,
        error_description: clientValidation.errorDescription,
        state: params.state
      }, params.redirect_uri);
    }
    
    const client = clientValidation.client!;
    debugLog('AUTHORIZE', `Client validated: ${client.name}`);
    
    // Step 3: Validate redirect URI
    const redirectValidation = clientService.validateRedirectUri(client, params.redirect_uri);
    if (!redirectValidation.isValid) {
      debugLog('AUTHORIZE', `Redirect URI validation failed: ${redirectValidation.error}`);
      // Cannot redirect to invalid redirect_uri, return error directly
      return res.status(400).json({
        error: redirectValidation.error,
        error_description: redirectValidation.errorDescription
      });
    }
    
    // Step 4: Validate requested scopes
    const scopeValidation = clientService.validateScopes(client, params.scope);
    if (!scopeValidation.isValid) {
      debugLog('AUTHORIZE', `Scope validation failed: ${scopeValidation.error}`);
      return sendErrorResponse(res, {
        error: scopeValidation.error!,
        error_description: scopeValidation.errorDescription,
        state: params.state
      }, params.redirect_uri);
    }
    
    const grantedScopes = scopeValidation.grantedScopes;
    debugLog('AUTHORIZE', `Scopes validated: ${grantedScopes.join(' ')}`);
    
    // Step 5: Validate PKCE challenge (for clients that require it)
    if (params.code_challenge && params.code_challenge_method) {
      const pkceValidation = pkceService.validateChallenge(
        params.code_challenge,
        params.code_challenge_method
      );
      
      if (!pkceValidation.isValid) {
        debugLog('AUTHORIZE', `PKCE validation failed: ${pkceValidation.error}`);
        return sendErrorResponse(res, {
          error: pkceValidation.error!,
          error_description: pkceValidation.errorDescription,
          state: params.state
        }, params.redirect_uri);
      }
    }
    
    // Step 6: Check user authentication
    const sessionUser = (req.session as any)?.user;
    if (!sessionUser || !sessionUser.id) {
      debugLog('AUTHORIZE', 'User not authenticated, redirecting to login');
      // Store authorization request in session for post-login redirect
      (req.session as any).authorizationRequest = params;
      
      // Add 15-second delay for reading console output
      setTimeout(() => {
        res.redirect(`/login?${new URLSearchParams({
          return_to: req.originalUrl
        }).toString()}`);
      }, 15000);
      return;
    }
    
    const userId = sessionUser.id;
    
    // Verify user still exists in storage
    const user = userStore.findById(userId);
    if (!user || !user.isActive) {
      debugLog('AUTHORIZE', 'User session invalid, redirecting to login');
      delete (req.session as any).user;
      (req.session as any).authorizationRequest = params;
      
      // Add 15-second delay for reading console output
      setTimeout(() => {
        res.redirect(`/login?${new URLSearchParams({
          return_to: req.originalUrl
        }).toString()}`);
      }, 15000);
      return;
    }
    
    debugLog('AUTHORIZE', `User authenticated: ${user.username}`);
    
    // Step 7: Check existing consent
    const scopeString = grantedScopes.join(' ');
    const hasConsent = consentStore.hasConsent(userId, client.id, scopeString);
    
    if (!hasConsent && clientService.requiresConsent(client, grantedScopes)) {
      debugLog('AUTHORIZE', 'User consent required, redirecting to consent screen');
      // Store authorization request for post-consent redirect
      (req.session as any).authorizationRequest = params;
      (req.session as any).grantedScopes = grantedScopes;
      return res.redirect('/consent');
    }
    
    debugLog('AUTHORIZE', 'Consent check passed, generating authorization code');
    
    // Step 8: Generate authorization code
    const authorizationRequest = {
      clientId: client.id,
      userId: user.id,
      redirectUri: params.redirect_uri,
      scope: scopeString,
      nonce: params.nonce,
      codeChallenge: params.code_challenge,
      codeChallengeMethod: params.code_challenge_method
    };
    
    const codeResult = authorizationService.generateAuthorizationCode(authorizationRequest);
    debugLog('AUTHORIZE', `Authorization code generated: ${codeResult.code.substring(0, 8)}...`);
    
    // Step 9: Redirect back to client with authorization code
    const redirectUrl = new URL(params.redirect_uri);
    redirectUrl.searchParams.set('code', codeResult.code);
    redirectUrl.searchParams.set('state', params.state);
    
    debugLog('AUTHORIZE', `Redirecting to client: ${redirectUrl.origin}`);
    res.redirect(redirectUrl.toString());
    
  } catch (error) {
    debugLog('AUTHORIZE', `Authorization error: ${error}`);
    
    // Try to extract redirect_uri and state for error response
    const redirect_uri = req.query.redirect_uri as string;
    const state = req.query.state as string;
    
    if (redirect_uri) {
      return sendErrorResponse(res, {
        error: 'server_error',
        error_description: 'Authorization server encountered an unexpected condition',
        state
      }, redirect_uri);
    } else {
      // No valid redirect_uri, return error directly
      return res.status(500).json({
        error: 'server_error',
        error_description: 'Authorization server encountered an unexpected condition'
      });
    }
  }
});

/**
 * Extract and validate authorization request parameters
 * 
 * Validates required OAuth 2.0 parameters and returns structured request object.
 * 
 * @param req Express request object
 * @returns Validation result with parsed parameters
 */
function extractAuthRequest(req: Request): {
  isValid: boolean;
  params?: AuthorizeRequest;
  error?: AuthorizeError;
  redirect_uri?: string;
  state?: string;
} {
  const query = req.query;
  
  // Extract parameters
  const response_type = query.response_type as string;
  const client_id = query.client_id as string;
  const redirect_uri = query.redirect_uri as string;
  const scope = query.scope as string;
  const state = query.state as string;
  const code_challenge = query.code_challenge as string;
  const code_challenge_method = query.code_challenge_method as string;
  const nonce = query.nonce as string;
  
  // Validate required parameters
  if (!response_type) {
    return {
      isValid: false,
      error: { error: 'invalid_request', error_description: 'Missing response_type parameter' },
      redirect_uri,
      state
    };
  }
  
  if (response_type !== 'code') {
    return {
      isValid: false,
      error: { 
        error: 'unsupported_response_type', 
        error_description: 'Only response_type=code is supported' 
      },
      redirect_uri,
      state
    };
  }
  
  if (!client_id) {
    return {
      isValid: false,
      error: { error: 'invalid_request', error_description: 'Missing client_id parameter' },
      redirect_uri,
      state
    };
  }
  
  if (!redirect_uri) {
    return {
      isValid: false,
      error: { error: 'invalid_request', error_description: 'Missing redirect_uri parameter' },
      redirect_uri,
      state
    };
  }
  
  if (!scope) {
    return {
      isValid: false,
      error: { error: 'invalid_request', error_description: 'Missing scope parameter' },
      redirect_uri,
      state
    };
  }
  
  if (!state) {
    return {
      isValid: false,
      error: { error: 'invalid_request', error_description: 'Missing state parameter' },
      redirect_uri,
      state
    };
  }
  
  // Validate redirect_uri format
  try {
    new URL(redirect_uri);
  } catch (error) {
    return {
      isValid: false,
      error: { error: 'invalid_request', error_description: 'Invalid redirect_uri format' },
      redirect_uri,
      state
    };
  }
  
  return {
    isValid: true,
    params: {
      response_type,
      client_id,
      redirect_uri,
      scope,
      state,
      code_challenge,
      code_challenge_method,
      nonce
    }
  };
}

/**
 * Send OAuth 2.0 error response
 * 
 * Redirects to client with error parameters according to OAuth 2.0 spec.
 * If redirect_uri is invalid, returns error directly.
 * 
 * @param res Express response object
 * @param error Error details
 * @param redirect_uri Client redirect URI
 * @param state Optional state parameter
 */
function sendErrorResponse(
  res: Response,
  error: AuthorizeError,
  redirect_uri?: string,
  state?: string
): void {
  
  if (!redirect_uri) {
    // Cannot redirect without valid redirect_uri
    res.status(400).json(error);
    return;
  }
  
  try {
    const redirectUrl = new URL(redirect_uri);
    
    // Add error parameters
    redirectUrl.searchParams.set('error', error.error);
    if (error.error_description) {
      redirectUrl.searchParams.set('error_description', error.error_description);
    }
    if (error.error_uri) {
      redirectUrl.searchParams.set('error_uri', error.error_uri);
    }
    if (state) {
      redirectUrl.searchParams.set('state', state);
    }
    
    debugLog('AUTHORIZE', `Redirecting with error: ${error.error}`);
    res.redirect(redirectUrl.toString());
    
  } catch (urlError) {
    // Invalid redirect_uri, return error directly
    res.status(400).json(error);
  }
}


export default router;