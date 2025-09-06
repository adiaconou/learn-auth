import React, { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { authService } from '../services/auth'

/**
 * OAuth Callback Page Component
 * 
 * Handles the OAuth 2.0 authorization callback from the Identity Provider.
 * This page processes the authorization code and completes the token exchange.
 * 
 * Key responsibilities:
 * - Extract authorization code and state from URL parameters
 * - Validate OAuth response for errors
 * - Process callback via AuthService
 * - Handle success/error states appropriately
 * - Redirect user after successful authentication
 */

interface CallbackState {
  loading: boolean;
  error: string | null;
  success: boolean;
}

const CallbackPage: React.FC = () => {
  const navigate = useNavigate();
  const [state, setState] = useState<CallbackState>({
    loading: true,
    error: null,
    success: false,
  });

  useEffect(() => {
    const processCallback = async () => {
      console.log('🔄 OAuth callback page loaded');
      console.log(`   • URL: ${window.location.href}`);
      
      try {
        // Extract URL parameters from callback
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const state = urlParams.get('state');
        const error = urlParams.get('error');
        const errorDescription = urlParams.get('error_description');
        const errorUri = urlParams.get('error_uri');

        console.log('📋 Callback parameters extracted:');
        console.log(`   • Code: ${code ? code.substring(0, 8) + '...' : 'not provided'}`);
        console.log(`   • State: ${state || 'not provided'}`);
        console.log(`   • Error: ${error || 'none'}`);

        // Check for OAuth error response
        if (error) {
          console.error('❌ OAuth error received from Identity Provider:');
          console.error(`   • Error: ${error}`);
          console.error(`   • Description: ${errorDescription || 'No description provided'}`);
          console.error(`   • URI: ${errorUri || 'No documentation URI provided'}`);
          
          throw new Error(
            errorDescription || 
            `OAuth error: ${error}` ||
            'Authentication failed - no error details provided'
          );
        }

        // Validate required parameters
        if (!code) {
          throw new Error('Authorization code not found in callback URL');
        }

        if (!state) {
          throw new Error('State parameter not found in callback URL - possible CSRF attack');
        }

        console.log('✅ Callback parameters validated, processing authentication...');

        // Process callback through auth service
        const result = await authService.handleCallback(code, state);
        
        console.log('🎉 Authentication completed successfully!');
        console.log(`   • User ID: ${result.user.sub}`);
        console.log(`   • Email: ${result.user.email || 'not provided'}`);
        console.log(`   • Token expires: ${new Date(result.tokens.expiresAt).toISOString()}`);

        // Update state to show success
        setState({
          loading: false,
          error: null,
          success: true,
        });

        // Redirect to home page after brief success message
        setTimeout(() => {
          console.log('🏠 Redirecting to home page...');
          navigate('/', { replace: true });
        }, 2000);

      } catch (error) {
        console.error('❌ Callback processing failed:', error);
        
        const errorMessage = error instanceof Error 
          ? error.message 
          : 'Authentication failed - unknown error occurred';

        setState({
          loading: false,
          error: errorMessage,
          success: false,
        });

        // Redirect to login page after error delay
        setTimeout(() => {
          console.log('🔄 Redirecting to login page after error...');
          navigate('/login', { replace: true });
        }, 5000);
      }
    };

    // Start callback processing
    processCallback();
  }, [navigate]);

  // Loading state
  if (state.loading) {
    return (
      <div style={{ 
        padding: '3rem', 
        textAlign: 'center',
        maxWidth: '600px',
        margin: '0 auto'
      }}>
        <div style={{
          background: 'white',
          borderRadius: '12px',
          padding: '3rem 2rem',
          boxShadow: '0 4px 20px rgba(0, 0, 0, 0.1)',
          border: '1px solid #e5e7eb'
        }}>
          <h2 style={{ 
            color: '#2c3e50',
            marginBottom: '1rem',
            fontSize: '1.5rem'
          }}>
            Processing Authentication
          </h2>
          
          <p style={{ 
            color: '#6b7280',
            marginBottom: '2rem',
            fontSize: '1rem'
          }}>
            Completing your login with the Identity Provider...
          </p>
          
          {/* Loading spinner */}
          <div style={{ 
            width: '48px', 
            height: '48px', 
            border: '4px solid #f1f5f9',
            borderTop: '4px solid #3498db',
            borderRadius: '50%',
            animation: 'spin 1s linear infinite',
            margin: '0 auto'
          }} />
          
          <div style={{ 
            marginTop: '2rem',
            fontSize: '0.875rem',
            color: '#9ca3af'
          }}>
            <p>• Validating authorization code</p>
            <p>• Exchanging tokens</p>
            <p>• Verifying identity</p>
          </div>
        </div>
      </div>
    );
  }

  // Error state
  if (state.error) {
    return (
      <div style={{ 
        padding: '3rem', 
        textAlign: 'center',
        maxWidth: '600px',
        margin: '0 auto'
      }}>
        <div style={{
          background: 'white',
          borderRadius: '12px',
          padding: '3rem 2rem',
          boxShadow: '0 4px 20px rgba(0, 0, 0, 0.1)',
          border: '1px solid #fecaca'
        }}>
          <div style={{
            width: '64px',
            height: '64px',
            background: '#fef2f2',
            borderRadius: '50%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 1.5rem',
          }}>
            <span style={{ fontSize: '2rem', color: '#dc2626' }}>⚠️</span>
          </div>
          
          <h2 style={{ 
            color: '#dc2626',
            marginBottom: '1rem',
            fontSize: '1.5rem'
          }}>
            Authentication Failed
          </h2>
          
          <p style={{ 
            color: '#6b7280',
            marginBottom: '2rem',
            fontSize: '1rem',
            lineHeight: '1.5'
          }}>
            {state.error}
          </p>
          
          <div style={{
            padding: '1rem',
            background: '#fef9c3',
            borderRadius: '8px',
            border: '1px solid #fbbf24',
            marginBottom: '2rem'
          }}>
            <p style={{ 
              color: '#92400e',
              fontSize: '0.875rem',
              margin: 0
            }}>
              You will be automatically redirected to the login page in a few seconds.
            </p>
          </div>
          
          <button
            onClick={() => navigate('/login', { replace: true })}
            style={{
              background: '#3498db',
              color: 'white',
              border: 'none',
              padding: '0.75rem 1.5rem',
              borderRadius: '6px',
              fontSize: '1rem',
              cursor: 'pointer',
              transition: 'background-color 0.2s'
            }}
            onMouseOver={(e) => e.currentTarget.style.background = '#2980b9'}
            onMouseOut={(e) => e.currentTarget.style.background = '#3498db'}
          >
            Try Login Again
          </button>
        </div>
      </div>
    );
  }

  // Success state
  if (state.success) {
    return (
      <div style={{ 
        padding: '3rem', 
        textAlign: 'center',
        maxWidth: '600px',
        margin: '0 auto'
      }}>
        <div style={{
          background: 'white',
          borderRadius: '12px',
          padding: '3rem 2rem',
          boxShadow: '0 4px 20px rgba(0, 0, 0, 0.1)',
          border: '1px solid #d1fae5'
        }}>
          <div style={{
            width: '64px',
            height: '64px',
            background: '#ecfdf5',
            borderRadius: '50%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 1.5rem',
          }}>
            <span style={{ fontSize: '2rem', color: '#059669' }}>✅</span>
          </div>
          
          <h2 style={{ 
            color: '#059669',
            marginBottom: '1rem',
            fontSize: '1.5rem'
          }}>
            Authentication Successful!
          </h2>
          
          <p style={{ 
            color: '#6b7280',
            marginBottom: '2rem',
            fontSize: '1rem'
          }}>
            Welcome! You have been successfully authenticated.
          </p>
          
          <div style={{
            padding: '1rem',
            background: '#f0f9ff',
            borderRadius: '8px',
            border: '1px solid #0284c7',
            marginBottom: '2rem'
          }}>
            <p style={{ 
              color: '#0c4a6e',
              fontSize: '0.875rem',
              margin: 0
            }}>
              Redirecting you to the application...
            </p>
          </div>
        </div>
      </div>
    );
  }

  // Fallback (should never reach here)
  return null;
};

export default CallbackPage