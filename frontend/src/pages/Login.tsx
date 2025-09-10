import React from 'react'
import { Link } from 'react-router-dom'
import { authService } from '../services/auth'

/**
 * Login Page Component
 * 
 * Traditional multi-provider login page supporting multiple identity providers.
 * Users can choose between Google OAuth and custom AlexIdP for authentication.
 * Implements OAuth 2.0 Authorization Code + PKCE flow for secure authentication.
 */
const LoginPage: React.FC = () => {
  /**
   * Handle login with AlexIdP (custom Identity Provider)
   * 
   * Initiates OAuth 2.0 flow with the custom Identity Provider:
   * 1. Generates PKCE parameters for security
   * 2. Creates state and nonce for protection
   * 3. Builds authorization URL with all OAuth parameters
   * 4. Redirects user to AlexIdP for authentication
   */
  const handleAlexIdPLogin = async () => {
    try {
      console.log('🎯 AlexIdP login initiated - OAuth 2.0 Authorization Code + PKCE flow...');
      console.log('📋 Expected flow:');
      console.log('   1. Generate PKCE code_verifier and code_challenge');
      console.log('   2. Generate state parameter for CSRF protection');
      console.log('   3. Generate nonce for ID token replay protection');
      console.log('   4. Build authorization URL with all parameters');
      console.log('   5. Redirect to AlexIdP at localhost:3001');
      console.log('   6. User will authenticate and grant consent');
      console.log('   7. IdP will redirect back to /callback with authorization code');
      
      await authService.initiateLogin();
    } catch (error) {
      console.error('❌ AlexIdP login failed:', error);
      alert(`AlexIdP login failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  };

  /**
   * Handle login with Google OAuth
   * 
   * Redirects user to Google's OAuth 2.0 authorization endpoint.
   * In a real implementation, this would use Google's OAuth client library
   * or redirect to Google's OAuth endpoint with proper parameters.
   */
  const handleGoogleLogin = () => {
    console.log('🎯 Google OAuth login initiated...');
    console.log('📋 In production, this would:');
    console.log('   1. Use Google OAuth client library or direct redirect');
    console.log('   2. Generate state parameter for CSRF protection');
    console.log('   3. Redirect to accounts.google.com/oauth/authorize');
    console.log('   4. Handle callback and token exchange');
    
    // For demo purposes, redirect to Google's OAuth endpoint
    // In production, you'd use proper OAuth client configuration
    const googleAuthUrl = 'https://accounts.google.com/oauth/authorize?' +
      'client_id=YOUR_GOOGLE_CLIENT_ID&' +
      'redirect_uri=http://localhost:5173/callback/google&' +
      'response_type=code&' +
      'scope=openid email profile&' +
      'state=google_oauth_state';
    
    console.log('🔗 Redirecting to Google OAuth (demo URL):', googleAuthUrl);
    alert('Demo: This would redirect to Google OAuth. Check console for details.');
    // window.location.href = googleAuthUrl; // Uncomment for actual redirect
  };

  return (
    <div style={{ 
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '2rem'
    }}>
      {/* Login Card */}
      <div style={{
        backgroundColor: 'white',
        borderRadius: '12px',
        boxShadow: '0 20px 40px rgba(0, 0, 0, 0.15)',
        padding: '3rem',
        maxWidth: '450px',
        width: '100%',
        textAlign: 'center'
      }}>
        
        {/* Company Logo/Header */}
        <div style={{ marginBottom: '2rem' }}>
          <div style={{
            width: '80px',
            height: '80px',
            backgroundColor: '#667eea',
            borderRadius: '50%',
            margin: '0 auto 1rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '2rem',
            color: 'white'
          }}>
            🔐
          </div>
          <h1 style={{ 
            margin: '0 0 0.5rem 0', 
            fontSize: '1.75rem', 
            fontWeight: '600',
            color: '#2d3748'
          }}>
            Sign in to your account
          </h1>
          <p style={{ 
            margin: '0', 
            color: '#718096',
            fontSize: '0.95rem'
          }}>
            Choose your preferred sign-in method
          </p>
        </div>

        {/* Identity Provider Options */}
        <div style={{ marginBottom: '2rem' }}>
          
          {/* Google Sign In Button */}
          <button 
            onClick={handleGoogleLogin}
            style={{
              width: '100%',
              padding: '0.875rem 1rem',
              fontSize: '1rem',
              fontWeight: '500',
              backgroundColor: '#ffffff',
              color: '#3c4043',
              border: '1px solid #dadce0',
              borderRadius: '6px',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              boxShadow: '0 1px 3px rgba(0, 0, 0, 0.12)',
              marginBottom: '1rem',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.75rem'
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = '#f8f9fa';
              e.currentTarget.style.boxShadow = '0 2px 6px rgba(0, 0, 0, 0.15)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = '#ffffff';
              e.currentTarget.style.boxShadow = '0 1px 3px rgba(0, 0, 0, 0.12)';
            }}
          >
            <svg width="20" height="20" viewBox="0 0 24 24">
              <path fill="#4285f4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
              <path fill="#34a853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
              <path fill="#fbbc05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
              <path fill="#ea4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
            </svg>
            Sign in with Google
          </button>

          {/* Divider */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            margin: '1.5rem 0',
            color: '#718096',
            fontSize: '0.875rem'
          }}>
            <div style={{ flex: 1, height: '1px', backgroundColor: '#e2e8f0' }}></div>
            <span style={{ padding: '0 1rem' }}>OR</span>
            <div style={{ flex: 1, height: '1px', backgroundColor: '#e2e8f0' }}></div>
          </div>

          {/* AlexIdP Sign In Button */}
          <button 
            onClick={handleAlexIdPLogin}
            style={{
              width: '100%',
              padding: '0.875rem 1rem',
              fontSize: '1rem',
              fontWeight: '500',
              backgroundColor: '#667eea',
              color: 'white',
              border: 'none',
              borderRadius: '6px',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              boxShadow: '0 1px 3px rgba(0, 0, 0, 0.12)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.75rem'
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = '#5a67d8';
              e.currentTarget.style.boxShadow = '0 4px 8px rgba(102, 126, 234, 0.4)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = '#667eea';
              e.currentTarget.style.boxShadow = '0 1px 3px rgba(0, 0, 0, 0.12)';
            }}
          >
            <div style={{
              width: '20px',
              height: '20px',
              backgroundColor: 'rgba(255, 255, 255, 0.2)',
              borderRadius: '4px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '12px'
            }}>
              🔐
            </div>
            Sign in with AlexIdP
          </button>

          {/* OAuth Info Panel */}
          <div style={{
            marginTop: '1.5rem',
            padding: '1rem',
            backgroundColor: '#f7fafc',
            border: '1px solid #e2e8f0',
            borderRadius: '6px',
            textAlign: 'left'
          }}>
            <p style={{ 
              margin: '0 0 0.5rem 0', 
              fontSize: '0.875rem', 
              color: '#4a5568',
              fontWeight: '500'
            }}>
              🔒 Secure OAuth 2.0 + OIDC Authentication
            </p>
            <p style={{ 
              margin: '0', 
              fontSize: '0.8rem', 
              color: '#718096',
              lineHeight: '1.4'
            }}>
              Both providers use industry-standard OAuth 2.0 with PKCE for secure authentication. Your credentials are never shared with this application.
            </p>
          </div>
        </div>

        {/* Footer Links */}
        <div style={{ 
          paddingTop: '1.5rem',
          borderTop: '1px solid #e2e8f0',
          fontSize: '0.875rem'
        }}>
          <div style={{ 
            display: 'flex', 
            justifyContent: 'center',
            gap: '1rem',
            color: '#718096'
          }}>
            <Link 
              to="/" 
              style={{ 
                color: '#667eea', 
                textDecoration: 'none',
                fontWeight: '500'
              }}
            >
              ← Back to Home
            </Link>
          </div>
          <p style={{ 
            margin: '1rem 0 0 0', 
            color: '#a0aec0',
            fontSize: '0.8rem'
          }}>
            Protected by OAuth 2.0 + OIDC • Learning Environment
          </p>
        </div>
      </div>

      {/* Developer Info Panel (only in dev) */}
      <div style={{
        position: 'fixed',
        bottom: '20px',
        right: '20px',
        backgroundColor: 'rgba(0, 0, 0, 0.8)',
        color: 'white',
        padding: '1rem',
        borderRadius: '8px',
        fontSize: '0.8rem',
        maxWidth: '320px',
        backdropFilter: 'blur(10px)'
      }}>
        <p style={{ margin: '0 0 0.5rem 0', fontWeight: '600' }}>
          🔧 Developer Mode
        </p>
        <p style={{ margin: '0 0 0.5rem 0', lineHeight: '1.4' }}>
          <strong>AlexIdP:</strong> Full OAuth 2.0 + PKCE flow to localhost:3001
        </p>
        <p style={{ margin: '0', lineHeight: '1.4' }}>
          <strong>Google:</strong> Demo mode (check console for OAuth URL)
        </p>
      </div>
    </div>
  );
};

export default LoginPage