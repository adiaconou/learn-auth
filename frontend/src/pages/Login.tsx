import React from 'react'
import { Link } from 'react-router-dom'
import { authService } from '../services/auth'

/**
 * Login Page Component
 * 
 * Professional login page designed to match enterprise Identity Provider
 * experience (similar to Okta, Auth0, Azure AD). Initiates OAuth 2.0
 * Authorization Code + PKCE flow when user clicks login.
 */
const LoginPage: React.FC = () => {
  /**
   * Handle OAuth 2.0 login initiation
   * 
   * This function starts the complete OAuth flow by:
   * 1. Generating PKCE parameters for security
   * 2. Creating state and nonce for protection
   * 3. Building authorization URL with all OAuth parameters
   * 4. Redirecting user to Identity Provider for authentication
   */
  const handleLogin = async () => {
    try {
      console.log('🎯 Login button clicked - initiating OAuth 2.0 Authorization Code + PKCE flow...');
      console.log('📋 Expected flow:');
      console.log('   1. Generate PKCE code_verifier and code_challenge');
      console.log('   2. Generate state parameter for CSRF protection');
      console.log('   3. Generate nonce for ID token replay protection');
      console.log('   4. Build authorization URL with all parameters');
      console.log('   5. Redirect to Identity Provider at localhost:3001');
      console.log('   6. User will authenticate and grant consent');
      console.log('   7. IdP will redirect back to /callback with authorization code');
      
      await authService.initiateLogin();
    } catch (error) {
      console.error('❌ Login initiation failed:', error);
      alert(`Login failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
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
            Learning Identity Provider
          </h1>
          <p style={{ 
            margin: '0', 
            color: '#718096',
            fontSize: '0.95rem'
          }}>
            Sign in to access your account
          </p>
        </div>

        {/* Login Form Area */}
        <div style={{ marginBottom: '2rem' }}>
          <div style={{
            padding: '1.5rem',
            backgroundColor: '#f7fafc',
            border: '1px solid #e2e8f0',
            borderRadius: '8px',
            marginBottom: '1.5rem',
            textAlign: 'left'
          }}>
            <h3 style={{ 
              margin: '0 0 1rem 0', 
              fontSize: '1rem',
              color: '#2d3748',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem'
            }}>
              <span style={{ 
                display: 'inline-block',
                width: '20px',
                height: '20px',
                backgroundColor: '#667eea',
                borderRadius: '50%',
                fontSize: '12px',
                color: 'white',
                textAlign: 'center',
                lineHeight: '20px'
              }}>
                i
              </span>
              OAuth 2.0 + OIDC Authentication
            </h3>
            <p style={{ 
              margin: '0 0 1rem 0', 
              fontSize: '0.875rem', 
              color: '#4a5568',
              lineHeight: '1.5'
            }}>
              This application uses industry-standard OAuth 2.0 with PKCE for secure authentication.
            </p>
            <details style={{ fontSize: '0.875rem', color: '#718096' }}>
              <summary style={{ 
                cursor: 'pointer', 
                fontWeight: '500',
                marginBottom: '0.5rem',
                color: '#667eea'
              }}>
                View technical details
              </summary>
              <ul style={{ 
                margin: '0', 
                paddingLeft: '1.25rem',
                lineHeight: '1.4'
              }}>
                <li>Authorization Code Flow with PKCE (RFC 7636)</li>
                <li>OpenID Connect for identity information</li>
                <li>State parameter for CSRF protection</li>
                <li>Nonce for token replay protection</li>
                <li>Secure token exchange and storage</li>
              </ul>
            </details>
          </div>

          {/* Sign In Button */}
          <button 
            onClick={handleLogin}
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
              boxShadow: '0 1px 3px rgba(0, 0, 0, 0.12)'
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
            Continue with Identity Provider
          </button>
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
        maxWidth: '300px',
        backdropFilter: 'blur(10px)'
      }}>
        <p style={{ margin: '0 0 0.5rem 0', fontWeight: '600' }}>
          🔧 Developer Mode
        </p>
        <p style={{ margin: '0', lineHeight: '1.4' }}>
          Open browser console (F12) to view detailed OAuth flow logging when you click "Continue".
        </p>
      </div>
    </div>
  );
};

export default LoginPage