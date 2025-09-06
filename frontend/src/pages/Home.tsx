import React from 'react'
import { Link } from 'react-router-dom'

/**
 * Home Page Component
 * 
 * Professional landing page for unauthenticated users.
 * Presents the Secure Notes Platform with enterprise-grade
 * trust indicators and a clear call-to-action to sign in.
 */
const HomePage: React.FC = () => (
  <div style={{ 
    minHeight: '90vh',
    background: 'linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%)',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    textAlign: 'center'
  }}>
    {/* Hero Section */}
    <div style={{ 
      maxWidth: '800px',
      padding: '0 2rem',
      marginBottom: '3rem'
    }}>
      {/* Logo/Brand */}
      <div style={{
        width: '120px',
        height: '120px',
        backgroundColor: '#667eea',
        borderRadius: '50%',
        margin: '0 auto 2rem',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontSize: '3rem',
        color: 'white',
        boxShadow: '0 10px 30px rgba(102, 126, 234, 0.3)'
      }}>
        🔐
      </div>
      
      {/* Main Heading */}
      <h1 style={{
        fontSize: '3rem',
        fontWeight: '700',
        color: '#2d3748',
        margin: '0 0 1rem 0',
        lineHeight: '1.2'
      }}>
        Secure Notes Platform
      </h1>
      
      {/* Subheading */}
      <p style={{
        fontSize: '1.25rem',
        color: '#4a5568',
        margin: '0 0 2rem 0',
        lineHeight: '1.5',
        maxWidth: '600px',
        marginLeft: 'auto',
        marginRight: 'auto'
      }}>
        Your personal notes, protected by enterprise-grade security. 
        Sign in to access your secure workspace and manage your notes with confidence.
      </p>

      {/* Call to Action */}
      <div style={{ marginBottom: '3rem' }}>
        <Link 
          to="/login" 
          style={{ 
            display: 'inline-block',
            padding: '1rem 2rem',
            fontSize: '1.1rem',
            fontWeight: '600',
            backgroundColor: '#667eea', 
            color: 'white', 
            textDecoration: 'none', 
            borderRadius: '8px',
            boxShadow: '0 4px 15px rgba(102, 126, 234, 0.4)',
            transition: 'all 0.3s ease',
            border: 'none',
            cursor: 'pointer'
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.backgroundColor = '#5a67d8';
            e.currentTarget.style.transform = 'translateY(-2px)';
            e.currentTarget.style.boxShadow = '0 6px 20px rgba(102, 126, 234, 0.5)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.backgroundColor = '#667eea';
            e.currentTarget.style.transform = 'translateY(0)';
            e.currentTarget.style.boxShadow = '0 4px 15px rgba(102, 126, 234, 0.4)';
          }}
        >
          Sign In to Your Account
        </Link>
      </div>
    </div>

    {/* Features Grid */}
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
      gap: '2rem',
      maxWidth: '900px',
      padding: '0 2rem',
      width: '100%'
    }}>
      {/* Feature 1 */}
      <div style={{
        backgroundColor: 'white',
        padding: '2rem',
        borderRadius: '12px',
        boxShadow: '0 4px 6px rgba(0, 0, 0, 0.07)',
        textAlign: 'center'
      }}>
        <div style={{ fontSize: '2.5rem', marginBottom: '1rem' }}>🔒</div>
        <h3 style={{ 
          fontSize: '1.25rem', 
          fontWeight: '600',
          color: '#2d3748',
          margin: '0 0 0.5rem 0'
        }}>
          Enterprise Security
        </h3>
        <p style={{ 
          color: '#718096',
          fontSize: '0.95rem',
          lineHeight: '1.4',
          margin: '0'
        }}>
          Protected by OAuth 2.0 and OpenID Connect with industry-standard encryption
        </p>
      </div>

      {/* Feature 2 */}
      <div style={{
        backgroundColor: 'white',
        padding: '2rem',
        borderRadius: '12px',
        boxShadow: '0 4px 6px rgba(0, 0, 0, 0.07)',
        textAlign: 'center'
      }}>
        <div style={{ fontSize: '2.5rem', marginBottom: '1rem' }}>📝</div>
        <h3 style={{ 
          fontSize: '1.25rem', 
          fontWeight: '600',
          color: '#2d3748',
          margin: '0 0 0.5rem 0'
        }}>
          Personal Notes
        </h3>
        <p style={{ 
          color: '#718096',
          fontSize: '0.95rem',
          lineHeight: '1.4',
          margin: '0'
        }}>
          Create, edit, and organize your personal notes in a secure environment
        </p>
      </div>

      {/* Feature 3 */}
      <div style={{
        backgroundColor: 'white',
        padding: '2rem',
        borderRadius: '12px',
        boxShadow: '0 4px 6px rgba(0, 0, 0, 0.07)',
        textAlign: 'center'
      }}>
        <div style={{ fontSize: '2.5rem', marginBottom: '1rem' }}>☁️</div>
        <h3 style={{ 
          fontSize: '1.25rem', 
          fontWeight: '600',
          color: '#2d3748',
          margin: '0 0 0.5rem 0'
        }}>
          Cloud Sync
        </h3>
        <p style={{ 
          color: '#718096',
          fontSize: '0.95rem',
          lineHeight: '1.4',
          margin: '0'
        }}>
          Access your notes from anywhere with automatic cloud synchronization
        </p>
      </div>
    </div>

    {/* Trust Indicators */}
    <div style={{
      marginTop: '4rem',
      padding: '1.5rem 2rem',
      backgroundColor: 'rgba(255, 255, 255, 0.8)',
      borderRadius: '8px',
      backdropFilter: 'blur(10px)',
      textAlign: 'center'
    }}>
      <p style={{
        color: '#718096',
        fontSize: '0.875rem',
        margin: '0',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '1rem',
        flexWrap: 'wrap'
      }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          🛡️ SOC 2 Compliant
        </span>
        <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          🔐 End-to-End Encrypted
        </span>
        <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          ✅ GDPR Ready
        </span>
      </p>
    </div>
  </div>
)

export default HomePage