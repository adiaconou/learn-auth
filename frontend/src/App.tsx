import React from 'react'
import { BrowserRouter, Routes, Route, Link } from 'react-router-dom'
import HomePage from './pages/Home'
import LoginPage from './pages/Login'
import CallbackPage from './pages/Callback'
import NotesPage from './pages/Notes'
import ProfilePage from './pages/Profile'
import NotFoundPage from './pages/NotFound'

/**
 * Main Application Component
 * 
 * This is the root component of the OAuth 2.0 + OIDC learning application.
 * It sets up basic routing and navigation structure for the SPA.
 * 
 * Key responsibilities:
 * - Initialize React Router for SPA navigation
 * - Define route structure for all pages
 * - Provide basic navigation between pages
 * - Establish foundation for authentication integration
 * 
 * Authentication Flow Integration (Future):
 * - Will be wrapped with AuthProvider context
 * - Protected routes will require authentication
 * - Navigation will show/hide based on auth status
 */

/**
 * Basic Navigation Component
 * 
 * Simple navigation bar that will later be enhanced with:
 * - Authentication status display
 * - User profile dropdown
 * - Login/logout buttons
 * - Conditional navigation based on auth state
 */
const Navigation: React.FC = () => (
  <nav style={{ 
    padding: '1rem 2rem', 
    backgroundColor: '#2c3e50', 
    color: 'white',
    borderBottom: '3px solid #3498db'
  }}>
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
      <Link 
        to="/" 
        style={{ 
          color: 'white', 
          textDecoration: 'none', 
          fontSize: '1.25rem', 
          fontWeight: 'bold' 
        }}
      >
        OAuth 2.0 Learning App
      </Link>
      <div style={{ display: 'flex', gap: '1rem' }}>
        <Link 
          to="/" 
          style={{ color: 'white', textDecoration: 'none' }}
        >
          Home
        </Link>
        <Link 
          to="/login" 
          style={{ color: 'white', textDecoration: 'none' }}
        >
          Login
        </Link>
        <Link 
          to="/notes" 
          style={{ color: 'white', textDecoration: 'none' }}
        >
          Notes
        </Link>
        <Link 
          to="/profile" 
          style={{ color: 'white', textDecoration: 'none' }}
        >
          Profile
        </Link>
      </div>
    </div>
  </nav>
)

/**
 * Main App Component
 * 
 * Sets up the complete routing structure for the OAuth 2.0 learning application.
 * This basic version will be enhanced in later steps with:
 * - Authentication context provider
 * - Protected routes
 * - Dynamic navigation based on auth state
 * - Error boundaries for route-specific errors
 */
const App: React.FC = () => {
  return (
    <BrowserRouter>
      <div style={{ minHeight: '100vh', backgroundColor: '#f8f9fa' }}>
        <Navigation />
        
        <main>
          <Routes>
            {/* Public Routes */}
            <Route path="/" element={<HomePage />} />
            <Route path="/login" element={<LoginPage />} />
            <Route path="/callback" element={<CallbackPage />} />
            
            {/* Protected Routes (will be wrapped with ProtectedRoute component later) */}
            <Route path="/notes" element={<NotesPage />} />
            <Route path="/profile" element={<ProfilePage />} />
            
            {/* 404 Catch-all Route */}
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}

export default App