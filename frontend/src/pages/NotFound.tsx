import React from 'react'
import { Link } from 'react-router-dom'

/**
 * 404 Not Found Page Component
 * 
 * Displays when user navigates to a route that doesn't exist.
 * Provides navigation back to the home page.
 */
const NotFoundPage: React.FC = () => (
  <div style={{ padding: '2rem', textAlign: 'center' }}>
    <h2>Page Not Found</h2>
    <p>The page you're looking for doesn't exist.</p>
    <div style={{ marginTop: '2rem' }}>
      <Link to="/" style={{ color: '#3498db' }}>← Back to Home</Link>
    </div>
  </div>
)

export default NotFoundPage