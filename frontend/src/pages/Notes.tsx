import React from 'react'
import { Link } from 'react-router-dom'

/**
 * Notes Page Component
 * 
 * Protected page that will display and manage user notes.
 * Requires authentication and demonstrates Bearer token usage
 * with the Resource Server API.
 */
const NotesPage: React.FC = () => (
  <div style={{ padding: '2rem', textAlign: 'center' }}>
    <h2>Notes</h2>
    <p>Protected notes management will be implemented here.</p>
    <div style={{ marginTop: '2rem' }}>
      <p>This page will demonstrate:</p>
      <ul style={{ display: 'inline-block', textAlign: 'left' }}>
        <li>Bearer token authentication</li>
        <li>API calls to Resource Server</li>
        <li>Scope-based authorization</li>
        <li>Automatic token refresh</li>
        <li>CRUD operations on notes</li>
      </ul>
    </div>
    <div style={{ marginTop: '2rem' }}>
      <Link to="/" style={{ color: '#3498db' }}>← Back to Home</Link>
    </div>
  </div>
)

export default NotesPage