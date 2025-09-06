import React from 'react'
import { Link } from 'react-router-dom'

/**
 * User Profile Page Component
 * 
 * Protected page that displays user information from the ID token.
 * Demonstrates OIDC identity claims and token introspection.
 */
const ProfilePage: React.FC = () => (
  <div style={{ padding: '2rem', textAlign: 'center' }}>
    <h2>User Profile</h2>
    <p>User information from ID token will be displayed here.</p>
    <div style={{ marginTop: '2rem' }}>
      <p>This page will show:</p>
      <ul style={{ display: 'inline-block', textAlign: 'left' }}>
        <li>User ID (sub claim)</li>
        <li>Email address</li>
        <li>Display name</li>
        <li>Authentication time</li>
        <li>Token expiration details</li>
      </ul>
    </div>
    <div style={{ marginTop: '2rem' }}>
      <Link to="/" style={{ color: '#3498db' }}>← Back to Home</Link>
    </div>
  </div>
)

export default ProfilePage