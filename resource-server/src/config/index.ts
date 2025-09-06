interface Config {
  resourceServer: {
    port: number;
    audience: string;
    corsOrigin: string;
  };
  identityProvider: {
    port: number;
    issuer: string;
    jwksUri: string;
  };
  development: {
    enableTestMode: boolean;
    testSecret: string;
  };
}

const config: Config = {
  // Resource Server Configuration
  resourceServer: {
    port: parseInt(process.env.PORT || '3000', 10),
    audience: process.env.AUDIENCE || 'notes-api',
    corsOrigin: process.env.CORS_ORIGIN || 'http://localhost:5173' // Future frontend
  },
  
  // Identity Provider Configuration (for Phase 2)
  identityProvider: {
    port: parseInt(process.env.IDP_PORT || '3001', 10),
    issuer: process.env.ISSUER || 'http://localhost:3001',
    jwksUri: process.env.JWKS_URI || 'http://localhost:3001/.well-known/jwks.json'
  },

  // Development/Testing Configuration (Phase 1)
  development: {
    enableTestMode: process.env.NODE_ENV === 'development' || process.env.ENABLE_TEST_MODE === 'true',
    testSecret: process.env.TEST_SECRET || 'test-secret-key-for-development-only'
  }
};

export default config;