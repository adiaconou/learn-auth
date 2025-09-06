import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  
  // Development server configuration
  server: {
    port: 5173,
    host: true, // Allow external connections
    cors: true, // Enable CORS for development
    hmr: {
      port: 5173,
    },
  },
  
  // Build configuration
  build: {
    target: 'es2015',
    outDir: 'dist',
    sourcemap: true,
    minify: 'esbuild',
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html'),
      },
    },
  },
  
  // Environment variable handling
  define: {
    // Make environment variables available in the client
    __DEV__: JSON.stringify(process.env.NODE_ENV === 'development'),
  },
  
  // Path resolution
  resolve: {
    alias: {
      '@': resolve(__dirname, './src'),
      '@components': resolve(__dirname, './src/components'),
      '@pages': resolve(__dirname, './src/pages'),
      '@services': resolve(__dirname, './src/services'),
      '@utils': resolve(__dirname, './src/utils'),
      '@types': resolve(__dirname, './src/types'),
      '@hooks': resolve(__dirname, './src/hooks'),
      '@contexts': resolve(__dirname, './src/contexts'),
      '@config': resolve(__dirname, './src/config'),
    },
  },
  
  // Environment variables that should be exposed to the client
  envPrefix: 'VITE_',
  
  // CSS configuration
  css: {
    devSourcemap: true,
  },
  
  // Optimize dependencies
  optimizeDeps: {
    include: ['react', 'react-dom', 'react-router-dom'],
  },
})