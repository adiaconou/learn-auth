/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_IDP_ISSUER: string
  readonly VITE_IDP_CLIENT_ID: string
  readonly VITE_RESOURCE_SERVER_URL: string
  readonly VITE_REDIRECT_URI: string
  readonly VITE_ENABLE_DEBUG: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}