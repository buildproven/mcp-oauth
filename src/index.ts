/** Package version, kept in step with package.json by tests/version.test.ts. */
export const VERSION = '0.1.0'

export {
  AUTHORIZE_PATH,
  GITHUB_CALLBACK_PATH,
  JWKS_PATH,
  MCP_PATH,
  METADATA_PATH,
  REGISTER_PATH,
  TOKEN_PATH,
  createOAuthServer,
  redirectMatches,
} from './oauth-server.js'
export type { FetchFn, OAuthServer, OAuthServerOptions } from './oauth-server.js'
export { GrantStoreError, createMemoryGrantStore } from './grant-store.js'
export type { GrantStore } from './grant-store.js'
