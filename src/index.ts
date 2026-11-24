/** Package version, kept in step with package.json by tests/version.test.ts. */
export const VERSION = '0.2.0'

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
  signupMode,
} from './oauth-server.js'
export type { FetchFn, OAuthServer, OAuthServerOptions, SignupMode } from './oauth-server.js'
export { GrantStoreError, createMemoryGrantStore } from './grant-store.js'
export type { GrantStore } from './grant-store.js'
export { RESOURCE_METADATA_PATH, authorizeMcpRequest, resourceUrls } from './http-auth.js'
export type { AuthResult, AuthorizeConfig } from './http-auth.js'
