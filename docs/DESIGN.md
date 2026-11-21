# Design

## Why

jobrecon and retire-runway each carry a ~1,300-line copy of the same OAuth server (`mcp/oauth-server.ts`,
`src/mcp/oauth-server.ts`) and its resource-server checks (`http-auth.ts`); on 2026-11-21 the copies differed in 246
lines (jobrecon added loopback redirects on any port, `redirectMatches`). wander-page and every later hosted product
need the same server. One package keeps one tested copy.

## Shape

- `createOAuthServer({ prefix, grantStore, env?, now?, fetch?, resolver?, randomId? })` returns the handlers for
  `/oauth/authorize`, `/oauth/token`, `/oauth/register`, `/oauth/jwks`, `/oauth/github/callback`, and the
  `/.well-known/oauth-authorization-server` metadata (`metadata`, `jwks`, `register`, `authorize`, `githubCallback`,
  `token`, `preflight`). The route paths are exported as constants. `prefix` is upper case (`WANDERPAGE`); the server
  throws at creation for another form, and for a `grantStore` without `claim` and `has`.
- Env names derive from `prefix`: `<PREFIX>_OAUTH_ISSUER`, `<PREFIX>_OAUTH_SIGNING_KEY`,
  `<PREFIX>_GITHUB_OAUTH_CLIENT_ID`, `<PREFIX>_GITHUB_OAUTH_CLIENT_SECRET`. Optional: `<PREFIX>_SSRF_BLOCKED_DOMAINS`, a comma-separated list added to the SSRF blocklist (from the injected `env`, not `process.env`). The owner login is `OWNER_GITHUB_LOGIN`.
  Settings are read on each request. A missing or unusable setting answers `500` with `error_description` and
  `missing` / `invalid` naming the variable; the value is never printed. No other prefix is read.
- The `typ` and `aud` of each signed value, the sign-in nonce cookie and the GitHub `user-agent` carry the lower-case
  prefix (`wanderpage-code+jwt`, `urn:wanderpage:code`, `wanderpage_oauth_nonce`), so products never mix their values.
  A product moving from its own copy of the server re-registers its clients once.
- `GrantStore { claim(id, expiresAt), has(id) }` records spent codes (`code:<jti>`), spent refresh tokens
  (`refresh:<jti>`) and revoked token families (`family:<id>`). `expiresAt` is in seconds. The package ships
  `createMemoryGrantStore` for tests and single-process use; each product supplies its own adapter (private git repo,
  Postgres) and keeps its GitHub App token code. A store rejects with `GrantStoreError`: the server then issues no
  token, logs the message, and answers `503` without it (unless `ownerAction` is set, for a setup step the owner must
  take). Any other error from a store is a bug and is not caught.
- `src/ssrf-protection.ts` guards client ID metadata document URLs: https on port 443, a host that resolves only to
  public unicast addresses, and a fetch pinned to the checked address with no redirect and a size limit.
- `authorizeMcpRequest(request, { prefix, env?, keys? })` checks the bearer token for the MCP route (`src/http-auth.ts`,
  moved from jobrecon `mcp/http-auth.ts`). It reads `<PREFIX>_OAUTH_ISSUER`, `<PREFIX>_OAUTH_JWKS_URL` and
  `<PREFIX>_OWNER_SUBJECT` on each request and accepts only an asymmetric JWT with that `iss`, `aud` = the MCP URL,
  `sub` and `exp`. Answers: `503` naming each missing or non-https setting (before the token is read), `401` with
  `WWW-Authenticate: Bearer resource_metadata="<origin>/.well-known/oauth-protected-resource"` for no or an invalid
  token, `403` for another subject, `502` when the keys cannot be loaded; else `AuthInfo` for the MCP SDK.
  `resourceUrls(request)` builds the MCP and metadata URLs from the origin of `request.url`, never from `Host` or
  `X-Forwarded-*`. `@modelcontextprotocol/server` is a peer and dev dependency (the `AuthInfo` type only). Unlike
  jobrecon's copy it does not check `DATABASE_URL`: the product checks its own store settings.
- Stateless otherwise: client IDs (DCR), sign-in state, codes and refresh tokens are JWTs signed with the ES256 key,
  each with its own `typ` and `aud`.

Redirects: `https://claude.ai/api/mcp/auth_callback` and a loopback redirect on any port for Claude Code.
