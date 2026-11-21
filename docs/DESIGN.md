# Design

## Why

jobrecon and retire-runway each carry a ~1,300-line copy of the same OAuth server (`mcp/oauth-server.ts`,
`src/mcp/oauth-server.ts`) and its resource-server checks (`http-auth.ts`); on 2026-11-21 the copies differed in 246
lines (jobrecon added loopback redirects on any port, `redirectMatches`). wander-page and every later hosted product
need the same server. One package keeps one tested copy.

## Shape

- `createOAuthServer({ prefix, grantStore, env?, now?, fetch? })` returns the handlers for `/oauth/authorize`,
  `/oauth/token`, `/oauth/register`, `/oauth/jwks`, `/oauth/github/callback`, and the
  `/.well-known/oauth-authorization-server` metadata. Env names derive from `prefix` (for example
  `WANDERPAGE_OAUTH_SIGNING_KEY`, `WANDERPAGE_GITHUB_OAUTH_CLIENT_ID`); the owner login is `OWNER_GITHUB_LOGIN`.
- `authorizeMcpRequest(request, config)` and `resourceUrls(request)` check a bearer token for the MCP route and build
  the `401` `WWW-Authenticate: Bearer resource_metadata=…` answer.
- `GrantStore { claim(id, expiresAt), has(id) }` records spent codes and refresh tokens. The package ships
  `createMemoryGrantStore` for tests; each product supplies its own adapter (private git repo, Postgres).
- Stateless otherwise: client IDs (DCR), sign-in state, codes and refresh tokens are JWTs signed with the ES256 key,
  each with its own `typ` and `aud`.

Redirects: `https://claude.ai/api/mcp/auth_callback` and a loopback redirect on any port for Claude Code.
