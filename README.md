# @buildproven/mcp-oauth

Owner-only OAuth 2.1 authorization server and token checks for a hosted MCP endpoint, shared by BuildProven's
agent-first products (machine-setup `docs/AGENT-FIRST.md`, rule 3). Claude signs the owner in through GitHub; only the
configured GitHub login gets a token.

The authorization server (`createOAuthServer`) is here, moved from `jobrecon/mcp/oauth-server.ts`, and so is the
bearer-token check for the MCP route (`authorizeMcpRequest`, from `jobrecon/mcp/http-auth.ts`). The move of
`retire-runway` follows (see `docs/DESIGN.md`).

## Use

Products install the release tarball of a version tag, not npm and not the git tag itself:
`"@buildproven/mcp-oauth": "https://github.com/buildproven/mcp-oauth/releases/download/v0.1.0/buildproven-mcp-oauth-0.1.0.tgz"`.
The tarball already holds `dist/`, so no install script runs (pnpm 11 refuses a git dependency's `prepare`). Pushing a
`v*` tag that matches `package.json` publishes it (`.github/workflows/release.yml`); a published tarball never changes.

```ts
import { createOAuthServer } from '@buildproven/mcp-oauth'

const oauth = createOAuthServer({ prefix: 'WANDERPAGE', grantStore })
// oauth.authorize(request), oauth.token(request), oauth.register(request), oauth.jwks(request),
// oauth.githubCallback(request), oauth.metadata(request), oauth.preflight()
```

Each handler takes a Web `Request` and answers a `Response`; mount them on `/oauth/authorize`, `/oauth/token`,
`/oauth/register`, `/oauth/jwks`, `/oauth/github/callback` and `/.well-known/oauth-authorization-server` (the path
constants are exported). With `prefix: 'WANDERPAGE'` the server reads `WANDERPAGE_OAUTH_ISSUER`,
`WANDERPAGE_OAUTH_SIGNING_KEY` (an ES256 private JWK), `WANDERPAGE_GITHUB_OAUTH_CLIENT_ID`,
`WANDERPAGE_GITHUB_OAUTH_CLIENT_SECRET` and `OWNER_GITHUB_LOGIN`. A missing or invalid setting answers `500` naming the
variable, never its value.

By default only the GitHub login in `OWNER_GITHUB_LOGIN` gets a code. Set `WANDERPAGE_SIGNUP=open` to let any GitHub
login sign in: each gets tokens whose `sub` is its login in lower case, and `OWNER_GITHUB_LOGIN` is not needed. Unset or
`owner` keeps the owner-only rule; any other value answers `500` naming the variable. `signupMode('WANDERPAGE')`
(optionally with an `env` object) returns `'owner'` or `'open'`, so a server can show the mode.

`grantStore` records spent codes and refresh tokens (`claim(id, expiresAt)` is true on the first claim only). Use
`createMemoryGrantStore()` for tests; a hosted product supplies a shared store and rejects with `GrantStoreError` when it
cannot read or write.

## Protect the MCP route

```ts
import { authorizeMcpRequest, resourceUrls } from '@buildproven/mcp-oauth'

const auth = await authorizeMcpRequest(request, { prefix: 'WANDERPAGE' })
if (!auth.ok) return auth.response
// auth.value is the AuthInfo the MCP SDK expects (token, clientId, scopes, expiresAt, resource, extra.subject)
```

The check reads `WANDERPAGE_OAUTH_ISSUER`, `WANDERPAGE_OAUTH_JWKS_URL` and `WANDERPAGE_OWNER_SUBJECT` on each request.
With `WANDERPAGE_SIGNUP=open` it accepts a valid token for any subject (returned as `extra.subject`) and
`WANDERPAGE_OWNER_SUBJECT` is not needed; signature, issuer, audience and expiry are still checked.
It answers `401` with `WWW-Authenticate: Bearer resource_metadata="<origin>/.well-known/oauth-protected-resource"` for no
token or an invalid one (wrong signature, issuer, audience or algorithm, or expired), `403` for another subject, `502`
when the issuer's keys cannot be loaded, and `503` naming each missing or non-https setting (never its value). Serve
`/.well-known/oauth-protected-resource` with `resource: resourceUrls(request).mcpUrl`; `resourceUrls` takes the host from
`request.url`, never from a `Host` or `X-Forwarded-*` header.

`@modelcontextprotocol/server` (for the `AuthInfo` type) is a peer dependency: the product already installs it.

## Develop

`npm ci`, then `npm test`, `npm run lint`, `npm run type-check`, `npm run format:check`.

MIT License.
