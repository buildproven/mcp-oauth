# @buildproven/mcp-oauth

Owner-only OAuth 2.1 authorization server and token checks for a hosted MCP endpoint, shared by BuildProven's
agent-first products (machine-setup `docs/AGENT-FIRST.md`, rule 3). Claude signs the owner in through GitHub; only the
configured GitHub login gets a token.

The authorization server (`createOAuthServer`) is here, moved from `jobrecon/mcp/oauth-server.ts`. The bearer-token
check for the MCP route and the move of `retire-runway` follow (see `docs/DESIGN.md`).

## Use

Products depend on a git tag, not npm: `"@buildproven/mcp-oauth": "github:buildproven/mcp-oauth#v0.1.0"`. Installing
runs `prepare`, which builds `dist/`.

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

`grantStore` records spent codes and refresh tokens (`claim(id, expiresAt)` is true on the first claim only). Use
`createMemoryGrantStore()` for tests; a hosted product supplies a shared store and rejects with `GrantStoreError` when it
cannot read or write.

## Develop

`npm ci`, then `npm test`, `npm run lint`, `npm run type-check`, `npm run format:check`.

MIT License.
