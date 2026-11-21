# @buildproven/mcp-oauth

Owner-only OAuth 2.1 authorization server and token checks for a hosted MCP endpoint, shared by BuildProven's
agent-first products (machine-setup `docs/AGENT-FIRST.md`, rule 3). Claude signs the owner in through GitHub; only the
configured GitHub login gets a token.

Status: scaffold. The code moves here from `jobrecon/mcp/oauth-server.ts` and `retire-runway/src/mcp/oauth-server.ts`
(see `docs/DESIGN.md`).

## Use

Products depend on a git tag, not npm: `"@buildproven/mcp-oauth": "github:buildproven/mcp-oauth#v0.1.0"`. Installing
runs `prepare`, which builds `dist/`.

## Develop

`npm ci`, then `npm test`, `npm run lint`, `npm run type-check`, `npm run format:check`.

MIT License.
