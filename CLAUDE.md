# mcp-oauth

Shared owner-only OAuth 2.1 server for hosted MCP endpoints (`docs/DESIGN.md`). A library, no UI, no deploy.

- Install: `npm ci`. Test: `npm test` (Vitest). Lint: `npm run lint`. Types: `npm run type-check`. Format: `npm run format:check`.
- Consumers pin a git tag; a breaking change needs a new minor tag and a CHANGELOG line.
- Never log tokens, codes, or keys. Every env name comes from the consumer's `prefix`.
