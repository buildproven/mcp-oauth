// REQ-OAUTH-4: the package surface.
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import * as api from '../src/index.js'
import type { GrantStore, OAuthServer } from '../src/index.js'

function readPackage(): {
  dependencies?: Record<string, string>
  exports: { '.': { types: string; import: string } }
} {
  return JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
}

describe('REQ-OAUTH-4: the package exports', () => {
  it('REQ-OAUTH-4: exports the server factory, the memory store, redirectMatches and the route paths', () => {
    expect(typeof api.createOAuthServer).toBe('function')
    expect(typeof api.createMemoryGrantStore).toBe('function')
    expect(typeof api.redirectMatches).toBe('function')
    expect(api.AUTHORIZE_PATH).toBe('/oauth/authorize')
    expect(api.TOKEN_PATH).toBe('/oauth/token')
    expect(api.REGISTER_PATH).toBe('/oauth/register')
    expect(api.JWKS_PATH).toBe('/oauth/jwks')
    expect(api.GITHUB_CALLBACK_PATH).toBe('/oauth/github/callback')
    expect(api.METADATA_PATH).toBe('/.well-known/oauth-authorization-server')
    expect(api.MCP_PATH).toBe('/api/mcp')
  })

  it('REQ-OAUTH-4: the GrantStore and OAuthServer types describe the handlers', () => {
    const store: GrantStore = api.createMemoryGrantStore()
    const server: OAuthServer = api.createOAuthServer({
      prefix: 'X',
      grantStore: store,
      env: {},
    })
    for (const name of [
      'metadata',
      'jwks',
      'register',
      'authorize',
      'githubCallback',
      'token',
      'preflight',
    ] as const) {
      expect(typeof server[name]).toBe('function')
    }
  })

  it('REQ-OAUTH-4: leaves the GitHub-repo grant store and GitHub App token code in the products', () => {
    expect(api).not.toHaveProperty('createGitHubGrantStore')
    expect(api).not.toHaveProperty('createAppTokenSource')
    expect(api).not.toHaveProperty('createHostedOAuthServer')
    expect(api).not.toHaveProperty('oauthServer')
  })

  it('REQ-OAUTH-4: the built entry point is dist/index.js, with types', () => {
    expect(readPackage().exports['.']).toEqual({
      types: './dist/index.d.ts',
      import: './dist/index.js',
    })
  })

  it('REQ-OAUTH-4: jose is a runtime dependency, since dist imports it', () => {
    expect(readPackage().dependencies).toHaveProperty('jose')
  })
})
