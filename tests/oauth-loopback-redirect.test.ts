// @vitest-environment node
// REQ-OAUTH-2 (jobrecon REQ-MCPAUTH-2, BUI-1942): Claude Code lists portless
// loopback redirects in its client metadata document and sends a random port
// at sign-in (RFC 8252 section 7.3). Authorize must accept that port, and
// nothing else that differs from a registered redirect.
import { beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { redirectMatches } from '../src/index.js'
import {
  CIMD_URL,
  CLAUDE_REDIRECT,
  ISSUER,
  MCP_URL,
  OWNER,
  clientAuth,
  createWorld,
  makeEnv,
  pkce,
} from './support.js'
import type { World } from './support.js'

let baseEnv: Record<string, string>
let world: World

beforeAll(async () => {
  baseEnv = await makeEnv()
})

beforeEach(() => {
  world = createWorld(baseEnv)
  // The metadata document Claude Code publishes: no ports.
  world.clientDocument = {
    client_id: CIMD_URL,
    client_name: 'Claude Code',
    redirect_uris: ['http://localhost/callback', 'http://127.0.0.1/callback'],
    ...clientAuth(),
  }
})

function setRedirects(redirectUris: string[]): void {
  world.clientDocument = {
    client_id: CIMD_URL,
    client_name: 'Claude Code',
    redirect_uris: redirectUris,
    ...clientAuth(),
  }
}

function authorizeUrl(redirectUri: string, challenge: string, state = 's') {
  return `${ISSUER}/oauth/authorize?${new URLSearchParams({
    response_type: 'code',
    client_id: CIMD_URL,
    redirect_uri: redirectUri,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
    resource: MCP_URL,
  })}`
}

function authorize(redirectUri: string): Promise<Response> {
  return world.server.authorize(new Request(authorizeUrl(redirectUri, pkce().challenge)))
}

async function signInAt(redirectUri: string, challenge: string): Promise<string> {
  const start = await world.server.authorize(new Request(authorizeUrl(redirectUri, challenge)))
  const github = new URL(start.headers.get('location') ?? '')
  const cookie = (start.headers.get('set-cookie') ?? '').split(';')[0] ?? ''
  const back = await world.server.githubCallback(
    new Request(
      `${ISSUER}/oauth/github/callback?${new URLSearchParams({
        code: `gh-code:${OWNER}`,
        state: github.searchParams.get('state') ?? '',
      })}`,
      { headers: { cookie } },
    ),
  )
  const location = new URL(back.headers.get('location') ?? '')
  expect(`${location.origin}${location.pathname}`).toBe(redirectUri)
  return location.searchParams.get('code') ?? ''
}

function exchangeAt(code: string, verifier: string, redirectUri: string): Promise<Response> {
  return world.server.token(
    new Request(`${ISSUER}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: CIMD_URL,
        code,
        code_verifier: verifier,
        redirect_uri: redirectUri,
      }).toString(),
    }),
  )
}

describe('REQ-OAUTH-2: loopback redirects match on host and path', () => {
  it.each([
    'http://localhost:51124/callback',
    'http://127.0.0.1:51124/callback',
    'http://localhost/callback',
  ])('REQ-OAUTH-2: authorize accepts %s', async redirectUri => {
    const response = await authorize(redirectUri)
    expect(response.status).toBe(302)
    expect(new URL(response.headers.get('location') ?? '').origin).toBe('https://github.com')
  })

  it.each([
    ['another path', 'http://localhost:51124/other'],
    ['another host', 'http://evil.com:51124/callback'],
    ['https', 'https://localhost:51124/callback'],
    ['a query', 'http://localhost:51124/callback?x=1'],
    ['a fragment', 'http://localhost:51124/callback#x'],
    ['user info', 'http://user@localhost:51124/callback'],
    ['a trailing path', 'http://localhost:51124/callback/'],
    ['a host that only ends in localhost', 'http://evil.localhost:5/callback'],
    ['a not-URL', 'localhost:51124/callback'],
    ['an empty value', ''],
  ])('REQ-OAUTH-2: authorize refuses %s with 400', async (_label, uri) => {
    const response = await authorize(uri)
    expect(response.status).toBe(400)
    expect(response.headers.get('location')).toBeNull()
  })

  it('REQ-OAUTH-2: a localhost-only client refuses a 127.0.0.1 redirect', async () => {
    setRedirects(['http://localhost/callback'])
    const response = await authorize('http://127.0.0.1:5/callback')
    expect(response.status).toBe(400)
    expect((await authorize('http://localhost:5/callback')).status).toBe(302)
  })

  it('REQ-OAUTH-2: the hosted redirect is matched exactly', async () => {
    setRedirects([CLAUDE_REDIRECT])
    expect((await authorize(CLAUDE_REDIRECT)).status).toBe(302)
    expect((await authorize(`${CLAUDE_REDIRECT}?x=1`)).status).toBe(400)
    expect((await authorize('https://claude.ai:444/api/mcp/auth_callback')).status).toBe(400)
    // A hosted-only client has no loopback redirect to match.
    expect((await authorize('http://localhost:51124/callback')).status).toBe(400)
  })

  it('REQ-OAUTH-2: redirectMatches ignores the port of both sides for loopback only', () => {
    expect(redirectMatches('http://localhost:1/callback', ['http://localhost:2/callback'])).toBe(
      true,
    )
    expect(redirectMatches('http://localhost/callback', [CLAUDE_REDIRECT])).toBe(false)
    expect(redirectMatches(CLAUDE_REDIRECT, [CLAUDE_REDIRECT])).toBe(true)
    expect(redirectMatches(CLAUDE_REDIRECT, [])).toBe(false)
    expect(redirectMatches('http://localhost:1/callback', ['not a url'])).toBe(false)
    expect(redirectMatches('http://localhost:1/callback', ['http://127.0.0.1:1/callback'])).toBe(
      false,
    )
  })

  it('REQ-OAUTH-2: the token exchange still needs the exact redirect used at authorize', async () => {
    const { verifier, challenge } = pkce()
    const redirectUri = 'http://localhost:51124/callback'
    const code = await signInAt(redirectUri, challenge)
    expect(code).not.toBe('')
    // Same host and path, another port: not the redirect used at authorize.
    const wrong = await exchangeAt(code, verifier, 'http://localhost:51125/callback')
    expect(wrong.status).toBe(400)
    expect(((await wrong.json()) as { error: string }).error).toBe('invalid_grant')
  })

  it('REQ-OAUTH-2: the token exchange accepts the exact redirect used at authorize', async () => {
    const { verifier, challenge } = pkce()
    const redirectUri = 'http://127.0.0.1:51124/callback'
    const code = await signInAt(redirectUri, challenge)
    const response = await exchangeAt(code, verifier, redirectUri)
    expect(response.status).toBe(200)
  })
})
