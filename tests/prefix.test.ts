// @vitest-environment node
// REQ-OAUTH-1: env names come from the `prefix` option.
import { beforeAll, describe, expect, it, vi } from 'vitest'
import { createMemoryGrantStore, createOAuthServer } from '../src/index.js'
import {
  ISSUER,
  OWNER,
  authorizeParams,
  authorizeRequest,
  createWorld,
  makeEnv,
  pkce,
  registerClient,
  signIn,
} from './support.js'

const CLAUDE = 'https://claude.ai/api/mcp/auth_callback'

let envA: Record<string, string>
let envB: Record<string, string>

beforeAll(async () => {
  envA = await makeEnv('A')
  envB = await makeEnv('B')
})

function serverWith(prefix: string, env: Record<string, string | undefined>) {
  return createOAuthServer({
    prefix,
    grantStore: createMemoryGrantStore(),
    env,
  })
}

const jwksRequest = () => new Request(`${ISSUER}/oauth/jwks`)

describe('REQ-OAUTH-1: env names come from the prefix', () => {
  it('REQ-OAUTH-1: a server with prefix A ignores B_* variables and names A_OAUTH_SIGNING_KEY when it is missing', async () => {
    const onlyB = Object.fromEntries(
      Object.entries(envB).filter(([name]) => !name.startsWith('A_')),
    )
    const response = await serverWith('A', onlyB).jwks(jwksRequest())
    expect(response.status).toBe(500)
    const body = (await response.json()) as {
      missing: string[]
      error_description: string
    }
    expect(body.missing).toContain('A_OAUTH_SIGNING_KEY')
    expect(body.missing.some(name => name.startsWith('B_'))).toBe(false)
    expect(body.error_description).toContain('A_OAUTH_SIGNING_KEY')
  })

  it('REQ-OAUTH-1: the issuer, GitHub client and signing key are read from A_*', async () => {
    const response = await serverWith('A', envA).jwks(jwksRequest())
    expect(response.status).toBe(200)
    const missing = await serverWith('A', {}).authorize(authorizeRequest({}))
    const body = (await missing.json()) as { missing: string[] }
    // The issuer is checked first, then the signing key.
    expect(body.missing).toEqual(['A_OAUTH_ISSUER'])
    const noKey = await serverWith('A', { A_OAUTH_ISSUER: ISSUER }).authorize(authorizeRequest({}))
    expect(((await noKey.json()) as { missing: string[] }).missing).toEqual(['A_OAUTH_SIGNING_KEY'])
    const settings = await serverWith('A', {
      A_OAUTH_ISSUER: ISSUER,
      A_OAUTH_SIGNING_KEY: envA.A_OAUTH_SIGNING_KEY,
    }).authorize(authorizeRequest({}))
    expect(((await settings.json()) as { missing: string[] }).missing).toEqual([
      'A_GITHUB_OAUTH_CLIENT_ID',
      'A_GITHUB_OAUTH_CLIENT_SECRET',
      'OWNER_GITHUB_LOGIN',
    ])
  })

  it('REQ-OAUTH-1: two prefixes in one process keep their own keys', async () => {
    const a = await serverWith('A', { ...envA, ...envB }).jwks(jwksRequest())
    const b = await serverWith('B', { ...envA, ...envB }).jwks(jwksRequest())
    const kidA = ((await a.json()) as { keys: { kid: string }[] }).keys[0]?.kid
    const kidB = ((await b.json()) as { keys: { kid: string }[] }).keys[0]?.kid
    expect(kidA).toBeDefined()
    expect(kidB).toBeDefined()
    expect(kidA).not.toBe(kidB)
  })

  it('REQ-OAUTH-1: no JOBRECON_* name is read', async () => {
    const legacy = await makeEnv('JOBRECON')
    const response = await serverWith('WANDERPAGE', legacy).jwks(jwksRequest())
    expect(response.status).toBe(500)
    const text = JSON.stringify(await response.json())
    expect(text).toContain('WANDERPAGE_OAUTH_SIGNING_KEY')
    expect(text).not.toContain('JOBRECON')
  })

  it('REQ-OAUTH-1: a wanderpage server signs in the owner with WANDERPAGE_* settings and OWNER_GITHUB_LOGIN', async () => {
    const env = await makeEnv('WANDERPAGE')
    const world = createWorld(env)
    world.server = createOAuthServer({
      prefix: 'WANDERPAGE',
      grantStore: world.store,
      env,
      fetch: world.fakeFetch,
      resolver: world.resolver,
      now: () => world.clock,
    })
    const clientId = await registerClient(world, [CLAUDE])
    const signed = await signIn(world, OWNER, clientId, pkce().challenge)
    expect(signed.code).toBeDefined()
    const start = await world.server.authorize(
      authorizeRequest(authorizeParams(clientId, pkce().challenge)),
    )
    expect(start.headers.get('set-cookie')).toContain('wanderpage_oauth_nonce=')
  })

  it.each(['', 'lower', 'HAS SPACE', '1ABC', 'A-B', 'É'])(
    'REQ-OAUTH-1: refuses the prefix %j when the server is created',
    prefix => {
      expect(() => serverWith(prefix, envA)).toThrow(/prefix/)
    },
  )

  it('REQ-OAUTH-1: reads process.env when no env is given', async () => {
    const env = await makeEnv('FROMPROCESS')
    for (const [name, value] of Object.entries(env)) vi.stubEnv(name, value)
    try {
      const server = createOAuthServer({
        prefix: 'FROMPROCESS',
        grantStore: createMemoryGrantStore(),
      })
      expect((await server.jwks(jwksRequest())).status).toBe(200)
      const other = createOAuthServer({
        prefix: 'NOTSET',
        grantStore: createMemoryGrantStore(),
      })
      expect((await other.jwks(jwksRequest())).status).toBe(500)
    } finally {
      vi.unstubAllEnvs()
    }
  })

  it('REQ-OAUTH-1: refuses a missing grant store when the server is created', () => {
    expect(() =>
      createOAuthServer({
        prefix: 'A',
        env: envA,
      } as unknown as Parameters<typeof createOAuthServer>[0]),
    ).toThrow(/grantStore/)
  })
})
