// @vitest-environment node
// Review follow-ups: the SSRF extra blocklist comes from the injected env under
// the prefix (REQ-OAUTH-1), and a grant store missing `has` is refused when the
// server is created, not on the first refresh (REQ-OAUTH-2).
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { createMemoryGrantStore, createOAuthServer } from '../src/index.js'
import {
  CIMD_HOST,
  CIMD_URL,
  PREFIX,
  authorizeParams,
  authorizeRequest,
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
})

afterEach(() => {
  vi.unstubAllEnvs()
})

function authorizeCimd(server = world.server): Promise<Response> {
  return server.authorize(authorizeRequest(authorizeParams(CIMD_URL, pkce().challenge)))
}

describe('REQ-OAUTH-1: the extra SSRF blocklist is a prefixed setting of the injected env', () => {
  it('REQ-OAUTH-1: <PREFIX>_SSRF_BLOCKED_DOMAINS blocks a client metadata host before any lookup', async () => {
    const server = world.newServer({
      [`${PREFIX}_SSRF_BLOCKED_DOMAINS`]: ` x.test , ${CIMD_HOST} `,
    })
    const response = await authorizeCimd(server)
    expect(response.status).toBe(400)
    expect(await response.text()).toContain('Domain is blocked')
    expect(world.resolverCalls).toEqual([])
    expect(world.fetchedUrls).toEqual([])
  })

  it('REQ-OAUTH-1: the setting blocks subdomains of a listed domain', async () => {
    const server = world.newServer({ [`${PREFIX}_SSRF_BLOCKED_DOMAINS`]: 'example.test' })
    expect((await authorizeCimd(server)).status).toBe(400)
    expect(world.fetchedUrls).toEqual([])
  })

  it('REQ-OAUTH-1: process.env SSRF_BLOCKED_DOMAINS and another prefix are ignored', async () => {
    vi.stubEnv('SSRF_BLOCKED_DOMAINS', CIMD_HOST)
    const other = world.newServer({ OTHER_SSRF_BLOCKED_DOMAINS: CIMD_HOST })
    expect((await authorizeCimd(other)).status).toBe(302)
    expect(world.fetchedUrls).toEqual([CIMD_URL])
  })

  it('REQ-OAUTH-1: a blank setting blocks nothing extra', async () => {
    const server = world.newServer({ [`${PREFIX}_SSRF_BLOCKED_DOMAINS`]: ' , ' })
    expect((await authorizeCimd(server)).status).toBe(302)
  })

  it('REQ-OAUTH-1: the server reads the setting on each request', async () => {
    const env: Record<string, string> = { ...baseEnv }
    const server = createOAuthServer({
      prefix: PREFIX,
      grantStore: world.store,
      env,
      fetch: world.fakeFetch,
      resolver: world.resolver,
      now: () => world.clock,
    })
    expect((await authorizeCimd(server)).status).toBe(302)
    env[`${PREFIX}_SSRF_BLOCKED_DOMAINS`] = CIMD_HOST
    expect((await authorizeCimd(server)).status).toBe(400)
  })
})

describe('REQ-OAUTH-2: the grant store is checked whole at creation', () => {
  const make = (grantStore: unknown) => () =>
    createOAuthServer({
      prefix: 'A',
      env: {},
      grantStore: grantStore as ReturnType<typeof createMemoryGrantStore>,
    })

  it('REQ-OAUTH-2: refuses a store with no has', () => {
    expect(make({ claim: async () => true })).toThrow(/grantStore/)
  })

  it('REQ-OAUTH-2: refuses a store with no claim, a non-function member, and a non-object', () => {
    expect(make({ has: async () => false })).toThrow(/grantStore/)
    expect(make({ claim: async () => true, has: 'yes' })).toThrow(/grantStore/)
    expect(make(undefined)).toThrow(/grantStore/)
    expect(make(null)).toThrow(/grantStore/)
  })

  it('REQ-OAUTH-2: accepts a store with both methods', () => {
    expect(make(createMemoryGrantStore())).not.toThrow()
  })
})
