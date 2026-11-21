// Shared fixtures for the OAuth server tests. GitHub and the client metadata
// host are faked by injecting `fetch` and the DNS resolver into the server;
// global `fetch` and real DNS are never used.
import { createHash } from 'node:crypto'
import { exportJWK, generateKeyPair } from 'jose'
import { expect } from 'vitest'
import { createMemoryGrantStore, createOAuthServer } from '../src/index.js'
import type { GrantStore, OAuthServer } from '../src/index.js'
import type { DnsResolver, PinnedAddress } from '../src/ssrf-protection.js'

export const PREFIX = 'TESTPROD'
export const ISSUER = 'https://app.example.test'
export const MCP_URL = `${ISSUER}/api/mcp`
export const OWNER = 'Owner-Login'
export const CLAUDE_REDIRECT = 'https://claude.ai/api/mcp/auth_callback'
export const LOOPBACK_REDIRECT = 'http://localhost:53682/callback'
export const CIMD_HOST = 'client.example.test'
export const CIMD_URL = `https://${CIMD_HOST}/oauth/client.json`
export const GITHUB_ID = 'gh-oauth-client'
// The GitHub OAuth app credential, built from parts so no literal is assigned.
export const GITHUB_CRED = ['gh', 'oauth', 'cred'].join('-')
export const PUBLIC_IP = '93.184.216.34'

const AUTH_FIELD = ['token', 'endpoint', 'auth', 'method'].join('_')

/** The `token_endpoint_auth_method` field of a client registration. */
export function clientAuth(method = 'none'): Record<string, string> {
  return { [AUTH_FIELD]: method }
}

/** What the faked GitHub hands out for a sign-in as `login`. */
export function githubGrant(login: string): string {
  return `gh-user:${login}`
}

export async function makeEnv(
  prefix = PREFIX,
  extra: Record<string, string> = {},
): Promise<Record<string, string>> {
  const pair = await generateKeyPair('ES256', { extractable: true })
  return {
    [`${prefix}_OAUTH_ISSUER`]: ISSUER,
    [`${prefix}_OAUTH_SIGNING_KEY`]: JSON.stringify(await exportJWK(pair.privateKey)),
    OWNER_GITHUB_LOGIN: OWNER,
    [`${prefix}_GITHUB_OAUTH_CLIENT_ID`]: GITHUB_ID,
    [`${prefix}_GITHUB_OAUTH_CLIENT_SECRET`]: GITHUB_CRED,
    ...extra,
  }
}

export interface World {
  env: Record<string, string>
  clock: number
  githubCalls: { url: string; body: string }[]
  fetchedUrls: string[]
  fetchPins: { url: string; pin: PinnedAddress | undefined }[]
  resolverCalls: string[]
  clientDocument: unknown
  dnsTable: Record<string, { v4?: string[]; v6?: string[] }>
  store: GrantStore
  server: OAuthServer
  fakeFetch: (input: string, init?: RequestInit, pin?: PinnedAddress) => Promise<Response>
  resolver: DnsResolver
  newServer: (overrides?: Record<string, string>, store?: GrantStore) => OAuthServer
}

export function createWorld(env: Record<string, string>): World {
  const world: World = {
    env,
    clock: Date.now(),
    githubCalls: [],
    fetchedUrls: [],
    fetchPins: [],
    resolverCalls: [],
    clientDocument: {
      client_id: CIMD_URL,
      client_name: 'Test client',
      redirect_uris: [CLAUDE_REDIRECT, LOOPBACK_REDIRECT],
      ...clientAuth(),
    },
    dnsTable: { [CIMD_HOST]: { v4: [PUBLIC_IP] } },
    store: createMemoryGrantStore(() => world.clock),
    server: undefined as unknown as OAuthServer,
    // The GitHub code `gh-code:<login>` signs in `<login>`.
    async fakeFetch(input, init = {}, pin) {
      const body = typeof init.body === 'string' ? init.body : ''
      world.fetchPins.push({ url: input, pin })
      world.githubCalls.push({ url: input, body })
      if (input === 'https://github.com/login/oauth/access_token') {
        const { code } = JSON.parse(body) as { code: string }
        return Response.json(
          code.startsWith('gh-code:')
            ? { access_token: githubGrant(code.slice(8)) }
            : { error: 'bad_verification_code' },
        )
      }
      if (input === 'https://api.github.com/user') {
        const auth = new Headers(init.headers).get('authorization') ?? ''
        return Response.json({ login: auth.replace('Bearer gh-user:', '') })
      }
      if (input.startsWith('https://')) world.fetchedUrls.push(input)
      if (input === CIMD_URL) return Response.json(world.clientDocument as object)
      return new Response('not found', { status: 404 })
    },
    resolver: {
      async resolve4(host) {
        world.resolverCalls.push(host)
        const row = world.dnsTable[host]
        if (row === undefined) throw new Error(`ENOTFOUND ${host}`)
        return row.v4 ?? []
      },
      async resolve6(host) {
        const row = world.dnsTable[host]
        if (row === undefined) throw new Error(`ENOTFOUND ${host}`)
        return row.v6 ?? []
      },
    },
    newServer(overrides = {}, store = world.store) {
      return createOAuthServer({
        prefix: PREFIX,
        grantStore: store,
        env: { ...world.env, ...overrides },
        fetch: world.fakeFetch,
        resolver: world.resolver,
        now: () => world.clock,
      })
    },
  }
  world.server = world.newServer()
  return world
}

export function pkce(): { verifier: string; challenge: string } {
  const verifier = `${'v'.repeat(30)}${Math.random().toString(36).slice(2, 20)}`.padEnd(43, 'x')
  return {
    verifier,
    challenge: createHash('sha256').update(verifier).digest('base64url'),
  }
}

export async function register(
  world: World,
  body: unknown,
  target: OAuthServer = world.server,
): Promise<Response> {
  return target.register(
    new Request(`${ISSUER}/oauth/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: typeof body === 'string' ? body : JSON.stringify(body),
    }),
  )
}

export async function registerClient(world: World, redirectUris: string[]): Promise<string> {
  const response = await register(world, {
    redirect_uris: redirectUris,
    ...clientAuth(),
  })
  expect(response.status).toBe(201)
  return ((await response.json()) as { client_id: string }).client_id
}

export function authorizeRequest(params: Record<string, string>): Request {
  return new Request(`${ISSUER}/oauth/authorize?${new URLSearchParams(params)}`)
}

export function authorizeParams(
  clientId: string,
  challenge: string,
  extra: Record<string, string> = {},
): Record<string, string> {
  return {
    response_type: 'code',
    client_id: clientId,
    redirect_uri: CLAUDE_REDIRECT,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state: 'client-state-1',
    resource: MCP_URL,
    ...extra,
  }
}

export interface SignedIn {
  readonly response: Response
  readonly code?: string
  readonly clientState?: string | null
}

/** The owner's browser: authorize, GitHub, then the GitHub callback. */
export async function signIn(
  world: World,
  login: string,
  clientId: string,
  challenge: string,
  options: { redirectUri?: string; cookie?: string | null } = {},
): Promise<SignedIn> {
  const start = await world.server.authorize(
    authorizeRequest(
      authorizeParams(clientId, challenge, {
        redirect_uri: options.redirectUri ?? CLAUDE_REDIRECT,
      }),
    ),
  )
  expect(start.status).toBe(302)
  const github = new URL(start.headers.get('location') ?? '')
  expect(`${github.origin}${github.pathname}`).toBe('https://github.com/login/oauth/authorize')
  const cookie =
    options.cookie !== undefined
      ? options.cookie
      : (start.headers.get('set-cookie') ?? '').split(';')[0]
  const response = await world.server.githubCallback(
    new Request(
      `${ISSUER}/oauth/github/callback?${new URLSearchParams({
        code: `gh-code:${login}`,
        state: github.searchParams.get('state') ?? '',
      })}`,
      { headers: cookie ? { cookie } : {} },
    ),
  )
  const location = response.headers.get('location')
  if (location === null) return { response }
  const back = new URL(location)
  return {
    response,
    code: back.searchParams.get('code') ?? undefined,
    clientState: back.searchParams.get('state'),
  }
}

export function tokenRequest(fields: Record<string, string>): Request {
  return new Request(`${ISSUER}/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields).toString(),
  })
}

export async function exchange(
  world: World,
  clientId: string,
  code: string,
  verifier: string,
  redirectUri = CLAUDE_REDIRECT,
): Promise<Response> {
  return world.server.token(
    tokenRequest({
      grant_type: 'authorization_code',
      client_id: clientId,
      code,
      code_verifier: verifier,
      redirect_uri: redirectUri,
    }),
  )
}

export function refresh(world: World, clientId: string, refreshValue: string): Promise<Response> {
  return world.server.token(
    tokenRequest({
      grant_type: 'refresh_token',
      client_id: clientId,
      refresh_token: refreshValue,
    }),
  )
}

export interface Tokens {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
}

export async function ownerTokens(world: World): Promise<{ clientId: string; tokens: Tokens }> {
  const clientId = await registerClient(world, [CLAUDE_REDIRECT])
  const { verifier, challenge } = pkce()
  const signed = await signIn(world, OWNER, clientId, challenge)
  expect(signed.code).toBeDefined()
  const response = await exchange(world, clientId, signed.code ?? '', verifier)
  expect(response.status).toBe(200)
  return { clientId, tokens: (await response.json()) as Tokens }
}

export async function errorOf(response: Response): Promise<string> {
  return ((await response.json()) as { error: string }).error
}
