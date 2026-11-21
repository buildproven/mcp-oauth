// @vitest-environment node
// Authorization server behavior, ported from jobrecon's oauth-server tests
// (REQ-MCPAUTH-1 to 7 there; REQ-OAUTH-2 here) and run with prefix TESTPROD.
// REQ-OAUTH-3 covers the settings messages.
import { SignJWT, createLocalJWKSet, decodeJwt, generateKeyPair, jwtVerify } from 'jose'
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  GrantStoreError,
  createMemoryGrantStore,
  createOAuthServer,
  redirectMatches,
} from '../src/index.js'
import type { GrantStore } from '../src/index.js'
import { isAllowedRedirect } from '../src/oauth-server.js'
import {
  CIMD_HOST,
  CIMD_URL,
  CLAUDE_REDIRECT,
  GITHUB_CRED,
  GITHUB_ID,
  ISSUER,
  LOOPBACK_REDIRECT,
  MCP_URL,
  OWNER,
  PREFIX,
  PUBLIC_IP,
  authorizeParams,
  authorizeRequest,
  clientAuth,
  createWorld,
  errorOf,
  exchange,
  githubGrant,
  makeEnv,
  ownerTokens,
  pkce,
  refresh,
  register,
  registerClient,
  signIn,
  tokenRequest,
} from './support.js'
import type { Tokens, World } from './support.js'

let baseEnv: Record<string, string>
let world: World

beforeAll(async () => {
  baseEnv = await makeEnv()
})

beforeEach(() => {
  world = createWorld(baseEnv)
})

describe('REQ-OAUTH-2: authorization server metadata', () => {
  it('REQ-OAUTH-2: serves RFC 8414 metadata with the endpoints, S256, CIMD and none', async () => {
    const response = world.server.metadata(
      new Request(`${ISSUER}/.well-known/oauth-authorization-server`),
    )
    expect(response.status).toBe(200)
    const metadata = (await response.json()) as Record<string, unknown>
    expect(metadata).toMatchObject({
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/oauth/authorize`,
      token_endpoint: `${ISSUER}/oauth/token`,
      registration_endpoint: `${ISSUER}/oauth/register`,
      jwks_uri: `${ISSUER}/oauth/jwks`,
      code_challenge_methods_supported: ['S256'],
      client_id_metadata_document_supported: true,
      response_types_supported: ['code'],
    })
    expect(metadata.token_endpoint_auth_methods_supported).toContain('none')
    expect(metadata.grant_types_supported).toEqual(['authorization_code', 'refresh_token'])
  })

  it('REQ-OAUTH-2: an issuer set with trailing slashes is published without them', async () => {
    const server = world.newServer({ [`${PREFIX}_OAUTH_ISSUER`]: `${ISSUER}//` })
    const response = server.metadata(
      new Request(`${ISSUER}/.well-known/oauth-authorization-server`),
    )
    expect(((await response.json()) as { issuer: string }).issuer).toBe(ISSUER)
  })

  it('REQ-OAUTH-2: publishes only the public half of the signing key', async () => {
    const response = await world.server.jwks(new Request(`${ISSUER}/oauth/jwks`))
    const { keys } = (await response.json()) as {
      keys: Record<string, unknown>[]
    }
    expect(keys).toHaveLength(1)
    expect(keys[0]).toMatchObject({ kty: 'EC', alg: 'ES256', use: 'sig' })
    expect(keys[0]).not.toHaveProperty('d')
    expect(typeof keys[0]?.kid).toBe('string')
  })

  it('REQ-OAUTH-2: answers CORS preflight', () => {
    const response = world.server.preflight()
    expect(response.status).toBe(204)
    expect(response.headers.get('access-control-allow-origin')).toBe('*')
  })
})

describe('REQ-OAUTH-3: a missing or invalid setting is named, never its value', () => {
  const badKey = 'not json but looks like a private value'

  it('REQ-OAUTH-3: names the issuer variable when it is unset', async () => {
    const response = world
      .newServer({ [`${PREFIX}_OAUTH_ISSUER`]: '' })
      .metadata(new Request(`${ISSUER}/.well-known/oauth-authorization-server`))
    expect(response.status).toBe(500)
    expect(((await response.json()) as { missing: string[] }).missing).toEqual([
      `${PREFIX}_OAUTH_ISSUER`,
    ])
  })

  it('REQ-OAUTH-3: names the issuer variable, not its value, when it is not an https URL', async () => {
    const value = 'http://insecure.example.test/secret-path'
    const response = world
      .newServer({ [`${PREFIX}_OAUTH_ISSUER`]: value })
      .metadata(new Request(`${ISSUER}/.well-known/oauth-authorization-server`))
    expect(response.status).toBe(500)
    const text = await response.text()
    expect(text).toContain(`${PREFIX}_OAUTH_ISSUER`)
    expect(text).not.toContain('insecure.example.test')
    expect(text).not.toContain('secret-path')
  })

  it('REQ-OAUTH-3: names each missing setting on the endpoints that need it', async () => {
    const keys = await world
      .newServer({ [`${PREFIX}_OAUTH_SIGNING_KEY`]: '' })
      .jwks(new Request(`${ISSUER}/oauth/jwks`))
    expect(keys.status).toBe(500)
    expect(((await keys.json()) as { missing: string[] }).missing).toEqual([
      `${PREFIX}_OAUTH_SIGNING_KEY`,
    ])
    const start = await world.newServer({ OWNER_GITHUB_LOGIN: '' }).authorize(authorizeRequest({}))
    expect(start.status).toBe(500)
    expect(((await start.json()) as { missing: string[] }).missing).toEqual(['OWNER_GITHUB_LOGIN'])
    const both = await world
      .newServer({
        [`${PREFIX}_GITHUB_OAUTH_CLIENT_ID`]: '',
        [`${PREFIX}_GITHUB_OAUTH_CLIENT_SECRET`]: '  ',
      })
      .authorize(authorizeRequest({}))
    expect(((await both.json()) as { missing: string[] }).missing).toEqual([
      `${PREFIX}_GITHUB_OAUTH_CLIENT_ID`,
      `${PREFIX}_GITHUB_OAUTH_CLIENT_SECRET`,
    ])
    const owner = await world
      .newServer({ OWNER_GITHUB_LOGIN: '' })
      .token(tokenRequest({ grant_type: 'refresh_token', client_id: 'x' }))
    expect(((await owner.json()) as { missing: string[] }).missing).toEqual(['OWNER_GITHUB_LOGIN'])
  })

  it('REQ-OAUTH-3: names the signing key variable and never prints a bad key', async () => {
    for (const key of [
      badKey,
      JSON.stringify({ kty: 'oct', k: 'AAAA' }),
      JSON.stringify({ kty: 'EC', crv: 'P-256', d: 'AAAA', x: 'AAAA', y: 'AAAA' }),
    ]) {
      const response = await world
        .newServer({ [`${PREFIX}_OAUTH_SIGNING_KEY`]: key })
        .jwks(new Request(`${ISSUER}/oauth/jwks`))
      expect(response.status).toBe(500)
      const text = await response.text()
      expect(text).toContain(`${PREFIX}_OAUTH_SIGNING_KEY`)
      expect(text).not.toContain(key)
      expect(text).not.toContain('looks like a private value')
    }
  })

  it('REQ-OAUTH-3: a request that needs the signing key and the issuer reports a missing setting before any work', async () => {
    const response = await world.newServer({ [`${PREFIX}_OAUTH_SIGNING_KEY`]: '' }).register(
      new Request(`${ISSUER}/oauth/register`, {
        method: 'POST',
        body: JSON.stringify({ redirect_uris: [CLAUDE_REDIRECT] }),
      }),
    )
    expect(response.status).toBe(500)
  })
})

describe('REQ-OAUTH-2: only Claude redirects are accepted', () => {
  it('REQ-OAUTH-2: registers a client for the Claude and loopback redirects', async () => {
    const redirects = [
      CLAUDE_REDIRECT,
      'http://localhost:53682/callback',
      'http://localhost/callback',
      'http://127.0.0.1:8123/callback',
    ]
    const response = await register(world, {
      redirect_uris: redirects,
      client_name: 'Claude',
      ...clientAuth(),
    })
    expect(response.status).toBe(201)
    const client = (await response.json()) as Record<string, unknown>
    expect(client).toMatchObject({
      redirect_uris: redirects,
      client_name: 'Claude',
      ...clientAuth(),
    })
    expect(typeof client.client_id).toBe('string')
    expect(client).not.toHaveProperty('client_secret')
  })

  it.each([
    ['another https host', 'https://evil.example.test/api/mcp/auth_callback'],
    ['another Claude path', 'https://claude.ai/api/mcp/other'],
    ['a Claude path with a query', `${CLAUDE_REDIRECT}?x=1`],
    ['plain http on claude.ai', 'http://claude.ai/api/mcp/auth_callback'],
    ['a loopback path other than /callback', 'http://localhost:1234/other'],
    ['a loopback callback with a query', 'http://localhost:1234/callback?a=1'],
    ['a loopback callback with a fragment', 'http://localhost:1234/callback#a'],
    ['https on loopback', 'https://localhost:1234/callback'],
    ['a host that only starts with localhost', 'http://localhost.evil.test:1234/callback'],
    ['a userinfo trick', 'http://localhost:1234@evil.test/callback'],
    ['another loopback form', 'http://[::1]:1234/callback'],
    ['a non-URL', 'not a url'],
    ['a custom scheme', 'myapp://callback'],
  ])('REQ-OAUTH-2: rejects %s', async (_label, uri) => {
    expect(isAllowedRedirect(uri)).toBe(false)
    const response = await register(world, {
      redirect_uris: [CLAUDE_REDIRECT, uri],
    })
    expect(response.status).toBe(400)
    expect(await errorOf(response)).toBe('invalid_redirect_uri')
  })

  it('REQ-OAUTH-2: rejects empty, missing, oversized and non-string redirect lists', async () => {
    for (const redirect_uris of [
      [],
      undefined,
      CLAUDE_REDIRECT,
      [42],
      Array.from({ length: 6 }, () => CLAUDE_REDIRECT),
    ]) {
      const response = await register(world, { redirect_uris })
      expect(response.status).toBe(400)
      expect(await errorOf(response)).toBe('invalid_redirect_uri')
    }
  })

  it('REQ-OAUTH-2: rejects a body that is not a JSON object, a client that wants a secret, and a huge body', async () => {
    for (const body of ['{oops', '[]', 'null', '"x"']) {
      const response = await register(world, body)
      expect(response.status).toBe(400)
      expect(await errorOf(response)).toBe('invalid_client_metadata')
    }
    const wantsSecret = await register(world, {
      redirect_uris: [CLAUDE_REDIRECT],
      ...clientAuth('client_secret_basic'),
    })
    expect(wantsSecret.status).toBe(400)
    expect(await errorOf(wantsSecret)).toBe('invalid_client_metadata')
    const huge = await register(
      world,
      JSON.stringify({
        redirect_uris: [CLAUDE_REDIRECT],
        pad: 'x'.repeat(20_000),
      }),
    )
    expect(huge.status).toBe(400)
  })

  it('REQ-OAUTH-2: a client ID metadata document with both allowed redirects signs in', async () => {
    const { verifier, challenge } = pkce()
    const signed = await signIn(world, OWNER, CIMD_URL, challenge, {
      redirectUri: LOOPBACK_REDIRECT,
    })
    expect(signed.code).toBeDefined()
    expect(signed.response.headers.get('location')).toMatch(/^http:\/\/localhost:53682\/callback\?/)
    const response = await exchange(world, CIMD_URL, signed.code ?? '', verifier, LOOPBACK_REDIRECT)
    expect(response.status).toBe(200)
    expect(world.fetchedUrls).toContain(CIMD_URL)
  })

  it.each([
    [
      'a document whose client_id is another URL',
      {
        client_id: 'https://other.example.test/c.json',
        redirect_uris: [CLAUDE_REDIRECT],
      },
    ],
    [
      'a document with a foreign redirect',
      {
        client_id: CIMD_URL,
        redirect_uris: [CLAUDE_REDIRECT, 'https://evil.example.test/cb'],
      },
    ],
    [
      'a document that wants a client secret',
      {
        client_id: CIMD_URL,
        redirect_uris: [CLAUDE_REDIRECT],
        ...clientAuth('client_secret_post'),
      },
    ],
    ['a document with no redirects', { client_id: CIMD_URL }],
    ['a document that is not an object', ['x']],
  ])('REQ-OAUTH-2: refuses %s', async (_label, document) => {
    world.clientDocument = document
    const response = await world.server.authorize(
      authorizeRequest(authorizeParams(CIMD_URL, pkce().challenge)),
    )
    expect(response.status).toBe(400)
    expect(response.headers.get('location')).toBeNull()
  })

  it('REQ-OAUTH-2: refuses a document that cannot be fetched, is not JSON or is too large', async () => {
    const bodies: (() => Promise<Response>)[] = [
      async () => {
        throw new Error('offline')
      },
      async () => new Response('{"pad":"' + 'x'.repeat(20_000) + '"}'),
      async () => new Response('not json'),
      async () => new Response('gone', { status: 404 }),
    ]
    for (const reply of bodies) {
      const odd = createOAuthServer({
        prefix: PREFIX,
        grantStore: world.store,
        env: world.env,
        now: () => world.clock,
        resolver: world.resolver,
        fetch: reply,
      })
      const response = await odd.authorize(
        authorizeRequest(authorizeParams(CIMD_URL, pkce().challenge)),
      )
      expect(response.status).toBe(400)
      expect(response.headers.get('location')).toBeNull()
    }
  })

  it('REQ-OAUTH-2: answers 400 and no redirect for an unknown client or an unregistered redirect', async () => {
    const clientId = await registerClient(world, [CLAUDE_REDIRECT])
    const { challenge } = pkce()
    const cases = [
      authorizeParams('not-a-registered-client', challenge),
      authorizeParams(clientId, challenge, {
        redirect_uri: 'https://evil.example.test/cb',
      }),
      authorizeParams(clientId, challenge, { redirect_uri: LOOPBACK_REDIRECT }),
      { ...authorizeParams(clientId, challenge), redirect_uri: '' },
      { response_type: 'code' },
    ]
    for (const params of cases) {
      const response = await world.server.authorize(authorizeRequest(params))
      expect(response.status).toBe(400)
      expect(response.headers.get('location')).toBeNull()
      expect(response.headers.get('content-type')).toContain('text/html')
    }
  })

  it('REQ-OAUTH-2: refuses a client ID signed with another key', async () => {
    const other = await generateKeyPair('ES256')
    const forged = await new SignJWT({ redirect_uris: [CLAUDE_REDIRECT] })
      .setProtectedHeader({ alg: 'ES256', typ: 'testprod-client+jwt' })
      .setIssuer(ISSUER)
      .setAudience('urn:testprod:client')
      .sign(other.privateKey)
    const response = await world.server.authorize(
      authorizeRequest(authorizeParams(forged, pkce().challenge)),
    )
    expect(response.status).toBe(400)
  })

  it('REQ-OAUTH-2: sends protocol errors for a trusted redirect back to the client', async () => {
    const clientId = await registerClient(world, [CLAUDE_REDIRECT])
    const { challenge } = pkce()
    const cases: [Record<string, string>, string][] = [
      [
        authorizeParams(clientId, challenge, { response_type: 'token' }),
        'unsupported_response_type',
      ],
      [
        authorizeParams(clientId, challenge, {
          code_challenge_method: 'plain',
        }),
        'invalid_request',
      ],
      [authorizeParams(clientId, 'short'), 'invalid_request'],
      [authorizeParams(clientId, challenge, { state: 'x'.repeat(513) }), 'invalid_request'],
      [
        authorizeParams(clientId, challenge, {
          resource: 'https://other.example.test/api/mcp',
        }),
        'invalid_target',
      ],
    ]
    for (const [params, error] of cases) {
      const response = await world.server.authorize(authorizeRequest(params))
      expect(response.status).toBe(302)
      const back = new URL(response.headers.get('location') ?? '')
      expect(`${back.origin}${back.pathname}`).toBe(CLAUDE_REDIRECT)
      expect(back.searchParams.get('error')).toBe(error)
      expect(back.searchParams.has('code')).toBe(false)
    }
    const repeated = await world.server.authorize(
      new Request(
        `${ISSUER}/oauth/authorize?${new URLSearchParams(
          authorizeParams(clientId, challenge),
        )}&state=again`,
      ),
    )
    expect(repeated.status).toBe(400)
    expect(repeated.headers.get('location')).toBeNull()
  })
})

describe('REQ-OAUTH-2: the owner signs in and gets tokens', () => {
  it('REQ-OAUTH-2: issues a code after GitHub sign-in and tokens for a valid verifier', async () => {
    const clientId = await registerClient(world, [CLAUDE_REDIRECT])
    const { verifier, challenge } = pkce()
    const signed = await signIn(world, OWNER, clientId, challenge)
    expect(signed.response.status).toBe(302)
    expect(signed.clientState).toBe('client-state-1')
    expect(signed.code).toBeDefined()
    const exchangeCall = world.githubCalls.find(call => call.url.endsWith('/access_token'))
    expect(JSON.parse(exchangeCall?.body ?? '{}')).toMatchObject({
      client_id: GITHUB_ID,
      client_secret: GITHUB_CRED,
      redirect_uri: `${ISSUER}/oauth/github/callback`,
    })

    const response = await exchange(world, clientId, signed.code ?? '', verifier)
    expect(response.status).toBe(200)
    expect(response.headers.get('cache-control')).toBe('no-store')
    const tokens = (await response.json()) as Tokens
    expect(tokens.token_type).toBe('Bearer')
    expect(tokens.expires_in).toBe(3600)
    expect(typeof tokens.refresh_token).toBe('string')
    const claims = decodeJwt(tokens.access_token)
    expect(claims).toMatchObject({
      iss: ISSUER,
      sub: OWNER,
      aud: MCP_URL,
      client_id: clientId,
      scope: 'mcp',
    })
    expect((claims.exp ?? 0) - (claims.iat ?? 0)).toBe(3600)
  })

  it('REQ-OAUTH-2: the access token verifies against the published JWKS, and no other signed value does', async () => {
    const { clientId, tokens } = await ownerTokens(world)
    const published = await world.server.jwks(new Request(`${ISSUER}/oauth/jwks`))
    const keys = createLocalJWKSet(
      (await published.json()) as Parameters<typeof createLocalJWKSet>[0],
    )
    const check = (bearer: string) =>
      jwtVerify(bearer, keys, {
        issuer: ISSUER,
        audience: MCP_URL,
        typ: 'at+jwt',
        algorithms: ['ES256'],
      })
    expect((await check(tokens.access_token)).payload.sub).toBe(OWNER)
    const { challenge } = pkce()
    const code = (await signIn(world, OWNER, clientId, challenge)).code ?? ''
    for (const other of [tokens.refresh_token, code, clientId]) {
      await expect(check(other)).rejects.toThrow()
    }
  })

  it('REQ-OAUTH-2: the token endpoint takes only application/x-www-form-urlencoded', async () => {
    const clientId = await registerClient(world, [CLAUDE_REDIRECT])
    const { verifier, challenge } = pkce()
    const signed = await signIn(world, OWNER, clientId, challenge)
    const fields = {
      grant_type: 'authorization_code',
      client_id: clientId,
      code: signed.code ?? '',
      code_verifier: verifier,
      redirect_uri: CLAUDE_REDIRECT,
    }
    const asJson = await world.server.token(
      new Request(`${ISSUER}/oauth/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(fields),
      }),
    )
    expect(asJson.status).toBe(400)
    expect(await errorOf(asJson)).toBe('invalid_request')
    // The refused request did not spend the code.
    const withCharset = await world.server.token(
      new Request(`${ISSUER}/oauth/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        },
        body: new URLSearchParams(fields).toString(),
      }),
    )
    expect(withCharset.status).toBe(200)
  })

  it('REQ-OAUTH-2: answers invalid_request for missing or repeated fields and unsupported_grant_type for others', async () => {
    const clientId = await registerClient(world, [CLAUDE_REDIRECT])
    const cases: [string, string][] = [
      ['', 'invalid_request'],
      ['grant_type=authorization_code', 'invalid_request'],
      [`grant_type=authorization_code&client_id=${clientId}`, 'invalid_request'],
      [`grant_type=refresh_token&client_id=${clientId}`, 'invalid_request'],
      [
        `grant_type=refresh_token&client_id=${clientId}&client_id=x&refresh_token=y`,
        'invalid_request',
      ],
      [`grant_type=password&client_id=${clientId}`, 'unsupported_grant_type'],
    ]
    for (const [body, error] of cases) {
      const response = await world.server.token(
        new Request(`${ISSUER}/oauth/token`, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body,
        }),
      )
      expect(response.status).toBe(400)
      expect(await errorOf(response)).toBe(error)
    }
  })

  it('REQ-OAUTH-2: a refresh token yields a new access token and a new refresh token', async () => {
    const { clientId, tokens } = await ownerTokens(world)
    const response = await refresh(world, clientId, tokens.refresh_token)
    expect(response.status).toBe(200)
    const next = (await response.json()) as Tokens
    expect(next.refresh_token).not.toBe(tokens.refresh_token)
    expect(next.access_token).not.toBe(tokens.access_token)
    expect(decodeJwt(next.access_token)).toMatchObject({
      sub: OWNER,
      aud: MCP_URL,
      client_id: clientId,
    })
    expect((await refresh(world, clientId, next.refresh_token)).status).toBe(200)
  })

  it('REQ-OAUTH-2: the issued subject is the configured owner login whatever the case GitHub reports', async () => {
    const clientId = await registerClient(world, [CLAUDE_REDIRECT])
    const { verifier, challenge } = pkce()
    const signed = await signIn(world, OWNER.toUpperCase(), clientId, challenge)
    const response = await exchange(world, clientId, signed.code ?? '', verifier)
    const tokens = (await response.json()) as Tokens
    expect(decodeJwt(tokens.access_token).sub).toBe(OWNER)
  })
})

describe('REQ-OAUTH-2: only the owner signs in', () => {
  it('REQ-OAUTH-2: refuses another GitHub login with an error page and no code', async () => {
    const clientId = await registerClient(world, [CLAUDE_REDIRECT])
    const signed = await signIn(world, 'mallory', clientId, pkce().challenge)
    expect(signed.response.status).toBe(403)
    expect(signed.response.headers.get('location')).toBeNull()
    expect(signed.response.headers.get('content-type')).toContain('text/html')
    const page = await signed.response.text()
    expect(page).toContain('serves only its owner')
    expect(page).not.toContain(GITHUB_CRED)
    expect(page).not.toContain('gh-user')
    expect(signed.code).toBeUndefined()
  })

  it('REQ-OAUTH-2: refuses a login that only contains the owner login', async () => {
    const clientId = await registerClient(world, [CLAUDE_REDIRECT])
    for (const login of [`${OWNER}-2`, `x${OWNER}`, OWNER.slice(0, 4)]) {
      const signed = await signIn(world, login, clientId, pkce().challenge)
      expect(signed.response.status).toBe(403)
      expect(signed.code).toBeUndefined()
    }
  })

  it('REQ-OAUTH-2: refuses a sign-in that did not start in this browser', async () => {
    const clientId = await registerClient(world, [CLAUDE_REDIRECT])
    for (const cookie of [null, 'testprod_oauth_nonce=other']) {
      const signed = await signIn(world, OWNER, clientId, pkce().challenge, {
        cookie,
      })
      expect(signed.response.status).toBe(400)
      expect(signed.code).toBeUndefined()
    }
  })

  it('REQ-OAUTH-2: sets the nonce cookie HttpOnly, Lax and scoped to the callback', async () => {
    const clientId = await registerClient(world, [CLAUDE_REDIRECT])
    const start = await world.server.authorize(
      authorizeRequest(authorizeParams(clientId, pkce().challenge)),
    )
    const cookie = start.headers.get('set-cookie') ?? ''
    expect(cookie).toContain('testprod_oauth_nonce=')
    expect(cookie).toContain('HttpOnly')
    expect(cookie).toContain('SameSite=Lax')
    expect(cookie).toContain('Secure')
    expect(cookie).toContain('Path=/oauth/github/callback')
  })

  it('REQ-OAUTH-2: refuses a garbage state, a GitHub error, a callback with no code, and an expired state', async () => {
    const clientId = await registerClient(world, [CLAUDE_REDIRECT])
    const start = await world.server.authorize(
      authorizeRequest(authorizeParams(clientId, pkce().challenge)),
    )
    const cookie = (start.headers.get('set-cookie') ?? '').split(';')[0] ?? ''
    const state = new URL(start.headers.get('location') ?? '').searchParams.get('state') ?? ''
    for (const query of [
      'code=gh-code:Owner-Login&state=garbage',
      `code=gh-code:${OWNER}`,
      `state=${state}&error=access_denied`,
      `state=${state}`,
      `state=${state}&code=`,
    ]) {
      const response = await world.server.githubCallback(
        new Request(`${ISSUER}/oauth/github/callback?${query}`, {
          headers: { cookie },
        }),
      )
      expect(response.status).toBe(400)
      expect(response.headers.get('location')).toBeNull()
    }
    world.clock += 11 * 60 * 1000
    const expired = await world.server.githubCallback(
      new Request(`${ISSUER}/oauth/github/callback?state=${state}&code=gh-code:${OWNER}`, {
        headers: { cookie },
      }),
    )
    expect(expired.status).toBe(400)
  })

  it('REQ-OAUTH-2: answers 502 and no code when GitHub fails or does not confirm the login', async () => {
    const failures: ((url: string) => Promise<Response>)[] = [
      async () => Response.json({ error: 'bad_verification_code' }),
      async () => new Response('down', { status: 503 }),
      async () => {
        throw new Error('network down')
      },
      async url =>
        url.endsWith('/access_token')
          ? Response.json({ access_token: githubGrant('x') })
          : Response.json({}),
    ]
    for (const fail of failures) {
      world.server = createOAuthServer({
        prefix: PREFIX,
        grantStore: world.store,
        env: world.env,
        now: () => world.clock,
        resolver: world.resolver,
        fetch: (url, init) => (url === CIMD_URL ? world.fakeFetch(url, init) : fail(url)),
      })
      const id = await registerClient(world, [CLAUDE_REDIRECT])
      const signed = await signIn(world, OWNER, id, pkce().challenge)
      expect(signed.response.status).toBe(502)
      expect(signed.code).toBeUndefined()
    }
  })
})

describe('REQ-OAUTH-2: spent, expired and mismatched grants', () => {
  it('REQ-OAUTH-2: answers invalid_grant when a refresh token is reused, and ends its family', async () => {
    const { clientId, tokens } = await ownerTokens(world)
    const next = (await (await refresh(world, clientId, tokens.refresh_token)).json()) as Tokens
    const reused = await refresh(world, clientId, tokens.refresh_token)
    expect(reused.status).toBe(400)
    expect(await errorOf(reused)).toBe('invalid_grant')
    // The newer token of that family is revoked too.
    expect(await errorOf(await refresh(world, clientId, next.refresh_token))).toBe('invalid_grant')
  })

  it('REQ-OAUTH-2: answers invalid_grant when a refresh token is expired', async () => {
    const { clientId, tokens } = await ownerTokens(world)
    world.clock += 31 * 24 * 60 * 60 * 1000
    const response = await refresh(world, clientId, tokens.refresh_token)
    expect(response.status).toBe(400)
    expect(await errorOf(response)).toBe('invalid_grant')
  })

  it('REQ-OAUTH-2: answers invalid_grant for garbage, an access token, a code, or another client', async () => {
    const { clientId, tokens } = await ownerTokens(world)
    const stranger = await registerClient(world, [CLAUDE_REDIRECT])
    const code = (await signIn(world, OWNER, clientId, pkce().challenge)).code ?? ''
    for (const [id, value] of [
      [clientId, 'garbage'],
      [clientId, tokens.access_token],
      [clientId, code],
      [stranger, tokens.refresh_token],
    ] as const) {
      const response = await refresh(world, id, value)
      expect(response.status).toBe(400)
      expect(await errorOf(response)).toBe('invalid_grant')
    }
    // The wrong-client attempt did not spend the token.
    expect((await refresh(world, clientId, tokens.refresh_token)).status).toBe(200)
  })

  it('REQ-OAUTH-2: refuses to refresh once the owner setting names someone else', async () => {
    const { clientId, tokens } = await ownerTokens(world)
    world.server = world.newServer({ OWNER_GITHUB_LOGIN: 'someone-else' })
    expect(await errorOf(await refresh(world, clientId, tokens.refresh_token))).toBe(
      'invalid_grant',
    )
  })

  it('REQ-OAUTH-2: answers invalid_grant when the PKCE verifier does not match', async () => {
    const clientId = await registerClient(world, [CLAUDE_REDIRECT])
    const signed = await signIn(world, OWNER, clientId, pkce().challenge)
    const response = await exchange(world, clientId, signed.code ?? '', pkce().verifier)
    expect(response.status).toBe(400)
    expect(await errorOf(response)).toBe('invalid_grant')
  })

  it('REQ-OAUTH-2: answers invalid_grant for a malformed verifier', async () => {
    const clientId = await registerClient(world, [CLAUDE_REDIRECT])
    for (const verifier of ['short', 'x'.repeat(129), `${'a'.repeat(42)} `]) {
      const signed = await signIn(world, OWNER, clientId, pkce().challenge)
      const response = await exchange(world, clientId, signed.code ?? '', verifier)
      expect(await errorOf(response)).toBe('invalid_grant')
    }
  })

  it('REQ-OAUTH-2: spends the code on a wrong verifier, so a stolen code allows one guess', async () => {
    const clientId = await registerClient(world, [CLAUDE_REDIRECT])
    const { verifier, challenge } = pkce()
    const signed = await signIn(world, OWNER, clientId, challenge)
    expect(await errorOf(await exchange(world, clientId, signed.code ?? '', pkce().verifier))).toBe(
      'invalid_grant',
    )
    expect(await errorOf(await exchange(world, clientId, signed.code ?? '', verifier))).toBe(
      'invalid_grant',
    )
  })

  it('REQ-OAUTH-2: refuses a code used twice, expired, or for another client or redirect', async () => {
    const clientId = await registerClient(world, [CLAUDE_REDIRECT, LOOPBACK_REDIRECT])
    const other = await registerClient(world, [CLAUDE_REDIRECT])
    const { verifier, challenge } = pkce()
    const signed = await signIn(world, OWNER, clientId, challenge)
    const code = signed.code ?? ''
    expect(await errorOf(await exchange(world, other, code, verifier))).toBe('invalid_grant')
    expect(await errorOf(await exchange(world, clientId, code, verifier, LOOPBACK_REDIRECT))).toBe(
      'invalid_grant',
    )
    expect((await exchange(world, clientId, code, verifier)).status).toBe(200)
    expect(await errorOf(await exchange(world, clientId, code, verifier))).toBe('invalid_grant')
    const late = await signIn(world, OWNER, clientId, challenge)
    world.clock += 61_000
    expect(await errorOf(await exchange(world, clientId, late.code ?? '', verifier))).toBe(
      'invalid_grant',
    )
    expect(await errorOf(await exchange(world, clientId, 'garbage', verifier))).toBe(
      'invalid_grant',
    )
  })

  it('REQ-OAUTH-2: refuses a code when the owner setting changed after sign-in', async () => {
    const clientId = await registerClient(world, [CLAUDE_REDIRECT])
    const { verifier, challenge } = pkce()
    const signed = await signIn(world, OWNER, clientId, challenge)
    world.server = world.newServer({ OWNER_GITHUB_LOGIN: 'someone-else' })
    expect(await errorOf(await exchange(world, clientId, signed.code ?? '', verifier))).toBe(
      'invalid_grant',
    )
  })

  it('REQ-OAUTH-2: does not accept a refresh token as a code', async () => {
    const { clientId, tokens } = await ownerTokens(world)
    const asCode = await exchange(world, clientId, tokens.refresh_token, pkce().verifier)
    expect(await errorOf(asCode)).toBe('invalid_grant')
  })
})

describe('REQ-OAUTH-2: reuse is caught through the shared grant store', () => {
  it('REQ-OAUTH-2: a second instance on the same store refuses a spent refresh token and code', async () => {
    const { clientId, tokens } = await ownerTokens(world)
    expect((await refresh(world, clientId, tokens.refresh_token)).status).toBe(200)
    world.server = world.newServer()
    expect(await errorOf(await refresh(world, clientId, tokens.refresh_token))).toBe(
      'invalid_grant',
    )
  })

  it('REQ-OAUTH-2: a second instance on the same store refuses a code reused', async () => {
    const clientId = await registerClient(world, [CLAUDE_REDIRECT])
    const { verifier, challenge } = pkce()
    const signed = await signIn(world, OWNER, clientId, challenge)
    expect((await exchange(world, clientId, signed.code ?? '', verifier)).status).toBe(200)
    world.server = world.newServer()
    expect(await errorOf(await exchange(world, clientId, signed.code ?? '', verifier))).toBe(
      'invalid_grant',
    )
  })

  it('REQ-OAUTH-2: records code, refresh and family IDs through grantStore.claim', async () => {
    const claimed: string[] = []
    const inner = createMemoryGrantStore(() => world.clock)
    const spy: GrantStore = {
      has: id => inner.has(id),
      async claim(id, expiresAt) {
        claimed.push(id)
        return inner.claim(id, expiresAt)
      },
    }
    world.server = world.newServer({}, spy)
    const { clientId, tokens } = await ownerTokens(world)
    await refresh(world, clientId, tokens.refresh_token)
    await refresh(world, clientId, tokens.refresh_token)
    expect(claimed.some(id => id.startsWith('code:'))).toBe(true)
    expect(claimed.some(id => id.startsWith('refresh:'))).toBe(true)
    expect(claimed.some(id => id.startsWith('family:'))).toBe(true)
  })

  it('REQ-OAUTH-2: keeps a family revoked until its newest token has expired', async () => {
    const day = 24 * 60 * 60 * 1000
    const { clientId, tokens } = await ownerTokens(world)
    world.clock += 10 * day
    const next = (await (await refresh(world, clientId, tokens.refresh_token)).json()) as Tokens
    world.clock += day
    expect(await errorOf(await refresh(world, clientId, tokens.refresh_token))).toBe(
      'invalid_grant',
    )
    world.clock += 24 * day
    expect(await errorOf(await refresh(world, clientId, next.refresh_token))).toBe('invalid_grant')
  })

  it('REQ-OAUTH-2: answers 503 and issues no token when the store rejects, without leaking the detail', async () => {
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const clientId = await registerClient(world, [CLAUDE_REDIRECT])
      const { verifier, challenge } = pkce()
      const signed = await signIn(world, OWNER, clientId, challenge)
      const failing: GrantStore = {
        async has() {
          throw new GrantStoreError('private-repo/oauth-grants.json is down')
        },
        async claim() {
          throw new GrantStoreError('private-repo/oauth-grants.json is down')
        },
      }
      world.server = world.newServer({}, failing)
      const response = await exchange(world, clientId, signed.code ?? '', verifier)
      expect(response.status).toBe(503)
      const body = (await response.json()) as Record<string, string>
      expect(body.error).toBe('temporarily_unavailable')
      expect(JSON.stringify(body)).not.toContain('private-repo')
      expect(body).not.toHaveProperty('access_token')
      expect(String(logged.mock.calls[0]?.[0])).toContain('private-repo')
      expect(String(logged.mock.calls[0]?.[0])).toContain(PREFIX)
    } finally {
      logged.mockRestore()
    }
  })

  it('REQ-OAUTH-2: answers 503 and issues no token when the revocation check rejects on refresh', async () => {
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const { clientId, tokens } = await ownerTokens(world)
      world.server = world.newServer(
        {},
        {
          async has() {
            throw new GrantStoreError('record unreadable')
          },
          async claim() {
            return true
          },
        },
      )
      const response = await refresh(world, clientId, tokens.refresh_token)
      expect(response.status).toBe(503)
      expect(await response.text()).not.toContain('record unreadable')
    } finally {
      logged.mockRestore()
    }
  })

  it('REQ-OAUTH-2: shows the owner a setup step when the store error says it is the owner to fix', async () => {
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const clientId = await registerClient(world, [CLAUDE_REDIRECT])
      const { verifier, challenge } = pkce()
      const signed = await signIn(world, OWNER, clientId, challenge)
      world.server = world.newServer(
        {},
        {
          async has() {
            return false
          },
          async claim() {
            throw new GrantStoreError('install the app on the data repo', true)
          },
        },
      )
      const response = await exchange(world, clientId, signed.code ?? '', verifier)
      expect(response.status).toBe(503)
      expect(
        ((await response.json()) as { error_description: string }).error_description,
      ).toContain('install the app on the data repo')
    } finally {
      logged.mockRestore()
    }
  })

  it('REQ-OAUTH-2: a store that rejects with another error is not swallowed', async () => {
    const clientId = await registerClient(world, [CLAUDE_REDIRECT])
    const { verifier, challenge } = pkce()
    const signed = await signIn(world, OWNER, clientId, challenge)
    world.server = world.newServer(
      {},
      {
        async has() {
          return false
        },
        async claim() {
          throw new TypeError('bug in the store')
        },
      },
    )
    await expect(exchange(world, clientId, signed.code ?? '', verifier)).rejects.toThrow(
      'bug in the store',
    )
  })
})

describe('REQ-OAUTH-2: client metadata documents go through the SSRF check', () => {
  async function authorizeCimd(): Promise<Response> {
    return world.server.authorize(authorizeRequest(authorizeParams(CIMD_URL, pkce().challenge)))
  }

  it.each([
    ['a private IPv4 address', { v4: ['10.0.0.8'] }],
    ['a loopback address', { v4: ['127.0.0.1'] }],
    ['a link-local metadata address', { v4: ['169.254.169.254'] }],
    ['a private 192.168 address', { v4: ['192.168.1.20'] }],
    ['a private IPv6 address', { v6: ['fd00::1'] }],
    ['IPv6 loopback', { v6: ['::1'] }],
    ['one public and one private address', { v4: [PUBLIC_IP, '10.1.2.3'] }],
  ])(
    'REQ-OAUTH-2: refuses a URL that resolves to %s, with no fetch and no code',
    async (_label, row) => {
      world.dnsTable = { [CIMD_HOST]: row }
      const response = await authorizeCimd()
      expect(response.status).toBe(400)
      expect(response.headers.get('location')).toBeNull()
      expect(await response.text()).toContain('private')
      expect(world.fetchedUrls).toEqual([])
    },
  )

  it('REQ-OAUTH-2: refuses a URL that does not resolve, with no fetch and no code', async () => {
    const tables: (typeof world.dnsTable)[] = [
      {},
      { [CIMD_HOST]: {} },
      { [CIMD_HOST]: { v4: [], v6: [] } },
    ]
    for (const table of tables) {
      world.dnsTable = table
      const response = await authorizeCimd()
      expect(response.status).toBe(400)
      expect(response.headers.get('location')).toBeNull()
      expect(await response.text()).toContain('DNS resolution failed')
      expect(world.fetchedUrls).toEqual([])
    }
  })

  it('REQ-OAUTH-2: refuses a URL on a port other than 443', async () => {
    const url = `https://${CIMD_HOST}:8443/client.json`
    const response = await world.server.authorize(
      authorizeRequest(authorizeParams(url, pkce().challenge)),
    )
    expect(response.status).toBe(400)
    expect(world.fetchedUrls).toEqual([])
  })

  it('REQ-OAUTH-2: fetches a URL that resolves only to public addresses', async () => {
    world.dnsTable = {
      [CIMD_HOST]: { v4: [PUBLIC_IP], v6: ['2606:2800:220:1::1'] },
    }
    const response = await authorizeCimd()
    expect(response.status).toBe(302)
    expect(world.fetchedUrls).toEqual([CIMD_URL])
  })

  it('REQ-OAUTH-2: cheap filters still refuse IP literals, internal names and bare hosts before any lookup', async () => {
    for (const clientId of [
      'https://203.0.113.9/client.json',
      'https://localhost/client.json',
      'https://metadata.internal/client.json',
      'https://client.example.test/',
      'https://intranet/client.json',
      'https://[::1]/client.json',
      'https://user:pw@client.example.test/c.json',
      'http://client.example.test/c.json',
    ]) {
      const response = await world.server.authorize(
        authorizeRequest(authorizeParams(clientId, pkce().challenge)),
      )
      expect(response.status).toBe(400)
    }
    expect(world.fetchedUrls).toEqual([])
    expect(world.resolverCalls).toEqual([])
  })

  it('REQ-OAUTH-2: fetches a client metadata document pinned to the address the SSRF check allowed', async () => {
    const signed = await signIn(world, OWNER, CIMD_URL, pkce().challenge)
    expect(signed.code).toBeDefined()
    expect(world.resolverCalls).toEqual([CIMD_HOST])
    const document = world.fetchPins.filter(call => call.url === CIMD_URL)
    expect(document).toEqual([{ url: CIMD_URL, pin: { address: PUBLIC_IP, family: 4 } }])
    // GitHub calls are not client-chosen URLs and are not pinned.
    expect(world.fetchPins.filter(call => call.url.includes('github')).map(c => c.pin)).toEqual([
      undefined,
      undefined,
    ])
  })

  it('REQ-OAUTH-2: pins an IPv6-only host with family 6', async () => {
    world.dnsTable = { [CIMD_HOST]: { v6: ['2606:2800:220:1::1'] } }
    const response = await world.server.authorize(
      authorizeRequest(authorizeParams(CIMD_URL, pkce().challenge)),
    )
    expect(response.status).toBe(302)
    expect(world.fetchPins.find(call => call.url === CIMD_URL)?.pin).toEqual({
      address: '2606:2800:220:1::1',
      family: 6,
    })
  })
})

describe('REQ-OAUTH-2: redirectMatches', () => {
  it('REQ-OAUTH-2: ignores the port for loopback only and matches the hosted redirect exactly', () => {
    expect(redirectMatches('http://localhost:1/callback', ['http://localhost:2/callback'])).toBe(
      true,
    )
    expect(redirectMatches('http://localhost/callback', [CLAUDE_REDIRECT])).toBe(false)
    expect(redirectMatches(CLAUDE_REDIRECT, [CLAUDE_REDIRECT])).toBe(true)
    expect(redirectMatches(CLAUDE_REDIRECT, [])).toBe(false)
  })
})
