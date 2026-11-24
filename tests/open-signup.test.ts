// BUI-2214: `<PREFIX>_SIGNUP=open` gives any GitHub login its own token subject.
import { createLocalJWKSet, importJWK, SignJWT } from 'jose'
import { describe, expect, it } from 'vitest'
import { authorizeMcpRequest, signupMode } from '../src/index.js'
import {
  CLAUDE_REDIRECT,
  ISSUER,
  MCP_URL,
  OWNER,
  PREFIX,
  createWorld,
  errorOf,
  exchange,
  makeEnv,
  pkce,
  refresh,
  registerClient,
  signIn,
} from './support.js'
import type { Tokens, World } from './support.js'

const SIGNUP = `${PREFIX}_SIGNUP`
const VISITOR = 'New-Visitor'

async function worlds(): Promise<{ open: World; closed: World; env: Record<string, string> }> {
  const base = await makeEnv()
  const open = createWorld({ ...base, [SIGNUP]: 'open' })
  const closed = createWorld({ ...base })
  return { open, closed, env: base }
}

async function visitorTokens(
  world: World,
  login = VISITOR,
): Promise<{ clientId: string; tokens: Tokens }> {
  const clientId = await registerClient(world, [CLAUDE_REDIRECT])
  const { verifier, challenge } = pkce()
  const signed = await signIn(world, login, clientId, challenge)
  expect(signed.code).toBeDefined()
  const response = await exchange(world, clientId, signed.code ?? '', verifier)
  expect(response.status).toBe(200)
  return { clientId, tokens: (await response.json()) as Tokens }
}

async function checker(world: World, resourceExtra: Record<string, string>) {
  const published = await world.server.jwks(new Request(`${ISSUER}/oauth/jwks`))
  const keys = createLocalJWKSet(
    (await published.json()) as Parameters<typeof createLocalJWKSet>[0],
  )
  const env = {
    [`${PREFIX}_OAUTH_ISSUER`]: ISSUER,
    [`${PREFIX}_OAUTH_JWKS_URL`]: `${ISSUER}/oauth/jwks`,
    ...resourceExtra,
  }
  return (bearer: string) =>
    authorizeMcpRequest(new Request(MCP_URL, { headers: { authorization: `Bearer ${bearer}` } }), {
      prefix: PREFIX,
      env,
      keys,
    })
}

async function signedFor(
  env: Record<string, string>,
  audience: string,
  subject = VISITOR.toLowerCase(),
): Promise<string> {
  const key = await importJWK(JSON.parse(env[`${PREFIX}_OAUTH_SIGNING_KEY`] ?? '{}'), 'ES256')
  const published = await createWorld(env).server.jwks(new Request(`${ISSUER}/oauth/jwks`))
  const kid = ((await published.json()) as { keys: { kid: string }[] }).keys[0]?.kid
  return new SignJWT({ client_id: 'c', scope: 'mcp' })
    .setProtectedHeader({ alg: 'ES256', kid })
    .setIssuer(ISSUER)
    .setSubject(subject)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(key)
}

describe('REQ-SIGNUP-1: the OAuth server gives any GitHub login a code in open mode', () => {
  it('REQ-SIGNUP-1: a non-owner login gets a code and tokens with its own lower-case sub', async () => {
    const { open } = await worlds()
    const { tokens } = await visitorTokens(open)
    const claims = JSON.parse(
      Buffer.from(tokens.access_token.split('.')[1] ?? '', 'base64url').toString('utf8'),
    ) as { sub: string; aud: string }
    expect(claims.sub).toBe('new-visitor')
    expect(claims.aud).toBe(MCP_URL)
  })

  it('REQ-SIGNUP-1: open mode needs no OWNER_GITHUB_LOGIN', async () => {
    const base = await makeEnv(PREFIX, { [SIGNUP]: 'open' })
    delete base.OWNER_GITHUB_LOGIN
    const { tokens } = await visitorTokens(createWorld(base))
    expect(tokens.access_token).not.toBe('')
  })

  it('REQ-SIGNUP-1: the owner login also gets its lower-case login as sub in open mode', async () => {
    const { open } = await worlds()
    const { tokens } = await visitorTokens(open, OWNER)
    const claims = JSON.parse(
      Buffer.from(tokens.access_token.split('.')[1] ?? '', 'base64url').toString('utf8'),
    ) as { sub: string }
    expect(claims.sub).toBe(OWNER.toLowerCase())
  })

  it('REQ-SIGNUP-1: a refresh token keeps its own subject in open mode', async () => {
    const { open } = await worlds()
    const { clientId, tokens } = await visitorTokens(open)
    const response = await refresh(open, clientId, tokens.refresh_token)
    expect(response.status).toBe(200)
    const next = (await response.json()) as Tokens
    const check = await checker(open, { [SIGNUP]: 'open' })
    const result = await check(next.access_token)
    expect(result.ok && result.value.extra).toEqual({ subject: 'new-visitor' })
  })

  it('REQ-SIGNUP-1: with signup unset the same login gets 403 at sign-in and no code', async () => {
    const { closed } = await worlds()
    const clientId = await registerClient(closed, [CLAUDE_REDIRECT])
    const signed = await signIn(closed, VISITOR, clientId, pkce().challenge)
    expect(signed.response.status).toBe(403)
    expect(signed.code).toBeUndefined()
  })

  it('REQ-SIGNUP-1: SIGNUP=owner (any case, padded) keeps the owner-only rule', async () => {
    const base = await makeEnv(PREFIX, { [SIGNUP]: ' Owner ' })
    const world = createWorld(base)
    const clientId = await registerClient(world, [CLAUDE_REDIRECT])
    expect((await signIn(world, VISITOR, clientId, pkce().challenge)).response.status).toBe(403)
    const { tokens } = await visitorTokens(world, OWNER)
    expect(tokens.access_token).not.toBe('')
  })

  it('REQ-SIGNUP-1: a code from open mode is refused once the server is owner-only again', async () => {
    const { open, closed } = await worlds()
    const clientId = await registerClient(open, [CLAUDE_REDIRECT])
    const { verifier, challenge } = pkce()
    const signed = await signIn(open, VISITOR, clientId, challenge)
    const response = await exchange(closed, clientId, signed.code ?? '', verifier)
    expect(response.status).toBe(400)
    expect(await errorOf(response)).toBe('invalid_grant')
  })

  it('REQ-SIGNUP-1: a refresh token from open mode is refused once the server is owner-only again', async () => {
    const { open, closed } = await worlds()
    const { clientId, tokens } = await visitorTokens(open)
    const response = await refresh(closed, clientId, tokens.refresh_token)
    expect(response.status).toBe(400)
    expect(await errorOf(response)).toBe('invalid_grant')
  })

  it('REQ-SIGNUP-1: an unknown SIGNUP value is a 500 that names the setting', async () => {
    const world = createWorld(await makeEnv(PREFIX, { [SIGNUP]: 'everyone' }))
    const clientId = await registerClient(world, [CLAUDE_REDIRECT])
    const start = await world.server.authorize(
      new Request(
        `${ISSUER}/oauth/authorize?${new URLSearchParams({
          response_type: 'code',
          client_id: clientId,
          redirect_uri: CLAUDE_REDIRECT,
          code_challenge: pkce().challenge,
          code_challenge_method: 'S256',
          resource: MCP_URL,
        })}`,
      ),
    )
    expect(start.status).toBe(500)
    expect(JSON.stringify(await start.json())).toContain(SIGNUP)
  })
})

describe('REQ-SIGNUP-2: http-auth accepts any subject in open mode', () => {
  it('REQ-SIGNUP-2: accepts a visitor token and returns its subject, with no owner subject set', async () => {
    const { open } = await worlds()
    const { clientId, tokens } = await visitorTokens(open)
    const check = await checker(open, { [SIGNUP]: 'open' })
    const result = await check(tokens.access_token)
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.value.extra).toEqual({ subject: 'new-visitor' })
      expect(result.value.clientId).toBe(clientId)
    }
  })

  it('REQ-SIGNUP-2: open mode still refuses a refresh token, a missing token and a wrong signature', async () => {
    const { open } = await worlds()
    const { tokens } = await visitorTokens(open)
    const check = await checker(open, { [SIGNUP]: 'open' })
    expect((await check(tokens.refresh_token)).ok).toBe(false)
    const forged = tokens.access_token.slice(0, -4) + 'AAAA'
    const refused = await check(forged)
    expect(refused.ok).toBe(false)
    if (!refused.ok) expect(refused.response.status).toBe(401)
  })

  it('REQ-SIGNUP-2: an unknown SIGNUP value is a 503 that names the setting', async () => {
    const { open } = await worlds()
    const { tokens } = await visitorTokens(open)
    const check = await checker(open, { [SIGNUP]: 'everyone' })
    const result = await check(tokens.access_token)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.response.status).toBe(503)
      expect(JSON.stringify(await result.response.json())).toContain(SIGNUP)
    }
  })

  it('REQ-SIGNUP-2: with signup unset another subject gets 403 access_denied', async () => {
    const { open } = await worlds()
    const { tokens } = await visitorTokens(open)
    const check = await checker(open, { [`${PREFIX}_OWNER_SUBJECT`]: OWNER })
    const result = await check(tokens.access_token)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.response.status).toBe(403)
      expect(await errorOf(result.response)).toBe('access_denied')
    }
  })

  it('REQ-SIGNUP-2: with SIGNUP=owner another subject gets 403 access_denied', async () => {
    const { open } = await worlds()
    const { tokens } = await visitorTokens(open)
    const check = await checker(open, { [SIGNUP]: 'owner', [`${PREFIX}_OWNER_SUBJECT`]: OWNER })
    const result = await check(tokens.access_token)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.response.status).toBe(403)
  })

  it('REQ-SIGNUP-2: with signup unset the owner subject setting is still required', async () => {
    const { open } = await worlds()
    const { tokens } = await visitorTokens(open)
    const check = await checker(open, {})
    const result = await check(tokens.access_token)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.response.status).toBe(503)
  })
})

describe('REQ-SIGNUP-2: audience checks stay in both modes', () => {
  it('REQ-SIGNUP-2: a token for the wrong audience gets 401 with signup open and unset', async () => {
    const { open, env } = await worlds()
    const wrong = await signedFor(env, 'https://elsewhere.example.test/api/mcp')
    const right = await signedFor(env, MCP_URL)
    const resourceModes: Record<string, string>[] = [
      { [SIGNUP]: 'open' },
      { [`${PREFIX}_OWNER_SUBJECT`]: VISITOR.toLowerCase() },
    ]
    for (const resourceExtra of resourceModes) {
      const check = await checker(open, resourceExtra)
      const refused = await check(wrong)
      expect(refused.ok).toBe(false)
      if (!refused.ok) expect(refused.response.status).toBe(401)
      expect((await check(right)).ok).toBe(true)
    }
  })
})

describe('REQ-SIGNUP-3: the package exports the signup mode', () => {
  it('REQ-SIGNUP-3: signupMode reads <PREFIX>_SIGNUP', () => {
    expect(signupMode(PREFIX, { [SIGNUP]: 'open' })).toBe('open')
    expect(signupMode(PREFIX, { [SIGNUP]: ' OPEN ' })).toBe('open')
    expect(signupMode(PREFIX, { [SIGNUP]: 'owner' })).toBe('owner')
    expect(signupMode(PREFIX, {})).toBe('owner')
    expect(signupMode(PREFIX, { [SIGNUP]: '' })).toBe('owner')
    expect(signupMode(PREFIX, { [SIGNUP]: 'everyone' })).toBe('owner')
    expect(signupMode(PREFIX, { OTHER_SIGNUP: 'open' })).toBe('owner')
  })
})
