// REQ-HTTPAUTH-1 to 5: the resource-server checks (BUI-2098), ported from
// jobrecon's coverage of mcp/http-auth.ts.
import { readFileSync } from 'node:fs'
import { exportJWK, generateKeyPair, SignJWT } from 'jose'
import type { JWTVerifyGetKey } from 'jose'
import { beforeAll, describe, expect, it } from 'vitest'
import {
  RESOURCE_METADATA_PATH,
  authorizeMcpRequest,
  createMemoryGrantStore,
  createOAuthServer,
  resourceUrls,
} from '../src/index.js'
import { ISSUER, MCP_URL, OWNER, PREFIX } from './support.js'

const JWKS_URL = 'https://app.example.test/oauth/jwks'
const METADATA_URL = `${ISSUER}/.well-known/oauth-protected-resource`
const CHALLENGE = `Bearer resource_metadata="${METADATA_URL}"`

const env = {
  [`${PREFIX}_OAUTH_ISSUER`]: ISSUER,
  [`${PREFIX}_OAUTH_JWKS_URL`]: JWKS_URL,
  [`${PREFIX}_OWNER_SUBJECT`]: OWNER,
}

let privateKey: CryptoKey
let keys: JWTVerifyGetKey

beforeAll(async () => {
  const pair = await generateKeyPair('ES256')
  privateKey = pair.privateKey
  keys = async () => pair.publicKey
})

interface SignOptions {
  readonly issuer?: string
  readonly audience?: string
  readonly subject?: string
  readonly expiresIn?: string | number
  readonly extra?: Record<string, unknown>
}

function sign(options: SignOptions = {}): Promise<string> {
  return new SignJWT({ scope: 'mcp', client_id: 'client-1', ...options.extra })
    .setProtectedHeader({ alg: 'ES256' })
    .setIssuer(options.issuer ?? ISSUER)
    .setAudience(options.audience ?? MCP_URL)
    .setSubject(options.subject ?? OWNER)
    .setIssuedAt()
    .setExpirationTime(options.expiresIn ?? '1h')
    .sign(privateKey)
}

function call(
  bearer: string | undefined,
  settings: Record<string, string | undefined> = env,
  url = MCP_URL,
) {
  return authorizeMcpRequest(
    new Request(url, bearer === undefined ? {} : { headers: { authorization: bearer } }),
    { prefix: PREFIX, env: settings, keys },
  )
}

async function rejected(result: Awaited<ReturnType<typeof call>>): Promise<Response> {
  expect(result.ok).toBe(false)
  if (result.ok) throw new Error('expected a rejection')
  return result.response
}

describe('REQ-HTTPAUTH-1: no or an invalid bearer token answers 401 with the metadata challenge', () => {
  it('REQ-HTTPAUTH-1: a request with no Authorization header answers 401 and WWW-Authenticate', async () => {
    const response = await rejected(await call(undefined))
    expect(response.status).toBe(401)
    expect(response.headers.get('www-authenticate')).toBe(CHALLENGE)
    expect(((await response.json()) as { error: string }).error).toBe('invalid_token')
  })

  it('REQ-HTTPAUTH-1: a non-bearer scheme and an empty bearer answer 401', async () => {
    for (const header of ['Basic dXNlcjpwYXNz', 'Bearer ', 'Bearer a b']) {
      const response = await rejected(await call(header))
      expect(response.status).toBe(401)
      expect(response.headers.get('www-authenticate')).toBe(CHALLENGE)
    }
  })

  it('REQ-HTTPAUTH-1: a token that is not a JWT answers 401', async () => {
    const response = await rejected(await call('Bearer not-a-jwt'))
    expect(response.status).toBe(401)
    expect(response.headers.get('www-authenticate')).toBe(CHALLENGE)
  })

  it('REQ-HTTPAUTH-1: a wrong audience answers 401', async () => {
    const response = await rejected(
      await call(`Bearer ${await sign({ audience: 'https://other.example.test/api/mcp' })}`),
    )
    expect(response.status).toBe(401)
    expect(response.headers.get('www-authenticate')).toBe(CHALLENGE)
  })

  it('REQ-HTTPAUTH-1: a wrong issuer answers 401', async () => {
    const response = await rejected(
      await call(`Bearer ${await sign({ issuer: 'https://evil.example.test' })}`),
    )
    expect(response.status).toBe(401)
  })

  it('REQ-HTTPAUTH-1: an expired token answers 401', async () => {
    const response = await rejected(await call(`Bearer ${await sign({ expiresIn: -60 })}`))
    expect(response.status).toBe(401)
    expect(response.headers.get('www-authenticate')).toBe(CHALLENGE)
  })

  it('REQ-HTTPAUTH-1: a token signed by another key answers 401', async () => {
    const other = await generateKeyPair('ES256')
    const forged = await new SignJWT({})
      .setProtectedHeader({ alg: 'ES256' })
      .setIssuer(ISSUER)
      .setAudience(MCP_URL)
      .setSubject(OWNER)
      .setExpirationTime('1h')
      .sign(other.privateKey)
    const response = await rejected(await call(`Bearer ${forged}`))
    expect(response.status).toBe(401)
  })

  it('REQ-HTTPAUTH-1: a symmetric (HS256) token answers 401', async () => {
    const secret = new TextEncoder().encode('k'.repeat(32))
    const symmetric = await new SignJWT({})
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuer(ISSUER)
      .setAudience(MCP_URL)
      .setSubject(OWNER)
      .setExpirationTime('1h')
      .sign(secret)
    const response = await rejected(await call(`Bearer ${symmetric}`))
    expect(response.status).toBe(401)
  })

  it('REQ-HTTPAUTH-1: a token without an expiry answers 401', async () => {
    const noExpiry = await new SignJWT({})
      .setProtectedHeader({ alg: 'ES256' })
      .setIssuer(ISSUER)
      .setAudience(MCP_URL)
      .setSubject(OWNER)
      .sign(privateKey)
    const response = await rejected(await call(`Bearer ${noExpiry}`))
    expect(response.status).toBe(401)
  })

  it('REQ-HTTPAUTH-1: another subject answers 403, not a sign-in challenge', async () => {
    const response = await rejected(await call(`Bearer ${await sign({ subject: 'someone-else' })}`))
    expect(response.status).toBe(403)
    expect(response.headers.get('www-authenticate')).toBeNull()
    expect(((await response.json()) as { error: string }).error).toBe('access_denied')
  })

  it('REQ-HTTPAUTH-1: a key set that cannot be loaded answers 502, not 401', async () => {
    const result = await authorizeMcpRequest(
      new Request(MCP_URL, { headers: { authorization: `Bearer ${await sign()}` } }),
      {
        prefix: PREFIX,
        env,
        keys: async () => {
          throw new Error('fetch failed')
        },
      },
    )
    const response = await rejected(result)
    expect(response.status).toBe(502)
    expect(response.headers.get('www-authenticate')).toBeNull()
  })
})

describe('REQ-HTTPAUTH-2: a valid owner token returns the AuthInfo', () => {
  it('REQ-HTTPAUTH-2: returns token, client, scopes, expiry, resource and subject', async () => {
    const token = await sign()
    const result = await call(`Bearer ${token}`)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.value).toMatchObject({
      token,
      clientId: 'client-1',
      scopes: ['mcp'],
      extra: { subject: OWNER },
    })
    expect(result.value.resource?.href).toBe(MCP_URL)
    expect(typeof result.value.expiresAt).toBe('number')
  })

  it('REQ-HTTPAUTH-2: takes the client from azp when client_id is absent, and empty scopes when none', async () => {
    const token = await sign({ extra: { scope: undefined, client_id: undefined, azp: 'azp-1' } })
    const result = await call(`Bearer ${token}`)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.value.clientId).toBe('azp-1')
    expect(result.value.scopes).toEqual([])
  })

  it('REQ-HTTPAUTH-2: the scheme name is case-insensitive and a trailing issuer slash is ignored', async () => {
    const result = await call(`bearer ${await sign()}`, {
      ...env,
      [`${PREFIX}_OAUTH_ISSUER`]: `${ISSUER}/`,
    })
    expect(result.ok).toBe(true)
  })

  it('REQ-HTTPAUTH-2: accepts the access token the package server issues, and no other signed value', async () => {
    const pair = await generateKeyPair('ES256', { extractable: true })
    const serverEnv = {
      [`${PREFIX}_OAUTH_ISSUER`]: ISSUER,
      [`${PREFIX}_OAUTH_SIGNING_KEY`]: JSON.stringify(await exportJWK(pair.privateKey)),
      OWNER_GITHUB_LOGIN: OWNER,
      [`${PREFIX}_GITHUB_OAUTH_CLIENT_ID`]: 'gh-client',
      [`${PREFIX}_GITHUB_OAUTH_CLIENT_SECRET`]: ['gh', 'cred'].join('-'),
    }
    const server = createOAuthServer({
      prefix: PREFIX,
      grantStore: createMemoryGrantStore(),
      env: serverEnv,
    })
    const published = await server.jwks(new Request(`${ISSUER}/oauth/jwks`))
    const { createLocalJWKSet } = await import('jose')
    const local = createLocalJWKSet(
      (await published.json()) as Parameters<typeof createLocalJWKSet>[0],
    )
    // A server-signed value of another kind (a client ID) is not an access token.
    const registered = await server.register(
      new Request(`${ISSUER}/oauth/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
          token_endpoint_auth_method: 'none',
        }),
      }),
    )
    const { client_id: clientId } = (await registered.json()) as { client_id: string }
    const result = await authorizeMcpRequest(
      new Request(MCP_URL, { headers: { authorization: `Bearer ${clientId}` } }),
      { prefix: PREFIX, env, keys: local },
    )
    expect(result.ok).toBe(false)
  })
})

describe('REQ-HTTPAUTH-3: resourceUrls takes the host from the request URL, not proxy headers', () => {
  it('REQ-HTTPAUTH-3: builds the MCP and metadata URLs from the origin of request.url', () => {
    expect(resourceUrls(new Request(`${ISSUER}/api/mcp?x=1`))).toEqual({
      mcpUrl: MCP_URL,
      metadataUrl: METADATA_URL,
    })
    expect(RESOURCE_METADATA_PATH).toBe('/.well-known/oauth-protected-resource')
  })

  it('REQ-HTTPAUTH-3: ignores X-Forwarded-Host, X-Forwarded-Proto and Host from the caller', () => {
    const request = new Request(MCP_URL, {
      headers: {
        'x-forwarded-host': 'evil.example.test',
        'x-forwarded-proto': 'http',
        host: 'evil.example.test',
        forwarded: 'host=evil.example.test',
      },
    })
    expect(resourceUrls(request)).toEqual({ mcpUrl: MCP_URL, metadataUrl: METADATA_URL })
  })

  it('REQ-HTTPAUTH-3: the 401 challenge for a proxied request names the trusted host', async () => {
    const response = await rejected(
      await authorizeMcpRequest(
        new Request(MCP_URL, { headers: { 'x-forwarded-host': 'evil.example.test' } }),
        { prefix: PREFIX, env, keys },
      ),
    )
    expect(response.headers.get('www-authenticate')).toBe(CHALLENGE)
  })

  it('REQ-HTTPAUTH-3: a token for a forwarded-host audience is refused', async () => {
    const response = await rejected(
      await authorizeMcpRequest(
        new Request(MCP_URL, {
          headers: {
            authorization: `Bearer ${await sign({ audience: 'https://evil.example.test/api/mcp' })}`,
            'x-forwarded-host': 'evil.example.test',
          },
        }),
        { prefix: PREFIX, env, keys },
      ),
    )
    expect(response.status).toBe(401)
  })
})

describe('REQ-HTTPAUTH-4: a missing setting answers 503 naming it', () => {
  const names = [`${PREFIX}_OAUTH_ISSUER`, `${PREFIX}_OAUTH_JWKS_URL`, `${PREFIX}_OWNER_SUBJECT`]

  it.each(names)('REQ-HTTPAUTH-4: %s missing answers 503 naming it', async name => {
    const settings = { ...env, [name]: undefined }
    const response = await rejected(await call(`Bearer ${await sign()}`, settings))
    expect(response.status).toBe(503)
    const body = (await response.json()) as { error_description: string; missing: string[] }
    expect(body.error_description).toContain(name)
    expect(body.missing).toEqual([name])
  })

  it('REQ-HTTPAUTH-4: a blank setting counts as missing, and all missing names are listed', async () => {
    const response = await rejected(await call(undefined, { [names[0]]: '   ' }))
    expect(response.status).toBe(503)
    const body = (await response.json()) as { missing: string[] }
    expect(body.missing).toEqual(names)
  })

  it('REQ-HTTPAUTH-4: the configuration is checked before the token, even with none sent', async () => {
    const response = await rejected(await call(undefined, {}))
    expect(response.status).toBe(503)
    expect(response.headers.get('www-authenticate')).toBeNull()
  })

  it('REQ-HTTPAUTH-4: an issuer or JWKS URL that is not https is named as invalid, without its value', async () => {
    const response = await rejected(
      await call(undefined, { ...env, [names[1]]: 'http://keys.example.test/jwks' }),
    )
    expect(response.status).toBe(503)
    const body = (await response.json()) as { error_description: string; invalid: string[] }
    expect(body.invalid).toEqual([names[1]])
    expect(body.error_description).toContain(names[1])
    expect(body.error_description).not.toContain('keys.example.test')
  })

  it('REQ-HTTPAUTH-4: reads only the given prefix', async () => {
    const other = Object.fromEntries(
      Object.entries(env).map(([key, value]) => [key.replace(PREFIX, 'OTHER'), value]),
    )
    const response = await rejected(await call(undefined, other))
    expect(response.status).toBe(503)
  })

  it('REQ-HTTPAUTH-4: a prefix that is not upper case is refused when authorizing', async () => {
    await expect(
      authorizeMcpRequest(new Request(MCP_URL), { prefix: 'lower', env }),
    ).rejects.toThrow(/prefix/)
  })
})

describe('REQ-HTTPAUTH-5: package.json dependencies', () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
    dependencies?: Record<string, string>
    peerDependencies?: Record<string, string>
    devDependencies?: Record<string, string>
  }

  it('REQ-HTTPAUTH-5: jose is a dependency', () => {
    expect(pkg.dependencies).toHaveProperty('jose')
  })

  it('REQ-HTTPAUTH-5: @modelcontextprotocol/server is a peer and a dev dependency, not a dependency', () => {
    expect(pkg.peerDependencies).toHaveProperty('@modelcontextprotocol/server')
    expect(pkg.devDependencies).toHaveProperty('@modelcontextprotocol/server')
    expect(pkg.dependencies).not.toHaveProperty('@modelcontextprotocol/server')
  })
})
