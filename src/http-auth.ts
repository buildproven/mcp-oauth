// Resource-server checks for the hosted MCP route (BUI-2098). The route is an
// OAuth 2.0 resource server: it accepts only a JWT access token that the
// configured issuer signed (keys from its JWKS URL), issued for this server's
// MCP URL (`aud`, RFC 8707), unexpired, and whose subject is the owner. It
// never issues tokens; sign-in belongs to the authorization server.
import type { AuthInfo } from '@modelcontextprotocol/server'
import { createRemoteJWKSet, errors, jwtVerify } from 'jose'
import type { JWTPayload, JWTVerifyGetKey } from 'jose'
import { MCP_PATH, PREFIX_PATTERN } from './oauth-server.js'

/** Path of the RFC 9728 protected resource metadata document. */
export const RESOURCE_METADATA_PATH = '/.well-known/oauth-protected-resource'

// Asymmetric algorithms only: a symmetric (HS*) token would need a shared
// secret, and allowing one invites algorithm-confusion attacks.
const ALGORITHMS = ['RS256', 'PS256', 'ES256', 'EdDSA', 'Ed25519']

type Env = Readonly<Record<string, string | undefined>>

export interface AuthorizeConfig {
  /** Upper-case product prefix: env names are `<PREFIX>_OAUTH_ISSUER` and so on. */
  readonly prefix: string
  /** Settings source, read on each request. Default `process.env`. */
  readonly env?: Env
  /**
   * Replaces the issuer's remote key set. Tests pass the authorization
   * server's own keys so that no fetch is needed.
   */
  readonly keys?: JWTVerifyGetKey
}

export type AuthResult =
  | { readonly ok: true; readonly value: AuthInfo }
  | { readonly ok: false; readonly response: Response }

/**
 * The MCP URL and metadata URL of the deployment that serves `request`. The
 * host is the one in `request.url`, which the platform sets; a caller's
 * `Host`, `Forwarded` or `X-Forwarded-*` header is never used, so a client
 * cannot choose the audience or the challenge URL.
 */
export function resourceUrls(request: Request): {
  readonly mcpUrl: string
  readonly metadataUrl: string
} {
  const { origin } = new URL(request.url)
  return {
    mcpUrl: `${origin}${MCP_PATH}`,
    metadataUrl: `${origin}${RESOURCE_METADATA_PATH}`,
  }
}

function isSecureUrl(value: string): boolean {
  if (!URL.canParse(value)) return false
  const url = new URL(value)
  if (url.protocol === 'https:') return true
  return (
    url.protocol === 'http:' &&
    (url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]')
  )
}

/** A 503 that names the settings at fault and never their values. */
function configProblem(missing: readonly string[], invalid: readonly string[]): Response {
  const parts = [
    missing.length > 0 ? `missing ${missing.join(', ')}` : '',
    invalid.length > 0 ? `not an https URL: ${invalid.join(', ')}` : '',
  ].filter(part => part !== '')
  return Response.json(
    {
      error: 'server_error',
      error_description: `MCP OAuth configuration: ${parts.join('; ')}`,
      missing,
      invalid,
    },
    { status: 503, headers: { 'cache-control': 'no-store' } },
  )
}

interface Settings {
  /** The issuer without trailing slashes, the form the server signs as `iss`. */
  readonly issuer: string
  readonly jwksUrl: URL
  /** The one token subject (`sub`) the route serves. */
  readonly ownerSubject: string
}

function readSettings(
  prefix: string,
  env: Env,
): { ok: true; value: Settings } | { ok: false; response: Response } {
  const issuerEnv = `${prefix}_OAUTH_ISSUER`
  const jwksEnv = `${prefix}_OAUTH_JWKS_URL`
  const ownerEnv = `${prefix}_OWNER_SUBJECT`
  const missing: string[] = []
  const invalid: string[] = []
  const read = (name: string): string => {
    const value = (env[name] ?? '').trim()
    if (value === '') missing.push(name)
    return value
  }
  const issuer = read(issuerEnv)
  const jwks = read(jwksEnv)
  const owner = read(ownerEnv)
  if (issuer !== '' && !isSecureUrl(issuer)) invalid.push(issuerEnv)
  if (jwks !== '' && !isSecureUrl(jwks)) invalid.push(jwksEnv)
  if (missing.length > 0 || invalid.length > 0) {
    return { ok: false, response: configProblem(missing, invalid) }
  }
  return {
    ok: true,
    value: {
      issuer: issuer.replace(/\/+$/, ''),
      jwksUrl: new URL(jwks),
      ownerSubject: owner,
    },
  }
}

// One remote key set per JWKS URL, so keys are fetched once and cached
// across requests (jose refetches on an unknown key ID).
const keySets = new Map<string, ReturnType<typeof createRemoteJWKSet>>()

function keySet(url: URL): ReturnType<typeof createRemoteJWKSet> {
  const existing = keySets.get(url.href)
  if (existing) return existing
  const created = createRemoteJWKSet(url)
  keySets.set(url.href, created)
  return created
}

/** The 401 that starts sign-in (RFC 9728 §5.1). */
function challenge(metadataUrl: string): Response {
  return Response.json(
    {
      error: 'invalid_token',
      error_description: 'a valid bearer access token is required',
    },
    {
      status: 401,
      headers: {
        'WWW-Authenticate': `Bearer resource_metadata="${metadataUrl}"`,
        'cache-control': 'no-store',
      },
    },
  )
}

// jose errors that mean the token itself is bad. Any other failure (the key
// set cannot be fetched or parsed) is the server's problem, not the caller's.
const TOKEN_ERRORS = [
  errors.JWTExpired,
  errors.JWTClaimValidationFailed,
  errors.JWTInvalid,
  errors.JWSInvalid,
  errors.JWSSignatureVerificationFailed,
  errors.JWKSNoMatchingKey,
  errors.JWKSMultipleMatchingKeys,
  errors.JOSEAlgNotAllowed,
  errors.JOSENotSupported,
]

function isTokenError(error: unknown): boolean {
  return TOKEN_ERRORS.some(type => error instanceof type)
}

function bearerToken(request: Request): string | undefined {
  const header = request.headers.get('authorization') ?? ''
  const match = /^Bearer[ ]+([A-Za-z0-9\-._~+/]+=*)[ ]*$/i.exec(header)
  return match?.[1]
}

function authInfo(token: string, payload: JWTPayload, mcpUrl: string): AuthInfo {
  const scope = typeof payload.scope === 'string' ? payload.scope : ''
  const clientId =
    typeof payload.client_id === 'string'
      ? payload.client_id
      : typeof payload.azp === 'string'
        ? payload.azp
        : ''
  return {
    token,
    clientId,
    scopes: scope.split(' ').filter(item => item !== ''),
    expiresAt: payload.exp,
    resource: new URL(mcpUrl),
    extra: { subject: payload.sub },
  }
}

/**
 * Checks the request's bearer token. Resolves to the token's AuthInfo for the
 * owner, else to the response to send: 503 (a setting is missing or unusable,
 * named), 401 (no valid token, with the metadata challenge), 403 (another
 * subject) or 502 (the issuer's keys could not be loaded). Throws for a
 * `prefix` that is not upper case.
 */
export async function authorizeMcpRequest(
  request: Request,
  config: AuthorizeConfig,
): Promise<AuthResult> {
  if (typeof config.prefix !== 'string' || !PREFIX_PATTERN.test(config.prefix)) {
    throw new Error(
      'authorizeMcpRequest: prefix must be upper-case letters, digits and underscores, starting with a letter',
    )
  }
  const settings = readSettings(config.prefix, config.env ?? process.env)
  if (!settings.ok) return settings
  const { issuer, jwksUrl, ownerSubject } = settings.value
  const { mcpUrl, metadataUrl } = resourceUrls(request)

  const token = bearerToken(request)
  if (token === undefined) {
    return { ok: false, response: challenge(metadataUrl) }
  }

  let payload: JWTPayload
  try {
    const getKey: JWTVerifyGetKey = config.keys ?? keySet(jwksUrl)
    ;({ payload } = await jwtVerify(token, getKey, {
      issuer,
      audience: mcpUrl,
      algorithms: ALGORITHMS,
      requiredClaims: ['sub', 'exp'],
    }))
  } catch (error) {
    if (isTokenError(error)) {
      return { ok: false, response: challenge(metadataUrl) }
    }
    // The answer names only the key set URL, which is configuration, never
    // the token or the error text.
    return {
      ok: false,
      response: Response.json(
        {
          error: 'server_error',
          error_description: `could not load the issuer signing keys from ${jwksUrl.href}`,
        },
        { status: 502, headers: { 'cache-control': 'no-store' } },
      ),
    }
  }

  if (payload.sub !== ownerSubject) {
    return {
      ok: false,
      response: Response.json(
        {
          error: 'access_denied',
          error_description: 'this server serves only its owner: sign in with the owner account',
        },
        { status: 403, headers: { 'cache-control': 'no-store' } },
      ),
    }
  }
  return { ok: true, value: authInfo(token, payload, mcpUrl) }
}
