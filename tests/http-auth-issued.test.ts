// REQ-HTTPAUTH-2: the access token the package's own server issues passes the
// resource check, and no other value that server signs does.
import { createLocalJWKSet } from 'jose'
import { describe, expect, it } from 'vitest'
import { authorizeMcpRequest } from '../src/index.js'
import {
  CLAUDE_REDIRECT,
  ISSUER,
  MCP_URL,
  OWNER,
  PREFIX,
  createWorld,
  makeEnv,
  ownerTokens,
  pkce,
  registerClient,
  signIn,
} from './support.js'

describe('REQ-HTTPAUTH-2: tokens issued by createOAuthServer', () => {
  it('REQ-HTTPAUTH-2: accepts the issued access token, and refuses the refresh token, the code and the client ID', async () => {
    const world = createWorld(await makeEnv())
    const { clientId, tokens } = await ownerTokens(world)
    const published = await world.server.jwks(new Request(`${ISSUER}/oauth/jwks`))
    const keys = createLocalJWKSet(
      (await published.json()) as Parameters<typeof createLocalJWKSet>[0],
    )
    const resourceEnv = {
      [`${PREFIX}_OAUTH_ISSUER`]: ISSUER,
      [`${PREFIX}_OAUTH_JWKS_URL`]: `${ISSUER}/oauth/jwks`,
      [`${PREFIX}_OWNER_SUBJECT`]: OWNER,
    }
    const check = (bearer: string) =>
      authorizeMcpRequest(
        new Request(MCP_URL, { headers: { authorization: `Bearer ${bearer}` } }),
        { prefix: PREFIX, env: resourceEnv, keys },
      )

    const accepted = await check(tokens.access_token)
    expect(accepted.ok).toBe(true)
    if (accepted.ok) {
      expect(accepted.value.clientId).toBe(clientId)
      expect(accepted.value.scopes).toEqual(['mcp'])
      expect(accepted.value.extra).toEqual({ subject: OWNER })
      expect(accepted.value.resource?.href).toBe(MCP_URL)
    }

    const refused = await check(tokens.refresh_token)
    expect(refused.ok).toBe(false)
    const { challenge } = pkce()
    const code =
      (await signIn(world, OWNER, await registerClient(world, [CLAUDE_REDIRECT]), challenge))
        .code ?? ''
    expect(code).not.toBe('')
    expect((await check(code)).ok).toBe(false)
    expect((await check(clientId)).ok).toBe(false)
  })
})
