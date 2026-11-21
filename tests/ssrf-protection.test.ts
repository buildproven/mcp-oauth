// @vitest-environment node
// REQ-OAUTH-2: the SSRF guard that checks client metadata document URLs,
// ported from jobrecon's lib/ssrf-protection.ts and its tests.
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchPinned, pinOf, validateUrl } from '../src/ssrf-protection.js'
import type { DnsResolver, PinnedAddress } from '../src/ssrf-protection.js'

const HOST = 'doc.example.test'
const URL_ = `https://${HOST}/a`

function resolverFor(ip: string): DnsResolver {
  return {
    resolve4: async () => (ip.includes(':') ? [] : [ip]),
    resolve6: async () => (ip.includes(':') ? [ip] : []),
  }
}

describe('REQ-OAUTH-2: validateUrl', () => {
  it.each([
    '127.0.0.2',
    '127.255.255.254',
    '0.1.2.3',
    '100.100.0.1',
    '100.127.255.1',
    '192.0.0.8',
    '198.18.0.1',
    '224.0.0.1',
    '255.255.255.255',
    '::',
    '::1',
    '0:0:0:0:0:0:0:1',
    '::127.0.0.1',
    '::ffff:127.0.0.1',
    '::ffff:8.8.8.8',
    '64:ff9b::a00:1',
    '2002:a00:1::',
    '2001::1',
    'fc12::1',
    'fd12:3456::1',
    'FD00::1',
    'fe90::1',
    'febf::1',
    'fec0::1',
    'ff02::1',
    'fe80::1%en0',
    'not-an-address',
    '1::2::3',
    '1:2:3:4:5:6:7:8:9',
    '256.1.1.1',
    '::ffff:0:7f00:1',
    '::ffff:0:a00:1',
    '::ffff:0:127.0.0.1',
    '::ffff:0:8.8.8.8',
    '0:0:0:0:ffff:0:a9fe:a9fe',
    '::a00:1',
    '::1:2:3',
    '1:2:3:4:5:6:7:8',
    '64:ff9b:1::a00:1',
    '64:ff9b::7f00:1',
  ])('REQ-OAUTH-2: refuses a host whose address %s is not public unicast', async ip => {
    const result = await validateUrl(URL_, undefined, resolverFor(ip))
    expect(result.allowed).toBe(false)
  })

  it.each([
    '93.184.216.34',
    '8.8.8.8',
    '172.32.0.1',
    '100.128.0.1',
    '11.0.0.1',
    '2606:2800:220:1::1',
    '2002:808:808::1',
    '2001:db8:1::1',
    'fe00::1',
    '2001:4860:4860:0:0:0:0:8888',
    '2606:2800:220:1:0:0:5db8:d822',
  ])('REQ-OAUTH-2: allows a host whose address %s is public', async ip => {
    const result = await validateUrl(URL_, undefined, resolverFor(ip))
    expect(result.allowed).toBe(true)
    expect(result.ip).toBe(ip)
  })

  it('REQ-OAUTH-2: uses the injected resolver and reports the allowed address', async () => {
    const seen: string[] = []
    const allowed = await validateUrl(URL_, undefined, {
      async resolve4(host) {
        seen.push(host)
        return ['198.51.100.7']
      },
      async resolve6() {
        return []
      },
    })
    expect(allowed).toEqual({
      allowed: true,
      ip: '198.51.100.7',
      ips: ['198.51.100.7'],
      port: 443,
    })
    expect(seen).toEqual([HOST])
  })

  it('REQ-OAUTH-2: refuses a private address and a failed lookup', async () => {
    const refused = await validateUrl(URL_, undefined, resolverFor('10.0.0.1'))
    expect(refused.allowed).toBe(false)
    expect(refused.error).toContain('10.0.0.1')
    const failing = await validateUrl(URL_, undefined, {
      resolve4: async () => {
        throw new Error('ENOTFOUND')
      },
      resolve6: async () => {
        throw new Error('ENOTFOUND')
      },
    })
    expect(failing).toEqual({ allowed: false, error: 'DNS resolution failed' })
  })

  it('REQ-OAUTH-2: refuses other schemes, other ports, a bad URL and blocked domains', async () => {
    const resolver = resolverFor('93.184.216.34')
    expect((await validateUrl('ftp://doc.example.test/a', undefined, resolver)).error).toBe(
      'Only HTTP/HTTPS URLs are allowed',
    )
    expect(
      (await validateUrl('https://doc.example.test:8443/a', undefined, resolver)).allowed,
    ).toBe(false)
    expect((await validateUrl('not a url', undefined, resolver)).error).toBe('Invalid URL format')
    for (const host of [
      'localhost',
      'metadata.google.internal',
      'x.metadata.google.internal',
      '169.254.169.254',
    ]) {
      const result = await validateUrl(`https://${host}/a`, undefined, resolver)
      expect(result).toEqual({ allowed: false, error: 'Domain is blocked' })
    }
  })

  describe('SSRF_BLOCKED_DOMAINS', () => {
    afterEach(() => {
      vi.unstubAllEnvs()
    })

    it('REQ-OAUTH-2: also blocks the domains the deployment lists, at call time', async () => {
      vi.stubEnv('SSRF_BLOCKED_DOMAINS', ' evil.example.test , other.test ')
      const resolver = resolverFor('93.184.216.34')
      const result = await validateUrl('https://a.evil.example.test/x', undefined, resolver)
      expect(result).toEqual({ allowed: false, error: 'Domain is blocked' })
      expect((await validateUrl(URL_, undefined, resolver)).allowed).toBe(true)
    })

    it('REQ-OAUTH-2: an empty SSRF_BLOCKED_DOMAINS blocks nothing extra', async () => {
      vi.stubEnv('SSRF_BLOCKED_DOMAINS', '')
      const result = await validateUrl('https://a./x', undefined, resolverFor('93.184.216.34'))
      expect(result.error).not.toBe('Domain is blocked')
    })
  })

  it('REQ-OAUTH-2: honours the abort signal with an injected resolver', async () => {
    const controller = new AbortController()
    controller.abort()
    await expect(
      validateUrl(URL_, controller.signal, resolverFor('93.184.216.34')),
    ).rejects.toThrow('aborted')
  })

  it('REQ-OAUTH-2: pinOf gives the family of an address', () => {
    expect(pinOf('1.2.3.4')).toEqual({ address: '1.2.3.4', family: 4 })
    expect(pinOf('::1')).toEqual({ address: '::1', family: 6 })
  })
})

describe('REQ-OAUTH-2: fetchPinned', () => {
  let port: number
  let seenHosts: (string | undefined)[]
  const local = createServer((request, response) => {
    seenHosts.push(request.headers.host)
    if (request.url === '/redirect') {
      response.writeHead(302, { location: 'http://169.254.169.254/' })
      response.end()
      return
    }
    if (request.url === '/large') {
      response.writeHead(200, { 'content-type': 'application/json' })
      response.end('x'.repeat(5000))
      return
    }
    if (request.url === '/empty') {
      response.writeHead(204)
      response.end()
      return
    }
    if (request.url === '/slow') return
    response.writeHead(200, { 'content-type': 'application/json' })
    response.end(JSON.stringify({ accept: request.headers.accept }))
  })

  beforeAll(async () => {
    await new Promise<void>(resolve => local.listen(0, '127.0.0.1', resolve))
    port = (local.address() as AddressInfo).port
  })
  beforeEach(() => {
    seenHosts = []
  })
  afterAll(async () => {
    local.closeAllConnections()
    await new Promise(resolve => local.close(resolve))
  })

  const pin: PinnedAddress = { address: '127.0.0.1', family: 4 }

  it('REQ-OAUTH-2: connects to the pinned address and never resolves the host name', async () => {
    // doc.invalid can never resolve (RFC 6761); only the pin reaches it.
    const response = await fetchPinned(`http://doc.invalid:${port}/client.json`, pin, {
      headers: { accept: 'application/json' },
      maxBytes: 1000,
    })
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ accept: 'application/json' })
    expect(response.headers.get('content-type')).toBe('application/json')
    expect(seenHosts).toEqual([`doc.invalid:${port}`])
  })

  it('REQ-OAUTH-2: does not follow a redirect', async () => {
    const response = await fetchPinned(`http://doc.invalid:${port}/redirect`, pin, {
      maxBytes: 1000,
    })
    expect(response.status).toBe(302)
    expect(seenHosts).toHaveLength(1)
  })

  it('REQ-OAUTH-2: answers an empty 204 with no body', async () => {
    const response = await fetchPinned(`http://doc.invalid:${port}/empty`, pin, {
      maxBytes: 1000,
    })
    expect(response.status).toBe(204)
    expect(await response.text()).toBe('')
  })

  it('REQ-OAUTH-2: rejects a body over the limit, an aborted call and another scheme', async () => {
    await expect(
      fetchPinned(`http://doc.invalid:${port}/large`, pin, { maxBytes: 100 }),
    ).rejects.toThrow('too large')
    const controller = new AbortController()
    const slow = fetchPinned(`http://doc.invalid:${port}/slow`, pin, {
      maxBytes: 100,
      signal: controller.signal,
    })
    setTimeout(() => controller.abort(), 20)
    await expect(slow).rejects.toThrow()
    await expect(fetchPinned('ftp://doc.invalid/x', pin, { maxBytes: 100 })).rejects.toThrow(
      'Only HTTP/HTTPS',
    )
  })
})
