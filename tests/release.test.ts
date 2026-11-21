// REQ-OAUTH-RELEASE: the release tarball holds dist/ so products install it with no build step.
import { execFileSync } from 'node:child_process'
import { describe, expect, it } from 'vitest'
import { assetName, assetUrl, checkPacked, checkTag, REQUIRED_FILES } from '../scripts/release.js'

describe('REQ-OAUTH-RELEASE: release tarball', () => {
  it('REQ-OAUTH-RELEASE: npm pack holds the built dist/ entry and types', () => {
    // --dry-run runs `prepare` (the build) and lists what the tarball would hold.
    const out = execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts=false'], {
      encoding: 'utf8',
    })
    const [{ files }] = JSON.parse(out) as [{ files: { path: string }[] }]
    const listed = files.map(f => `package/${f.path}`)
    expect(() => checkPacked(listed)).not.toThrow()
    expect(listed.some(f => f.endsWith('.test.ts'))).toBe(false)
  }, 120_000)

  it('REQ-OAUTH-RELEASE: a tarball without dist/ is refused, naming the missing files', () => {
    expect(() => checkPacked(['package/package.json'])).toThrow(
      'packed tarball is missing package/dist/index.js, package/dist/index.d.ts',
    )
    expect(REQUIRED_FILES).toContain('package/dist/index.js')
  })

  it('REQ-OAUTH-RELEASE: the tag must be v + the package.json version', () => {
    expect(() => checkTag('v0.1.0', '0.1.0')).not.toThrow()
    expect(() => checkTag('v0.2.0', '0.1.0')).toThrow(
      'tag v0.2.0 does not match package.json version 0.1.0',
    )
    expect(() => checkTag('0.1.0', '0.1.0')).toThrow('want v0.1.0')
  })

  it('REQ-OAUTH-RELEASE: products install from the release asset URL', () => {
    expect(assetName('0.1.0')).toBe('buildproven-mcp-oauth-0.1.0.tgz')
    expect(assetUrl('buildproven/mcp-oauth', '0.1.0')).toBe(
      'https://github.com/buildproven/mcp-oauth/releases/download/v0.1.0/buildproven-mcp-oauth-0.1.0.tgz',
    )
  })
})
