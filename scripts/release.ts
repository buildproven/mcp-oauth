// REQ-OAUTH-RELEASE: each version tag publishes the built package as a GitHub release asset, so products install a
// tarball that already holds dist/ and run no install script (pnpm 11 refuses a git dependency's `prepare`).
// Run by .github/workflows/release.yml: `pack <tag>` in a read-only job, then `publish <tag> <file>` in a job that
// has write access and runs no dependency code (GITHUB_TOKEN and GITHUB_REPOSITORY set).
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { basename } from 'node:path'

/** The file name `npm pack` gives this package at `version`. */
export function assetName(version: string): string {
  return `buildproven-mcp-oauth-${version}.tgz`
}

/** The URL products put in package.json for `version`. */
export function assetUrl(repository: string, version: string): string {
  return `https://github.com/${repository}/releases/download/v${version}/${assetName(version)}`
}

/** Throws unless `tag` is `v` + the package.json version: a release never ships a tarball under another version. */
export function checkTag(tag: string, version: string): void {
  if (tag !== `v${version}`)
    throw new Error(`tag ${tag} does not match package.json version ${version} (want v${version})`)
}

/** The files a packed tarball must hold for an install with no build step. */
export const REQUIRED_FILES = [
  'package/dist/index.js',
  'package/dist/index.d.ts',
  'package/package.json',
]

/** Throws naming each required file missing from a tarball's file list. */
export function checkPacked(files: string[]): void {
  const missing = REQUIRED_FILES.filter(f => !files.includes(f))
  if (missing.length) throw new Error(`packed tarball is missing ${missing.join(', ')}`)
}

async function github(url: string, token: string, init: RequestInit = {}): Promise<Response> {
  return fetch(url, {
    ...init,
    headers: {
      authorization: `Bearer ${token}`,
      accept: 'application/vnd.github+json',
      ...init.headers,
    },
  })
}

/** Pack the checked-out tag (run in the package folder, read-only job): returns the checked tarball path. */
function pack(tag: string): string {
  const { version } = JSON.parse(readFileSync('package.json', 'utf8')) as { version: string }
  checkTag(tag, version)
  const file =
    execFileSync('npm', ['pack', '--silent'], { encoding: 'utf8' }).trim().split('\n').at(-1) ?? ''
  if (basename(file) !== assetName(version))
    throw new Error(`npm pack wrote ${file}, expected ${assetName(version)}`)
  checkPacked(execFileSync('tar', ['tzf', file], { encoding: 'utf8' }).trim().split('\n'))
  return file
}

/** Attach a packed tarball to the tag's release (write job: runs no dependency code). */
async function publish(tag: string, file: string): Promise<void> {
  const token = process.env.GITHUB_TOKEN
  const repository = process.env.GITHUB_REPOSITORY
  if (!token || !repository) throw new Error('GITHUB_TOKEN and GITHUB_REPOSITORY must be set')
  const version = tag.replace(/^v/, '')
  checkTag(tag, version)
  if (basename(file) !== assetName(version))
    throw new Error(`${file} is not ${assetName(version)} for tag ${tag}`)
  checkPacked(execFileSync('tar', ['tzf', file], { encoding: 'utf8' }).trim().split('\n'))

  const api = `https://api.github.com/repos/${repository}`
  let res = await github(`${api}/releases/tags/${tag}`, token)
  if (res.status === 404)
    res = await github(`${api}/releases`, token, {
      method: 'POST',
      body: JSON.stringify({ tag_name: tag, name: tag, generate_release_notes: true }),
    })
  if (!res.ok) throw new Error(`release ${tag}: GitHub answered ${res.status} ${await res.text()}`)
  const release = (await res.json()) as { upload_url: string; assets: { name: string }[] }
  // A published tarball never changes: products pin its URL.
  if (release.assets.some(a => a.name === assetName(version)))
    throw new Error(
      `release ${tag} already has ${assetName(version)}; publish a new version instead`,
    )

  const upload = release.upload_url.replace(/\{.*\}$/, `?name=${assetName(version)}`)
  const up = await github(upload, token, {
    method: 'POST',
    headers: { 'content-type': 'application/gzip' },
    body: readFileSync(file),
  })
  if (!up.ok)
    throw new Error(`upload ${assetName(version)}: GitHub answered ${up.status} ${await up.text()}`)
  console.log(`published ${assetUrl(repository, version)}`)
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const [mode, tag, file] = process.argv.slice(2)
  if (mode === 'pack' && tag) console.log(pack(tag))
  else if (mode === 'publish' && tag && file) await publish(tag, file)
  else throw new Error('usage: node scripts/release.ts pack <tag> | publish <tag> <file>')
}
