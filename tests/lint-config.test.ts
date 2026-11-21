import { readFileSync } from 'node:fs'
import { ESLint } from 'eslint'
import { describe, expect, it } from 'vitest'

describe('lint and format config', () => {
  it('eslint skips the built dist folder', async () => {
    const eslint = new ESLint({ cwd: new URL('..', import.meta.url).pathname })
    expect(await eslint.isPathIgnored('dist/index.js')).toBe(true)
    expect(await eslint.isPathIgnored('src/index.ts')).toBe(false)
  })

  it('prettier skips the built dist folder', () => {
    const ignore = readFileSync(new URL('../.prettierignore', import.meta.url), 'utf8').split('\n')
    expect(ignore).toContain('dist/')
  })
})
