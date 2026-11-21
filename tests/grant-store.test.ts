// REQ-OAUTH-2: the memory grant store (single use through `claim`).
import { describe, expect, it } from 'vitest'
import { GrantStoreError, createMemoryGrantStore } from '../src/index.js'

describe('REQ-OAUTH-2: createMemoryGrantStore', () => {
  it('REQ-OAUTH-2: claim succeeds once per ID and has sees the claim', async () => {
    const store = createMemoryGrantStore(() => 1_000_000)
    expect(await store.has('a')).toBe(false)
    expect(await store.claim('a', 2_000)).toBe(true)
    expect(await store.claim('a', 2_000)).toBe(false)
    expect(await store.has('a')).toBe(true)
    expect(await store.claim('b', 2_000)).toBe(true)
  })

  it('REQ-OAUTH-2: an ID is claimable again once its expiry has passed', async () => {
    let now = 1_000_000
    const store = createMemoryGrantStore(() => now)
    expect(await store.claim('a', 1_100)).toBe(true)
    now = 1_100_000
    expect(await store.has('a')).toBe(false)
    expect(await store.claim('a', 1_200)).toBe(true)
  })

  it('REQ-OAUTH-2: two concurrent claims of one ID give one winner', async () => {
    const store = createMemoryGrantStore(() => 0)
    const results = await Promise.all([store.claim('a', 9), store.claim('a', 9)])
    expect(results.filter(Boolean)).toHaveLength(1)
  })

  it('REQ-OAUTH-2: GrantStoreError carries the owner-action flag', () => {
    expect(new GrantStoreError('x').ownerAction).toBe(false)
    expect(new GrantStoreError('x', true).ownerAction).toBe(true)
    expect(new GrantStoreError('x').name).toBe('GrantStoreError')
  })
})
