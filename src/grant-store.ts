/**
 * Records spent codes and refresh tokens and revoked token families, shared
 * by every server instance. `claim` resolves true on the first claim of an ID
 * only; `expiresAt` is seconds since the epoch, and an ID may be claimed again
 * after it. Both methods reject with a `GrantStoreError` when the record cannot
 * be read or written, so the server issues no token instead of guessing.
 */
export interface GrantStore {
  claim(id: string, expiresAt: number): Promise<boolean>
  has(id: string): Promise<boolean>
}

/**
 * A grant store failure. The server logs `message` and answers 503. When
 * `ownerAction` is true the message is a setup step for the owner (for example
 * an app that is not installed) and the 503 reply carries it; otherwise the
 * reply says only that the record is unavailable, because the message may
 * name a private repository.
 */
export class GrantStoreError extends Error {
  override readonly name = 'GrantStoreError'
  readonly ownerAction: boolean

  constructor(message: string, ownerAction = false) {
    super(message)
    this.ownerAction = ownerAction
  }
}

/**
 * Process-local grant store, for tests and single-process embeddings. Server
 * instances that run in parallel or restart need a shared store instead.
 * `now` is milliseconds since the epoch.
 */
export function createMemoryGrantStore(now: () => number = () => Date.now()): GrantStore {
  const spent = new Map<string, number>()
  const prune = (): void => {
    const current = now() / 1000
    for (const [id, expiresAt] of spent) {
      if (expiresAt <= current) spent.delete(id)
    }
  }
  return {
    async has(id) {
      prune()
      return spent.has(id)
    },
    async claim(id, expiresAt) {
      prune()
      if (spent.has(id)) return false
      spent.set(id, expiresAt)
      return true
    },
  }
}
