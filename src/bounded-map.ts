export interface BoundedMap<V> {
  readonly has: (key: string) => boolean
  readonly get: (key: string) => V | undefined
  readonly set: (key: string, value: V) => void
  readonly forget: (key: string) => void
}

export const createBoundedMap = <V>(limit: number): BoundedMap<V> => {
  const entries = new Map<string, V>()
  return Object.freeze({
    has: (key: string): boolean => entries.has(key),
    get: (key: string): V | undefined => entries.get(key),
    set: (key: string, value: V): void => {
      entries.set(key, value)
      if (entries.size <= limit) return
      const oldest = entries.keys().next()
      if (!oldest.done) entries.delete(oldest.value)
    },
    forget: (key: string): void => {
      entries.delete(key)
    },
  })
}

export const SEEN_EVENT_LIMIT = 10_000

export interface SeenEventIds {
  readonly remember: (eventId: string) => boolean
}

export const createSeenEventIds = (limit: number = SEEN_EVENT_LIMIT): SeenEventIds => {
  const ids = createBoundedMap<true>(limit)
  return Object.freeze({
    remember: (eventId: string): boolean => {
      if (ids.has(eventId)) return false
      ids.set(eventId, true)
      return true
    },
  })
}
