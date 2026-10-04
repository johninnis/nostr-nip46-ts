import type { LocalSignerTools, NostrEvent, NostrFilter, PublicKey, RelayUrl } from "@innis/nostr-core"
import { Nip04CryptoError, Nip44CryptoError } from "@innis/nostr-core"
import { sigFixture } from "@innis/nostr-core/testing"
import type { Nip46SubscribeOptions, Nip46SubscriptionStatus, Nip46Transport } from "../../src/transport.ts"

export const makeFakeTools = (getPublicKey: (secretKey: Uint8Array) => PublicKey): LocalSignerTools => ({
  getPublicKey,
  schnorrSign: () => sigFixture("0".repeat(128)),
  getNip44ConversationKey: () => new Uint8Array(32),
  nip44Encrypt: (_ck, plaintext) => "ENC:" + btoa(String.fromCharCode(...new TextEncoder().encode(plaintext))),
  nip44Decrypt: (_ck, payload) => {
    if (!payload.startsWith("ENC:")) throw new Nip44CryptoError("not encrypted")
    return new TextDecoder().decode(Uint8Array.from(atob(payload.slice(4)), (char) => char.charCodeAt(0)))
  },
  nip04Encrypt: (_sk, _peer, plaintext) => `NIP04:${plaintext}?iv=AAAA`,
  nip04Decrypt: (_sk, _peer, ciphertext) => {
    if (!ciphertext.startsWith("NIP04:") || !ciphertext.endsWith("?iv=AAAA")) {
      throw new Nip04CryptoError("NIP-04 decryption failed")
    }
    return ciphertext.slice(6, -"?iv=AAAA".length)
  },
})

export interface CapturingTransport {
  readonly transport: Nip46Transport
  readonly published: ReadonlyArray<NostrEvent>
  readonly publishedRelays: ReadonlyArray<RelayUrl>
  readonly subscriptions: ReadonlyArray<Nip46SubscribeOptions>
  readonly activeSubscriptionCount: () => number
  readonly deliver: (event: NostrEvent) => void
  readonly emitStatus: (status: Nip46SubscriptionStatus) => void
  /** Makes every subsequent publish report the relay rejecting the event. */
  readonly rejectPublishes: () => void
  /** Makes every subsequent publish reject its promise, as a broken transport would. */
  readonly breakPublishes: () => void
}

export const createCapturingTransport = (): CapturingTransport => {
  const published: Array<NostrEvent> = []
  const publishedRelays: Array<RelayUrl> = []
  const subscriptions: Array<Nip46SubscribeOptions> = []
  let publishOk = true
  let publishBroken = false
  const handlers: Array<(event: NostrEvent) => void> = []
  const statusHandlers: Array<(status: Nip46SubscriptionStatus) => void> = []

  const transport: Nip46Transport = {
    subscribe: (options) => {
      const { onEvent, onStatus } = options
      subscriptions.push(options)
      handlers.push(onEvent)
      if (onStatus) statusHandlers.push(onStatus)
      return {
        abort: () => {
          const i = handlers.indexOf(onEvent)
          if (i >= 0) handlers.splice(i, 1)
          if (onStatus) {
            const s = statusHandlers.indexOf(onStatus)
            if (s >= 0) statusHandlers.splice(s, 1)
          }
        },
      }
    },
    publish: (url, event) => {
      if (publishBroken) return Promise.reject(new Error("socket torn down mid-write"))
      published.push(event)
      publishedRelays.push(url)
      return Promise.resolve({ ok: publishOk })
    },
  }

  return {
    transport,
    published,
    publishedRelays,
    subscriptions,
    activeSubscriptionCount: () => handlers.length,
    deliver: (event) => {
      for (const handler of [...handlers]) handler(event)
    },
    emitStatus: (status) => {
      for (const handler of statusHandlers) handler(status)
    },
    rejectPublishes: () => {
      publishOk = false
    },
    breakPublishes: () => {
      publishBroken = true
    },
  }
}

const matchesFilter = (filter: NostrFilter, event: NostrEvent): boolean => {
  const addressees: ReadonlyArray<string> = filter["#p"] ?? []
  const addressed = event.tags.some((tag) => tag[0] === "p" && addressees.includes(tag[1] ?? ""))
  const authored = filter.authors === undefined || filter.authors.includes(event.pubkey)
  return addressed && authored
}

/** A transport that hands every published event to each open subscription whose filter it matches, as a relay would. */
export const createLoopbackTransport = (): Nip46Transport => {
  const open = new Set<Nip46SubscribeOptions>()
  return {
    subscribe: (options) => {
      open.add(options)
      return { abort: () => open.delete(options) }
    },
    publish: (_url, event) => {
      for (const options of [...open]) {
        if (matchesFilter(options.filter, event)) queueMicrotask(() => options.onEvent(event))
      }
      return Promise.resolve({ ok: true })
    },
  }
}

const eventLoopTurn = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0))

export const flush = async (): Promise<void> => {
  for (let i = 0; i < 10; i++) await eventLoopTurn()
}
