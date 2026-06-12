import type { LocalSignerTools, NostrEvent, PublicKey, RelayUrl } from "@innis/nostr-core"
import { parseSig } from "@innis/nostr-core"
import type { Nip46Transport } from "../../src/transport.ts"

export const makeFakeTools = (getPublicKey: (secretKey: Uint8Array) => PublicKey): LocalSignerTools => ({
  getPublicKey,
  schnorrSign: () => parseSig("0".repeat(128)),
  getNip44ConversationKey: () => new Uint8Array(32),
  nip44Encrypt: (_ck, plaintext) => "ENC:" + plaintext,
  nip44Decrypt: (_ck, payload) => {
    if (!payload.startsWith("ENC:")) throw new Error("not encrypted")
    return payload.slice(4)
  },
  nip04Encrypt: (_sk, _peer, plaintext) => Promise.resolve("NIP04:" + plaintext),
  nip04Decrypt: (_sk, _peer, ciphertext) => {
    if (!ciphertext.startsWith("NIP04:")) return Promise.reject(new Error("not nip04"))
    return Promise.resolve(ciphertext.slice(6))
  },
})

export interface CapturingTransport {
  readonly transport: Nip46Transport
  readonly published: ReadonlyArray<NostrEvent>
  readonly publishedRelays: ReadonlyArray<RelayUrl>
  readonly deliver: (event: NostrEvent) => void
}

export const createCapturingTransport = (): CapturingTransport => {
  const published: Array<NostrEvent> = []
  const publishedRelays: Array<RelayUrl> = []
  const handlers: Array<(event: NostrEvent) => void> = []

  const transport: Nip46Transport = {
    subscribe: ({ onEvent }) => {
      handlers.push(onEvent)
      return {
        abort: () => {
          const i = handlers.indexOf(onEvent)
          if (i >= 0) handlers.splice(i, 1)
        },
      }
    },
    publish: (url, event) => {
      published.push(event)
      publishedRelays.push(url)
      return Promise.resolve()
    },
  }

  return {
    transport,
    published,
    publishedRelays,
    deliver: (event) => {
      for (const handler of handlers) handler(event)
    },
  }
}

const eventLoopTurn = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0))

export const flush = async (): Promise<void> => {
  for (let i = 0; i < 10; i++) await eventLoopTurn()
}
