import { assert } from "@std/assert"
import type { NostrEvent, PublicKey, RelayUrl, UnsignedEvent } from "@innis/nostr-core"
import { KIND_NOSTR_CONNECT, now } from "@innis/nostr-core"
import { eventIdFixture, publicKeyFixture, relayUrlFixture, sigFixture } from "@innis/nostr-core/testing"
import { createNip46ClientSigner, type Nip46ClientMetadata } from "../../src/client-signer.ts"
import type { Nip46Permission } from "../../src/permission.ts"
import type { Nip46SubscribeOptions } from "../../src/transport.ts"
import { createCapturingTransport, makeFakeTools } from "./fakes.ts"

export const CLIENT_SK = new Uint8Array(32).fill(1)
export const BUNKER_SK = new Uint8Array(32).fill(2)
export const CLIENT_PK = publicKeyFixture("c".repeat(64))
export const BUNKER_PK = publicKeyFixture("b".repeat(64))
export const USER_PK = publicKeyFixture("f".repeat(64))
export const RELAY = relayUrlFixture("wss://relay.example")

export const pubkeyOf = (sk: Uint8Array): PublicKey => sk[0] === 1 ? CLIENT_PK : BUNKER_PK

let signedCount = 0

export const makeSigned = (base: UnsignedEvent, pubkey: string): NostrEvent => ({
  ...base,
  id: eventIdFixture(`${++signedCount}`.padStart(64, "0")),
  pubkey: publicKeyFixture(pubkey),
  sig: sigFixture("0".repeat(128)),
})

export interface RequestIdBody {
  readonly id: string
}

export const isRequestIdBody = (value: unknown): value is RequestIdBody =>
  typeof value === "object" && value !== null && "id" in value && typeof value.id === "string"

export interface ConnectRequestBody {
  readonly method: string
  readonly params: ReadonlyArray<string>
}

export const isConnectRequestBody = (value: unknown): value is ConnectRequestBody =>
  typeof value === "object" && value !== null &&
  "method" in value && typeof value.method === "string" &&
  "params" in value && Array.isArray(value.params)

export const fakeTools = makeFakeTools(pubkeyOf)

export interface Harness {
  readonly signer: ReturnType<typeof createNip46ClientSigner>
  readonly published: ReadonlyArray<NostrEvent>
  readonly publishedRelays: ReadonlyArray<RelayUrl>
  readonly injectBunkerResponse: (
    requestIndex: number,
    response: { result?: string | null; error?: string | null },
    fromPubkey?: PublicKey,
  ) => NostrEvent
  readonly deliver: (event: NostrEvent) => void
  readonly rejectPublishes: () => void
  readonly breakPublishes: () => void
  readonly subscriptions: ReadonlyArray<Nip46SubscribeOptions>
  readonly activeSubscriptionCount: () => number
  readonly requestAt: (index: number) => ConnectRequestBody
}

export const createHarness = (
  opts: {
    secret?: string | null
    timeoutMs?: number
    initialUserPubkey?: typeof USER_PK | null
    relayUrls?: ReadonlyArray<RelayUrl>
    verifyEventSignature?: (event: NostrEvent) => boolean
    onPubkeyMismatch?: (expected: PublicKey, actual: PublicKey) => void
    onAuthChallenge?: (url: string) => void
    clientMetadata?: Nip46ClientMetadata
    requestedPerms?: ReadonlyArray<Nip46Permission>
  } = {},
): Harness => {
  const {
    transport,
    published,
    publishedRelays,
    deliver,
    rejectPublishes,
    breakPublishes,
    subscriptions,
    activeSubscriptionCount,
  } = createCapturingTransport()

  const signer = createNip46ClientSigner({
    tools: fakeTools,
    transport,
    clientSecretKey: CLIENT_SK,
    remoteSignerPubkey: BUNKER_PK,
    relayUrls: opts.relayUrls ?? [RELAY],
    secret: opts.secret ?? null,
    initialUserPubkey: opts.initialUserPubkey ?? null,
    timeoutMs: opts.timeoutMs ?? 30_000,
    verifyEventSignature: opts.verifyEventSignature ?? ((): boolean => true),
    onPubkeyMismatch: opts.onPubkeyMismatch,
    onAuthChallenge: opts.onAuthChallenge,
    clientMetadata: opts.clientMetadata,
    requestedPerms: opts.requestedPerms,
    generateRequestId: (() => {
      let n = 0
      return () => `req-${++n}`
    })(),
  })

  const injectBunkerResponse = (
    requestIndex: number,
    response: { result?: string | null; error?: string | null },
    fromPubkey: PublicKey = pubkeyOf(BUNKER_SK),
  ): NostrEvent => {
    const requestEvent = published[requestIndex]
    if (!requestEvent) throw new Error(`no request at index ${requestIndex}`)
    const decoded = fakeTools.nip44Decrypt(new Uint8Array(32), requestEvent.content)
    const parsed: unknown = JSON.parse(decoded)
    assert(isRequestIdBody(parsed))
    const responseBody = { id: parsed.id, ...response }
    const responseEnvelope: UnsignedEvent = {
      kind: KIND_NOSTR_CONNECT,
      created_at: now(),
      tags: [["p", CLIENT_PK]],
      content: fakeTools.nip44Encrypt(new Uint8Array(32), JSON.stringify(responseBody)),
    }
    const signed = makeSigned(responseEnvelope, fromPubkey)
    deliver(signed)
    return signed
  }

  const requestAt = (index: number): ConnectRequestBody => {
    const event = published[index]
    if (!event) throw new Error(`no request at index ${index}`)
    const decoded: unknown = JSON.parse(fakeTools.nip44Decrypt(new Uint8Array(32), event.content))
    assert(isConnectRequestBody(decoded))
    return decoded
  }

  return {
    signer,
    published,
    publishedRelays,
    injectBunkerResponse,
    deliver,
    rejectPublishes,
    breakPublishes,
    subscriptions,
    activeSubscriptionCount,
    requestAt,
  }
}
