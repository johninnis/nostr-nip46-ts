import { assert } from "@std/assert"
import type { NostrEvent, PublicKey, RelayUrl, Signer } from "@innis/nostr-core"
import { createJsonCipher, createLocalSigner, KIND_NOSTR_CONNECT } from "@innis/nostr-core"
import { eventIdFixture, publicKeyFixture, relayUrlFixture, sigFixture } from "@innis/nostr-core/testing"
import type { Nip46Bunker } from "../../src/bunker.ts"
import { createNip46Bunker } from "../../src/bunker.ts"
import type { Nip46Permission, PendingRequest } from "../../src/pending-request.ts"
import type { Nip46SubscribeOptions } from "../../src/transport.ts"
import { createCapturingTransport, flush, makeFakeTools } from "./fakes.ts"

export const BUNKER_SK = new Uint8Array(32).fill(2)
export const BUNKER_PK = publicKeyFixture("b".repeat(64))
export const CLIENT_PK = publicKeyFixture("c".repeat(64))
export const ATTACKER_PK = publicKeyFixture("d".repeat(64))
export const USER_PK = publicKeyFixture("f".repeat(64))
export const RELAY = relayUrlFixture("wss://relay.example")

export interface BunkerResponseBody {
  readonly id: string
  readonly result?: string
  readonly error?: string
}

export const isBunkerResponseBody = (value: unknown): value is BunkerResponseBody =>
  typeof value === "object" && value !== null && "id" in value && typeof value.id === "string"

export interface SignedEventBody {
  readonly kind: number
  readonly content: string
}

export const isSignedEventBody = (value: unknown): value is SignedEventBody =>
  typeof value === "object" && value !== null &&
  "kind" in value && typeof value.kind === "number" &&
  "content" in value && typeof value.content === "string"

export const fakeTools = makeFakeTools(() => BUNKER_PK)

export const grantAllButSigning = (_client: PublicKey, permission: Nip46Permission): boolean =>
  !permission.startsWith("sign_event")

export interface RequestBody {
  readonly id: string
  readonly method: string
  readonly params?: ReadonlyArray<string | { readonly [field: string]: string | number }> | null
}

export interface HarnessOptions {
  readonly now?: () => number
  readonly signer?: Signer
  readonly isAuthorised?: (client: PublicKey, permission: Nip46Permission) => boolean
  readonly onSecretUsed?: (secret: string, clientPubkey: PublicKey) => void
}

export interface Harness {
  readonly bunker: Nip46Bunker
  readonly published: ReadonlyArray<NostrEvent>
  readonly publishedRelays: ReadonlyArray<RelayUrl>
  readonly subscriptions: ReadonlyArray<Nip46SubscribeOptions>
  readonly activeSubscriptionCount: () => number
  readonly envelope: (clientPubkey: PublicKey, body: RequestBody, cipher?: "nip04" | "nip44") => Promise<NostrEvent>
  readonly send: (clientPubkey: PublicKey, body: RequestBody, cipher?: "nip04" | "nip44") => Promise<void>
  readonly deliver: (event: NostrEvent) => void
  readonly responseAt: (index: number) => BunkerResponseBody | null
  readonly lastResponse: () => BunkerResponseBody | null
  readonly lastResponseCipher: () => "nip04" | "nip44" | null
  readonly pending: () => ReadonlyArray<PendingRequest>
  readonly rejectPublishes: () => void
  readonly breakPublishes: () => void
  readonly stop: () => void
}

const decodeResponse = (event: NostrEvent): { plaintext: string; cipher: "nip04" | "nip44" } | null => {
  if (event.content.startsWith("NIP04:")) {
    return { plaintext: fakeTools.nip04Decrypt(new Uint8Array(32), CLIENT_PK, event.content), cipher: "nip04" }
  }
  if (event.content.startsWith("ENC:")) {
    return { plaintext: fakeTools.nip44Decrypt(new Uint8Array(32), event.content), cipher: "nip44" }
  }
  return null
}

export const createHarness = (secret: string, options: HarnessOptions = {}): Harness => {
  const capturing = createCapturingTransport()
  const bunkerSigner = options.signer ?? createLocalSigner(BUNKER_SK, fakeTools)

  const bunker = createNip46Bunker({
    transport: capturing.transport,
    signer: bunkerSigner,
    isAuthorised: options.isAuthorised ?? grantAllButSigning,
    now: options.now,
    onSecretUsed: options.onSecretUsed,
  })
  bunker.start(USER_PK, [RELAY], secret)

  let nextId = 0

  const envelope = async (
    clientPubkey: PublicKey,
    body: RequestBody,
    cipher: "nip04" | "nip44" = "nip44",
  ): Promise<NostrEvent> => {
    const fullBody = { id: body.id, method: body.method, params: body.params === undefined ? [] : body.params }
    const json = JSON.stringify(fullBody)
    let content: string
    if (cipher === "nip04") {
      content = await fakeTools.nip04Encrypt(BUNKER_SK, clientPubkey, json)
    } else {
      const result = await createJsonCipher(createLocalSigner(BUNKER_SK, fakeTools)).encrypt(clientPubkey, fullBody)
      if (!result.success) throw new Error("encrypt failed")
      content = result.value
    }
    return {
      id: eventIdFixture(`${nextId++}`.padStart(64, "0")),
      pubkey: publicKeyFixture(clientPubkey),
      created_at: 1700000000,
      kind: KIND_NOSTR_CONNECT,
      tags: [["p", USER_PK]],
      content,
      sig: sigFixture("0".repeat(128)),
    }
  }

  const send = async (clientPubkey: PublicKey, body: RequestBody, cipher?: "nip04" | "nip44"): Promise<void> => {
    capturing.deliver(await envelope(clientPubkey, body, cipher))
    await flush()
  }

  const responseAt = (index: number): BunkerResponseBody | null => {
    const event = capturing.published[index]
    if (!event) return null
    const decoded = decodeResponse(event)
    if (!decoded) return null
    const parsed: unknown = JSON.parse(decoded.plaintext)
    assert(isBunkerResponseBody(parsed))
    return parsed
  }

  const lastResponseCipher = (): "nip04" | "nip44" | null => {
    const event = capturing.published[capturing.published.length - 1]
    if (!event) return null
    return decodeResponse(event)?.cipher ?? null
  }

  return {
    bunker,
    published: capturing.published,
    publishedRelays: capturing.publishedRelays,
    subscriptions: capturing.subscriptions,
    activeSubscriptionCount: capturing.activeSubscriptionCount,
    envelope,
    send,
    deliver: capturing.deliver,
    responseAt,
    lastResponse: () => responseAt(capturing.published.length - 1),
    lastResponseCipher,
    pending: bunker.getPending,
    rejectPublishes: capturing.rejectPublishes,
    breakPublishes: capturing.breakPublishes,
    stop: bunker.stop,
  }
}
