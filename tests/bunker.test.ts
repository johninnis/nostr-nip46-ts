import { assert, assertEquals } from "@std/assert"
import type { NostrEvent, PublicKey, Signer } from "@innis/nostr-core"
import {
  createLocalSigner,
  encryptJson,
  KIND_NOSTR_CONNECT,
  parseEventId,
  parsePublicKey,
  parseRelayUrl,
  parseSig,
} from "@innis/nostr-core"
import type { Nip46Bunker, PendingSignRequest } from "../src/bunker.ts"
import { createNip46Bunker } from "../src/bunker.ts"
import { parseBunkerUrl } from "../src/bunker-url.ts"
import type { Nip46Transport } from "../src/transport.ts"
import { createCapturingTransport, flush, makeFakeTools } from "./helpers.ts"

const BUNKER_SK = new Uint8Array(32).fill(2)
const BUNKER_PK = parsePublicKey("b".repeat(64))
const CLIENT_PK = parsePublicKey("c".repeat(64))
const ATTACKER_PK = parsePublicKey("d".repeat(64))
const USER_PK = parsePublicKey("f".repeat(64))
const RELAY = parseRelayUrl("ws://127.0.0.1:0")

interface BunkerResponseBody {
  readonly id: string
  readonly result?: string
  readonly error?: string
}

const isBunkerResponseBody = (value: unknown): value is BunkerResponseBody =>
  typeof value === "object" && value !== null && "id" in value && typeof value.id === "string"

interface SignedEventBody {
  readonly kind: number
  readonly content: string
}

const isSignedEventBody = (value: unknown): value is SignedEventBody =>
  typeof value === "object" && value !== null &&
  "kind" in value && typeof value.kind === "number" &&
  "content" in value && typeof value.content === "string"

const fakeTools = makeFakeTools(() => BUNKER_PK)

interface Harness {
  readonly bunker: Nip46Bunker
  readonly published: ReadonlyArray<NostrEvent>
  readonly send: (
    clientPubkey: PublicKey,
    body: { id: string; method: string; params?: ReadonlyArray<string> },
    cipher?: "nip04" | "nip44",
  ) => Promise<void>
  readonly deliver: (event: NostrEvent) => void
  readonly lastResponse: () => { id: string; result?: string; error?: string } | null
  readonly lastResponseCipher: () => "nip04" | "nip44" | null
  readonly pending: () => ReadonlyArray<PendingSignRequest>
  readonly stop: () => void
}

const createHarness = (secret: string, now?: () => number): Harness => {
  const { transport, published, deliver } = createCapturingTransport()

  const bunkerSigner: Signer = createLocalSigner(BUNKER_SK, fakeTools)
  const bunker = createNip46Bunker({ transport, signer: bunkerSigner, now })
  bunker.start(USER_PK, [RELAY], secret)

  let nextId = 0

  const send = async (
    clientPubkey: PublicKey,
    body: { id: string; method: string; params?: ReadonlyArray<string> },
    cipher: "nip04" | "nip44" = "nip44",
  ): Promise<void> => {
    const fullBody = { id: body.id, method: body.method, params: body.params ?? [] }
    const json = JSON.stringify(fullBody)
    let content: string
    if (cipher === "nip04") {
      content = await fakeTools.nip04Encrypt(BUNKER_SK, clientPubkey, json)
    } else {
      const result = await encryptJson(bunkerSigner, clientPubkey, fullBody)
      if (!result.success) throw new Error("encrypt failed")
      content = result.value
    }
    const event: NostrEvent = {
      id: parseEventId(`${nextId++}`.padStart(64, "0")),
      pubkey: parsePublicKey(clientPubkey),
      created_at: 1700000000,
      kind: KIND_NOSTR_CONNECT,
      tags: [["p", USER_PK]],
      content,
      sig: parseSig("0".repeat(128)),
    }
    deliver(event)
    await flush()
  }

  const decodeResponse = (event: NostrEvent): { plaintext: string; cipher: "nip04" | "nip44" } | null => {
    if (event.content.startsWith("NIP04:")) return { plaintext: event.content.slice(6), cipher: "nip04" }
    if (event.content.startsWith("ENC:")) {
      return { plaintext: fakeTools.nip44Decrypt(new Uint8Array(32), event.content), cipher: "nip44" }
    }
    return null
  }

  const lastResponse = (): BunkerResponseBody | null => {
    const event = published[published.length - 1]
    if (!event) return null
    const decoded = decodeResponse(event)
    if (!decoded) return null
    const parsed: unknown = JSON.parse(decoded.plaintext)
    assert(isBunkerResponseBody(parsed))
    return parsed
  }

  const lastResponseCipher = (): "nip04" | "nip44" | null => {
    const event = published[published.length - 1]
    if (!event) return null
    return decodeResponse(event)?.cipher ?? null
  }

  return {
    bunker,
    published,
    send,
    deliver,
    lastResponse,
    lastResponseCipher,
    pending: bunker.getPending,
    stop: bunker.stop,
  }
}

Deno.test("bunker - rejects get_public_key from unauthenticated client", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "1", method: "get_public_key" })
    assertEquals(h.lastResponse()?.error, "not connected")
    assertEquals(h.lastResponse()?.result, undefined)
  } finally {
    h.stop()
  }
})

Deno.test("bunker - rejects nip44_encrypt from unauthenticated client", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "2", method: "nip44_encrypt", params: [USER_PK, "hi"] })
    assertEquals(h.lastResponse()?.error, "not connected")
  } finally {
    h.stop()
  }
})

Deno.test("bunker - rejects sign_event from unauthenticated client", async () => {
  const h = createHarness("supersecret")
  try {
    const eventToSign = JSON.stringify({ kind: 1, content: "hi" })
    await h.send(CLIENT_PK, { id: "3", method: "sign_event", params: [eventToSign] })
    assertEquals(h.lastResponse()?.error, "not connected")
  } finally {
    h.stop()
  }
})

Deno.test("bunker - allows ping from unauthenticated client", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "4", method: "ping" })
    assertEquals(h.lastResponse()?.result, "pong")
  } finally {
    h.stop()
  }
})

Deno.test("bunker - connect with wrong secret leaves client unauthenticated", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "5", method: "connect", params: [USER_PK, "wrong"] })
    assertEquals(h.lastResponse()?.error, "invalid secret")
    await h.send(CLIENT_PK, { id: "6", method: "get_public_key" })
    assertEquals(h.lastResponse()?.error, "not connected")
  } finally {
    h.stop()
  }
})

Deno.test("bunker - connect targeting a different signer pubkey is rejected", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "5b", method: "connect", params: [BUNKER_PK, "supersecret"] })
    assertEquals(h.lastResponse()?.error, "invalid signer")
    await h.send(CLIENT_PK, { id: "5c", method: "get_public_key" })
    assertEquals(h.lastResponse()?.error, "not connected")
  } finally {
    h.stop()
  }
})

Deno.test("bunker - connect with correct secret authenticates client for subsequent calls", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "7", method: "connect", params: [USER_PK, "supersecret"] })
    assertEquals(h.lastResponse()?.result, "ack")
    await h.send(CLIENT_PK, { id: "8", method: "get_public_key" })
    assertEquals(h.lastResponse()?.result, USER_PK)
  } finally {
    h.stop()
  }
})

Deno.test("bunker - authenticating one client does not authenticate another", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "9", method: "connect", params: [USER_PK, "supersecret"] })
    assertEquals(h.lastResponse()?.result, "ack")
    await h.send(ATTACKER_PK, { id: "10", method: "get_public_key" })
    assertEquals(h.lastResponse()?.error, "not connected")
  } finally {
    h.stop()
  }
})

Deno.test("bunker - silently drops requests whose envelope decrypts as neither nip44 nor nip04", async () => {
  const h = createHarness("supersecret")
  try {
    const event: NostrEvent = {
      id: parseEventId("a".repeat(64)),
      pubkey: CLIENT_PK,
      created_at: 1700000000,
      kind: KIND_NOSTR_CONNECT,
      tags: [["p", USER_PK]],
      content: "garbage-ciphertext-matching-neither-cipher",
      sig: parseSig("0".repeat(128)),
    }
    h.deliver(event)
    await new Promise((resolve) => setTimeout(resolve, 0))

    assertEquals(h.lastResponse(), null)
    assertEquals(h.pending().length, 0)
  } finally {
    h.stop()
  }
})

Deno.test("bunker - decrypts nip04-encrypted envelopes and replies in nip04", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "16", method: "connect", params: [USER_PK, "supersecret"] }, "nip04")
    assertEquals(h.lastResponse()?.result, "ack")
    assertEquals(h.lastResponseCipher(), "nip04")
    await h.send(CLIENT_PK, { id: "17", method: "get_public_key" }, "nip04")
    assertEquals(h.lastResponse()?.result, USER_PK)
    assertEquals(h.lastResponseCipher(), "nip04")
  } finally {
    h.stop()
  }
})

Deno.test("bunker - nip04 client cipher does not bleed into nip44 client responses", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "18", method: "connect", params: [USER_PK, "supersecret"] }, "nip04")
    assertEquals(h.lastResponseCipher(), "nip04")
    await h.send(ATTACKER_PK, { id: "19", method: "ping" }, "nip44")
    assertEquals(h.lastResponse()?.result, "pong")
    assertEquals(h.lastResponseCipher(), "nip44")
  } finally {
    h.stop()
  }
})

Deno.test("bunker - sign_event approval replies in the cipher the client used", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "20", method: "connect", params: [USER_PK, "supersecret"] }, "nip04")
    const eventToSign = JSON.stringify({ kind: 1, content: "from old client" })
    await h.send(CLIENT_PK, { id: "21", method: "sign_event", params: [eventToSign] }, "nip04")
    assertEquals(h.pending().length, 1)
    const pendingId = h.pending()[0]?.id
    if (!pendingId) throw new Error("expected pending request")
    await h.bunker.approve(pendingId)
    await new Promise((resolve) => setTimeout(resolve, 0))
    assertEquals(h.lastResponseCipher(), "nip04")
    const response = h.lastResponse()
    if (!response?.result) throw new Error("expected signed event in response")
    const signed: unknown = JSON.parse(response.result)
    assert(isSignedEventBody(signed))
    assertEquals(signed.kind, 1)
    assertEquals(signed.content, "from old client")
  } finally {
    h.stop()
  }
})

Deno.test("bunker - nip04_encrypt round-trips through the signer once authenticated", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "11", method: "connect", params: [USER_PK, "supersecret"] })
    assertEquals(h.lastResponse()?.result, "ack")
    await h.send(CLIENT_PK, { id: "12", method: "nip04_encrypt", params: [USER_PK, "hello"] })
    assertEquals(h.lastResponse()?.result, "NIP04:hello")
  } finally {
    h.stop()
  }
})

Deno.test("bunker - nip04_decrypt round-trips through the signer once authenticated", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "13", method: "connect", params: [USER_PK, "supersecret"] })
    assertEquals(h.lastResponse()?.result, "ack")
    await h.send(CLIENT_PK, { id: "14", method: "nip04_decrypt", params: [USER_PK, "NIP04:hello"] })
    assertEquals(h.lastResponse()?.result, "hello")
  } finally {
    h.stop()
  }
})

Deno.test("bunker - rejects nip04_encrypt from unauthenticated client", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "15", method: "nip04_encrypt", params: [USER_PK, "hi"] })
    assertEquals(h.lastResponse()?.error, "not connected")
  } finally {
    h.stop()
  }
})

Deno.test("bunker - start with an empty secret is a no-op and emits no URL", () => {
  const transport: Nip46Transport = {
    subscribe: () => ({ abort: () => {} }),
    publish: () => Promise.resolve(),
  }
  const bunker = createNip46Bunker({ transport, signer: createLocalSigner(BUNKER_SK, fakeTools) })

  bunker.start(USER_PK, [RELAY], "")
  assertEquals(bunker.getBunkerUrl(), null)
  bunker.stop()
})

Deno.test("bunker - URL-encodes the secret in getBunkerUrl", () => {
  const transport: Nip46Transport = {
    subscribe: () => ({ abort: () => {} }),
    publish: () => Promise.resolve(),
  }
  const bunkerSigner = createLocalSigner(BUNKER_SK, fakeTools)
  const bunker = createNip46Bunker({ transport, signer: bunkerSigner })

  bunker.start(USER_PK, [RELAY], "secret with spaces & symbols=#")
  const url = bunker.getBunkerUrl()
  bunker.stop()

  assertEquals(typeof url, "string")
  const parsed = parseBunkerUrl(url ?? "")
  assertEquals(parsed?.secret, "secret with spaces & symbols=#")
})

const SIGN_EVENT = JSON.stringify({ kind: 1, content: "hi" })

Deno.test("bunker - reject removes the pending request and replies user rejected", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "r1", method: "connect", params: [USER_PK, "supersecret"] })
    await h.send(CLIENT_PK, { id: "r2", method: "sign_event", params: [SIGN_EVENT] })
    assertEquals(h.pending().length, 1)
    const pendingId = h.pending()[0]?.id
    if (!pendingId) throw new Error("expected pending request")
    await h.bunker.reject(pendingId)
    await flush()
    assertEquals(h.pending().length, 0)
    assertEquals(h.lastResponse()?.error, "user rejected")
  } finally {
    h.stop()
  }
})

Deno.test("bunker - onUpdate fires when a request is queued and resolved, and stops after unsubscribe", async () => {
  const h = createHarness("supersecret")
  let updates = 0
  const unsubscribe = h.bunker.onUpdate(() => updates++)
  try {
    await h.send(CLIENT_PK, { id: "u1", method: "connect", params: [USER_PK, "supersecret"] })
    await h.send(CLIENT_PK, { id: "u2", method: "sign_event", params: [SIGN_EVENT] })
    assertEquals(updates, 1)
    const pendingId = h.pending()[0]?.id
    if (!pendingId) throw new Error("expected pending request")
    await h.bunker.reject(pendingId)
    assertEquals(updates, 2)
    unsubscribe()
    await h.send(CLIENT_PK, { id: "u3", method: "sign_event", params: [SIGN_EVENT] })
    assertEquals(updates, 2)
  } finally {
    h.stop()
  }
})

Deno.test("bunker - getPending returns the most recently received request first", async () => {
  let clock = 1000
  const h = createHarness("supersecret", () => clock)
  try {
    await h.send(CLIENT_PK, { id: "p0", method: "connect", params: [USER_PK, "supersecret"] })
    clock = 2000
    await h.send(CLIENT_PK, { id: "p1", method: "sign_event", params: [JSON.stringify({ kind: 1, content: "first" })] })
    clock = 3000
    await h.send(CLIENT_PK, {
      id: "p2",
      method: "sign_event",
      params: [JSON.stringify({ kind: 1, content: "second" })],
    })
    assertEquals(h.pending().map((p) => p.id), ["p2", "p1"])
  } finally {
    h.stop()
  }
})

Deno.test("bunker - rejects unsupported methods once authenticated", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "e1", method: "connect", params: [USER_PK, "supersecret"] })
    await h.send(CLIENT_PK, { id: "e2", method: "describe" })
    assertEquals(h.lastResponse()?.error, "unsupported method: describe")
  } finally {
    h.stop()
  }
})

Deno.test("bunker - rejects crypto calls whose target pubkey is invalid", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "e3", method: "connect", params: [USER_PK, "supersecret"] })
    await h.send(CLIENT_PK, { id: "e4", method: "nip44_encrypt", params: ["not-a-pubkey", "hi"] })
    assertEquals(h.lastResponse()?.error, "invalid params")
  } finally {
    h.stop()
  }
})

Deno.test("bunker - sign_event with no event param replies missing event", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "e5", method: "connect", params: [USER_PK, "supersecret"] })
    await h.send(CLIENT_PK, { id: "e6", method: "sign_event", params: [] })
    assertEquals(h.lastResponse()?.error, "missing event")
    assertEquals(h.pending().length, 0)
  } finally {
    h.stop()
  }
})

Deno.test("bunker - sign_event with malformed event JSON replies invalid event", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "e7", method: "connect", params: [USER_PK, "supersecret"] })
    await h.send(CLIENT_PK, { id: "e8", method: "sign_event", params: ["{ not json"] })
    assertEquals(h.lastResponse()?.error, "invalid event")
    assertEquals(h.pending().length, 0)
  } finally {
    h.stop()
  }
})
