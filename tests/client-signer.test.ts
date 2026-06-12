import { assert, assertEquals, assertRejects } from "@std/assert"
import type { NostrEvent, PublicKey, RelayUrl, UnsignedEvent } from "@innis/nostr-core"
import {
  KIND_NOSTR_CONNECT,
  now,
  parseEventId,
  parsePublicKey,
  parseRelayUrl,
  parseSig,
  PubkeyMismatchError,
  SigningError,
} from "@innis/nostr-core"
import { createNip46ClientSigner } from "../src/client-signer.ts"
import { createCapturingTransport, flush, makeFakeTools } from "./helpers.ts"

const CLIENT_SK = new Uint8Array(32).fill(1)
const BUNKER_SK = new Uint8Array(32).fill(2)
const CLIENT_PK = parsePublicKey("c".repeat(64))
const BUNKER_PK = parsePublicKey("b".repeat(64))
const USER_PK = parsePublicKey("f".repeat(64))
const RELAY = parseRelayUrl("ws://127.0.0.1:0")

const pubkeyOf = (sk: Uint8Array): PublicKey => sk[0] === 1 ? CLIENT_PK : BUNKER_PK

const makeSigned = (base: UnsignedEvent, pubkey: string): NostrEvent => ({
  ...base,
  id: parseEventId("0".repeat(64)),
  pubkey: parsePublicKey(pubkey),
  sig: parseSig("0".repeat(128)),
})

interface RequestIdBody {
  readonly id: string
}

const isRequestIdBody = (value: unknown): value is RequestIdBody =>
  typeof value === "object" && value !== null && "id" in value && typeof value.id === "string"

interface ConnectRequestBody {
  readonly method: string
  readonly params: ReadonlyArray<string>
}

const isConnectRequestBody = (value: unknown): value is ConnectRequestBody =>
  typeof value === "object" && value !== null &&
  "method" in value && typeof value.method === "string" &&
  "params" in value && Array.isArray(value.params)

const fakeTools = makeFakeTools(pubkeyOf)

interface Harness {
  readonly signer: ReturnType<typeof createNip46ClientSigner>
  readonly published: ReadonlyArray<NostrEvent>
  readonly publishedRelays: ReadonlyArray<RelayUrl>
  readonly injectBunkerResponse: (
    requestIndex: number,
    response: { result?: string; error?: string },
    fromPubkey?: PublicKey,
  ) => void
  readonly deliver: (event: NostrEvent) => void
}

const createHarness = (
  opts: {
    secret?: string | null
    timeoutMs?: number
    initialUserPubkey?: typeof USER_PK | null
    relayUrls?: ReadonlyArray<RelayUrl>
    verifyEventSignature?: (event: NostrEvent) => Promise<boolean>
    onPubkeyMismatch?: (expected: PublicKey, actual: PublicKey) => void
    onAuthChallenge?: (url: string) => void
  } = {},
): Harness => {
  const { transport, published, publishedRelays, deliver } = createCapturingTransport()

  const signer = createNip46ClientSigner({
    tools: fakeTools,
    transport,
    clientSecretKey: CLIENT_SK,
    remoteSignerPubkey: BUNKER_PK,
    relayUrls: opts.relayUrls ?? [RELAY],
    secret: opts.secret ?? null,
    initialUserPubkey: opts.initialUserPubkey ?? null,
    timeoutMs: opts.timeoutMs ?? 30_000,
    verifyEventSignature: opts.verifyEventSignature ?? ((): Promise<boolean> => Promise.resolve(true)),
    onPubkeyMismatch: opts.onPubkeyMismatch,
    onAuthChallenge: opts.onAuthChallenge,
    generateRequestId: (() => {
      let n = 0
      return () => `req-${++n}`
    })(),
  })

  const injectBunkerResponse = (
    requestIndex: number,
    response: { result?: string; error?: string },
    fromPubkey: PublicKey = pubkeyOf(BUNKER_SK),
  ): void => {
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
  }

  return { signer, published, publishedRelays, injectBunkerResponse, deliver }
}

Deno.test("signEvent - resolves with bunker-signed event when response matches request id", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })

  const unsigned: UnsignedEvent = { kind: 1, created_at: 100, tags: [], content: "hello" }
  const signPromise = h.signer.signEvent(unsigned)

  await flush()

  const signedByBunker = makeSigned(unsigned, USER_PK)
  h.injectBunkerResponse(0, { result: JSON.stringify(signedByBunker) })

  const result = await signPromise
  assertEquals(result.content, "hello")
  assertEquals(result.pubkey, USER_PK)
})

Deno.test("signEvent - throws PubkeyMismatchError when returned pubkey differs from known user pubkey", async () => {
  const h = createHarness()

  const getPublicKeyPromise = h.signer.getPublicKey()
  await flush()
  h.injectBunkerResponse(0, { result: USER_PK })
  assertEquals(await getPublicKeyPromise, USER_PK)

  const unsigned: UnsignedEvent = { kind: 1, created_at: 100, tags: [], content: "hello" }
  const signPromise = h.signer.signEvent(unsigned)
  await flush()

  const wrongSigned = makeSigned(unsigned, "d".repeat(64))
  h.injectBunkerResponse(1, { result: JSON.stringify(wrongSigned) })

  await assertRejects(() => signPromise, PubkeyMismatchError)
})

Deno.test("signEvent - fires onPubkeyMismatch callback before throwing", async () => {
  const calls: Array<{ expected: string; actual: string }> = []
  const h = createHarness({
    initialUserPubkey: USER_PK,
    onPubkeyMismatch: (expected, actual) => calls.push({ expected, actual }),
  })

  const unsigned: UnsignedEvent = { kind: 1, created_at: 100, tags: [], content: "hello" }
  const signPromise = h.signer.signEvent(unsigned)
  await flush()

  const wrongPubkey = "d".repeat(64)
  const wrongSigned = makeSigned(unsigned, wrongPubkey)
  h.injectBunkerResponse(0, { result: JSON.stringify(wrongSigned) })

  await assertRejects(() => signPromise, PubkeyMismatchError)
  assertEquals(calls.length, 1)
  const [call] = calls
  if (!call) throw new Error("expected one onPubkeyMismatch call")
  assertEquals(call.expected, USER_PK)
  assertEquals(call.actual, wrongPubkey)
})

Deno.test("signEvent - does not fire onPubkeyMismatch on success", async () => {
  const calls: Array<{ expected: string; actual: string }> = []
  const h = createHarness({
    initialUserPubkey: USER_PK,
    onPubkeyMismatch: (expected, actual) => calls.push({ expected, actual }),
  })

  const unsigned: UnsignedEvent = { kind: 1, created_at: 100, tags: [], content: "hello" }
  const signPromise = h.signer.signEvent(unsigned)
  await flush()

  const correctSigned = makeSigned(unsigned, USER_PK)
  h.injectBunkerResponse(0, { result: JSON.stringify(correctSigned) })

  await signPromise
  assertEquals(calls.length, 0)
})

Deno.test("signEvent - rejects when the bunker-signed event fails signature verification", async () => {
  const h = createHarness({
    initialUserPubkey: USER_PK,
    verifyEventSignature: () => Promise.resolve(false),
  })

  const unsigned: UnsignedEvent = { kind: 1, created_at: 100, tags: [], content: "hello" }
  const signPromise = h.signer.signEvent(unsigned)
  await flush()

  const signedByBunker = makeSigned(unsigned, USER_PK)
  h.injectBunkerResponse(0, { result: JSON.stringify(signedByBunker) })

  await assertRejects(() => signPromise, SigningError, "invalid signature")
})

Deno.test("signEvent - rejects with SigningError on timeout", async () => {
  const h = createHarness({ timeoutMs: 20, initialUserPubkey: USER_PK })

  const unsigned: UnsignedEvent = { kind: 1, created_at: 100, tags: [], content: "hello" }
  const signPromise = h.signer.signEvent(unsigned)

  await assertRejects(() => signPromise, SigningError, "timed out")
})

Deno.test("signEvent - rejects when called before connect", async () => {
  const h = createHarness()

  const unsigned: UnsignedEvent = { kind: 1, created_at: 100, tags: [], content: "hello" }

  await assertRejects(() => h.signer.signEvent(unsigned), SigningError, "not connected")
})

Deno.test("concurrent requests are correlated by id and do not cross", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })

  const unsignedA: UnsignedEvent = { kind: 1, created_at: 100, tags: [], content: "A" }
  const unsignedB: UnsignedEvent = { kind: 1, created_at: 100, tags: [], content: "B" }
  const signPromiseA = h.signer.signEvent(unsignedA)
  const signPromiseB = h.signer.signEvent(unsignedB)

  await flush()

  const signedB = makeSigned(unsignedB, USER_PK)
  h.injectBunkerResponse(1, { result: JSON.stringify(signedB) })
  const resultB = await signPromiseB
  assertEquals(resultB.content, "B")

  const signedA = makeSigned(unsignedA, USER_PK)
  h.injectBunkerResponse(0, { result: JSON.stringify(signedA) })
  const resultA = await signPromiseA
  assertEquals(resultA.content, "A")
})

Deno.test("disconnect - rejects in-flight requests and removes subscription", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })

  const unsigned: UnsignedEvent = { kind: 1, created_at: 100, tags: [], content: "x" }
  const signPromise = h.signer.signEvent(unsigned)
  await flush()

  h.signer.disconnect()

  await assertRejects(() => signPromise, SigningError, "disconnected")
})

Deno.test("connect - sends connect with secret and fetches user pubkey", async () => {
  const h = createHarness({ secret: "s1" })

  const connectPromise = h.signer.connect()
  await flush()
  assertEquals(h.published.length, 1)
  const [connectEvent] = h.published
  if (!connectEvent) throw new Error("expected a published connect event")
  const decoded: unknown = JSON.parse(fakeTools.nip44Decrypt(new Uint8Array(32), connectEvent.content))
  assert(isConnectRequestBody(decoded))
  assertEquals(decoded.method, "connect")
  assertEquals(decoded.params, [BUNKER_PK, "s1"])
  h.injectBunkerResponse(0, { result: "ack" })

  await flush()
  assertEquals(h.published.length, 2)
  h.injectBunkerResponse(1, { result: USER_PK })

  await connectPromise
  assertEquals(await h.signer.getPublicKey(), USER_PK)
})

Deno.test("connect - skips RPC when initialUserPubkey is provided (reload path)", async () => {
  const h = createHarness({ secret: "s1", initialUserPubkey: USER_PK })

  await h.signer.connect()
  assertEquals(h.published.length, 0)
  assertEquals(await h.signer.getPublicKey(), USER_PK)
})

Deno.test("connect - rejects when bunker returns error on connect", async () => {
  const h = createHarness({ secret: "wrong" })

  const connectPromise = h.signer.connect()
  await flush()
  h.injectBunkerResponse(0, { error: "invalid secret" })

  await assertRejects(() => connectPromise, SigningError, "invalid secret")
})

Deno.test("getClientPubkey - returns the ephemeral client pubkey derived from secret key", () => {
  const h = createHarness()
  assertEquals(h.signer.getClientPubkey(), CLIENT_PK)
})

Deno.test("auth_url response fires onAuthChallenge and leaves the request pending for the real reply", async () => {
  const urls: Array<string> = []
  const h = createHarness({ initialUserPubkey: USER_PK, onAuthChallenge: (url) => urls.push(url) })

  const unsigned: UnsignedEvent = { kind: 1, created_at: 100, tags: [], content: "hi" }
  const signPromise = h.signer.signEvent(unsigned)
  await flush()

  h.injectBunkerResponse(0, { result: "auth_url", error: "https://auth.example/approve" })
  await flush()
  assertEquals(urls, ["https://auth.example/approve"])

  const signed = makeSigned(unsigned, USER_PK)
  h.injectBunkerResponse(0, { result: JSON.stringify(signed) })
  const result = await signPromise
  assertEquals(result.content, "hi")
})

Deno.test("auth_url response without onAuthChallenge rejects with a clear error", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })

  const signPromise = h.signer.signEvent({ kind: 1, created_at: 100, tags: [], content: "hi" })
  await flush()
  h.injectBunkerResponse(0, { result: "auth_url", error: "https://auth.example/approve" })

  await assertRejects(() => signPromise, SigningError, "requires authentication")
})

Deno.test("nip44Encrypt returns a disconnected failure when the request times out", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK, timeoutMs: 20 })

  const result = await h.signer.nip44Encrypt(USER_PK, "secret")
  if (result.success) throw new Error("expected failure")
  assertEquals(result.error.tag, "disconnected")
})

Deno.test("nip44Encrypt maps a bunker error response to encrypt-failed", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })

  const resultPromise = h.signer.nip44Encrypt(USER_PK, "secret")
  await flush()
  h.injectBunkerResponse(0, { error: "nope" })

  const result = await resultPromise
  if (result.success) throw new Error("expected failure")
  assertEquals(result.error.tag, "encrypt-failed")
  assertEquals(result.error.message, "nope")
})

Deno.test("nip44Decrypt maps a bunker error response to decrypt-failed", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })

  const resultPromise = h.signer.nip44Decrypt(USER_PK, "cipher")
  await flush()
  h.injectBunkerResponse(0, { error: "nope" })

  const result = await resultPromise
  if (result.success) throw new Error("expected failure")
  assertEquals(result.error.tag, "decrypt-failed")
})

Deno.test("ignores a response from an author other than the remote signer", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK, timeoutMs: 50 })

  const unsigned: UnsignedEvent = { kind: 1, created_at: 100, tags: [], content: "hi" }
  const signPromise = h.signer.signEvent(unsigned)
  await flush()

  const forged = makeSigned(unsigned, USER_PK)
  h.injectBunkerResponse(0, { result: JSON.stringify(forged) }, parsePublicKey("d".repeat(64)))

  await assertRejects(() => signPromise, SigningError, "timed out")
})

Deno.test("publishes each request to every configured relay", async () => {
  const relayA = parseRelayUrl("ws://127.0.0.1:1")
  const relayB = parseRelayUrl("ws://127.0.0.1:2")
  const h = createHarness({ initialUserPubkey: USER_PK, relayUrls: [relayA, relayB] })

  h.signer.signEvent({ kind: 1, created_at: 100, tags: [], content: "x" }).catch(() => {})
  await flush()

  assertEquals(h.published.length, 2)
  assertEquals([...h.publishedRelays].sort(), [relayA, relayB].sort())

  h.signer.disconnect()
})

Deno.test("subscription filter targets kind 24133 addressed to client", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })

  h.signer.signEvent({ kind: 1, created_at: 100, tags: [], content: "x" }).catch(() => {})
  await flush()

  assert(h.published.length >= 1)
  const [publishedEvent] = h.published
  if (!publishedEvent) throw new Error("expected a published event")
  assertEquals(publishedEvent.kind, KIND_NOSTR_CONNECT)
  assertEquals(publishedEvent.tags[0], ["p", BUNKER_PK])

  h.signer.disconnect()
})

Deno.test("a NIP-04 response teaches the client the bunker's cipher for subsequent requests", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })

  const unsigned: UnsignedEvent = { kind: 1, created_at: 100, tags: [], content: "one" }
  const firstPromise = h.signer.signEvent(unsigned)
  await flush()

  const firstRequest = h.published[0]
  assert(firstRequest !== undefined)
  assert(firstRequest.content.startsWith("ENC:"), "first request defaults to NIP-44")

  const parsed: unknown = JSON.parse(fakeTools.nip44Decrypt(new Uint8Array(32), firstRequest.content))
  assert(isRequestIdBody(parsed))
  const signedByBunker = makeSigned(unsigned, USER_PK)
  const responseBody = { id: parsed.id, result: JSON.stringify(signedByBunker) }
  const nip04Content = await fakeTools.nip04Encrypt(BUNKER_SK, CLIENT_PK, JSON.stringify(responseBody))
  h.deliver(makeSigned({
    kind: KIND_NOSTR_CONNECT,
    created_at: now(),
    tags: [["p", CLIENT_PK]],
    content: nip04Content,
  }, BUNKER_PK))

  const result = await firstPromise
  assertEquals(result.content, "one")

  const secondPromise = h.signer.signEvent({ kind: 1, created_at: 101, tags: [], content: "two" })
  const secondRejection = assertRejects(() => secondPromise, SigningError)
  await flush()

  const secondRequest = h.published[1]
  assert(secondRequest !== undefined)
  assert(secondRequest.content.startsWith("NIP04:"), "second request follows the learned NIP-04 cipher")

  h.signer.disconnect()
  await secondRejection
})
