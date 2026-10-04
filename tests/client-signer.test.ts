import { assert, assertEquals, assertRejects } from "@std/assert"
import type { UnsignedEvent } from "@innis/nostr-core"
import { failure, InvalidArgumentError, KIND_NOSTR_CONNECT, now, ok } from "@innis/nostr-core"
import { publicKeyFixture, relayUrlFixture } from "@innis/nostr-core/testing"
import { createNip46ClientSigner } from "../src/client-signer.ts"
import { createCapturingTransport, flush } from "./_helpers/fakes.ts"
import {
  BUNKER_PK,
  BUNKER_SK,
  CLIENT_PK,
  createHarness,
  fakeTools,
  isConnectRequestBody,
  isRequestIdBody,
  makeSigned,
  USER_PK,
} from "./_helpers/client-harness.ts"

Deno.test("createNip46ClientSigner - builds a bunker-kind signer whose restored pubkey needs no request", async () => {
  const { transport, published } = createCapturingTransport()
  const signer = createNip46ClientSigner({
    tools: fakeTools,
    transport,
    clientSecretKey: new Uint8Array(32).fill(1),
    remoteSignerPubkey: BUNKER_PK,
    relayUrls: [relayUrlFixture("wss://relay.example")],
    secret: null,
    initialUserPubkey: USER_PK,
  })

  assertEquals(signer.kind, "bunker")
  assertEquals(await signer.getPublicKey(), ok(USER_PK))
  assertEquals(published.length, 0)
})
Deno.test("signEvent - resolves with bunker-signed event when response matches request id", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })

  const unsigned: UnsignedEvent = { kind: 1, created_at: 100, tags: [], content: "hello" }
  const signPromise = h.signer.signEvent(unsigned)

  await flush()

  const signedByBunker = makeSigned(unsigned, USER_PK)
  h.injectBunkerResponse(0, { result: JSON.stringify(signedByBunker) })

  const result = await signPromise
  assertEquals(result, ok(signedByBunker))
})

Deno.test("signEvent - returns pubkey-mismatch when returned pubkey differs from known user pubkey", async () => {
  const h = createHarness()

  const getPublicKeyPromise = h.signer.getPublicKey()
  await flush()
  h.injectBunkerResponse(0, { result: USER_PK })
  assertEquals(await getPublicKeyPromise, ok(USER_PK))

  const unsigned: UnsignedEvent = { kind: 1, created_at: 100, tags: [], content: "hello" }
  const signPromise = h.signer.signEvent(unsigned)
  await flush()

  const wrongSigned = makeSigned(unsigned, "d".repeat(64))
  h.injectBunkerResponse(1, { result: JSON.stringify(wrongSigned) })

  const result = await signPromise
  assertEquals(!result.success && result.error.type, "pubkey-mismatch")
})

Deno.test("signEvent - fires onPubkeyMismatch callback when returning pubkey-mismatch", async () => {
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

  await signPromise
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

Deno.test("signEvent - returns sign-failed when the bunker-signed event fails signature verification", async () => {
  const h = createHarness({
    initialUserPubkey: USER_PK,
    verifyEventSignature: () => false,
  })

  const unsigned: UnsignedEvent = { kind: 1, created_at: 100, tags: [], content: "hello" }
  const signPromise = h.signer.signEvent(unsigned)
  await flush()

  const signedByBunker = makeSigned(unsigned, USER_PK)
  h.injectBunkerResponse(0, { result: JSON.stringify(signedByBunker) })

  assertEquals(
    await signPromise,
    failure({ type: "sign-failed", message: "bunker returned an event with an invalid signature" }),
  )
})

Deno.test("signEvent - returns disconnected on timeout", async () => {
  const h = createHarness({ timeoutMs: 20, initialUserPubkey: USER_PK })

  const unsigned: UnsignedEvent = { kind: 1, created_at: 100, tags: [], content: "hello" }

  assertEquals(
    await h.signer.signEvent(unsigned),
    failure({ type: "disconnected", message: "bunker request timed out" }),
  )
})

Deno.test("signEvent - returns disconnected when called before connect", async () => {
  const h = createHarness()

  const unsigned: UnsignedEvent = { kind: 1, created_at: 100, tags: [], content: "hello" }

  const result = await h.signer.signEvent(unsigned)
  assertEquals(!result.success && result.error.type, "disconnected")
})

Deno.test("signEvent - returns rejected when the bunker's error says the user declined", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })

  const signPromise = h.signer.signEvent({ kind: 1, created_at: 100, tags: [], content: "hello" })
  await flush()
  h.injectBunkerResponse(0, { error: "user rejected" })

  assertEquals(await signPromise, failure({ type: "rejected", message: "user rejected" }))
})

Deno.test("signEvent - returns sign-failed carrying a bunker error that does not say the user declined", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })

  const signPromise = h.signer.signEvent({ kind: 1, created_at: 100, tags: [], content: "hello" })
  await flush()
  h.injectBunkerResponse(0, { error: "signing failed" })

  assertEquals(await signPromise, failure({ type: "sign-failed", message: "signing failed" }))
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
  assertEquals(resultB.success && resultB.value.content, "B")

  const signedA = makeSigned(unsignedA, USER_PK)
  h.injectBunkerResponse(0, { result: JSON.stringify(signedA) })
  const resultA = await signPromiseA
  assertEquals(resultA.success && resultA.value.content, "A")
})

Deno.test("disconnect - settles in-flight requests as disconnected", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })

  const unsigned: UnsignedEvent = { kind: 1, created_at: 100, tags: [], content: "x" }
  const signPromise = h.signer.signEvent(unsigned)
  await flush()

  h.signer.disconnect()

  assertEquals(await signPromise, failure({ type: "disconnected", message: "bunker disconnected" }))
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
  h.injectBunkerResponse(1, { result: "null" })

  await flush()
  assertEquals(h.published.length, 3)
  h.injectBunkerResponse(2, { result: USER_PK })

  assertEquals(await connectPromise, ok(undefined))
  assertEquals(await h.signer.getPublicKey(), ok(USER_PK))
})

Deno.test("connect - skips RPC when initialUserPubkey is provided (reload path)", async () => {
  const h = createHarness({ secret: "s1", initialUserPubkey: USER_PK })

  assertEquals(await h.signer.connect(), ok(undefined))
  assertEquals(h.published.length, 0)
  assertEquals(await h.signer.getPublicKey(), ok(USER_PK))
})

Deno.test("connect - returns public-key-failed carrying the bunker's error on connect", async () => {
  const h = createHarness({ secret: "wrong" })

  const connectPromise = h.signer.connect()
  await flush()
  h.injectBunkerResponse(0, { error: "invalid secret" })

  assertEquals(await connectPromise, failure({ type: "public-key-failed", message: "invalid secret" }))
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
  assertEquals(result.success && result.value.content, "hi")
})

Deno.test("auth_url response without onAuthChallenge returns a clear failure", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })

  const signPromise = h.signer.signEvent({ kind: 1, created_at: 100, tags: [], content: "hi" })
  await flush()
  h.injectBunkerResponse(0, { result: "auth_url", error: "https://auth.example/approve" })

  assertEquals(
    await signPromise,
    failure({ type: "sign-failed", message: "bunker requires authentication: https://auth.example/approve" }),
  )
})

Deno.test("nip44Encrypt returns a disconnected failure when the request times out", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK, timeoutMs: 20 })

  const result = await h.signer.nip44Encrypt(USER_PK, "secret")
  if (result.success) throw new Error("expected failure")
  assertEquals(result.error.type, "disconnected")
})

Deno.test("nip44Encrypt fails immediately when no relay accepts the request envelope", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })
  h.rejectPublishes()

  const result = await h.signer.nip44Encrypt(USER_PK, "secret")
  if (result.success) throw new Error("expected failure")
  assertEquals(result.error.type, "disconnected")
})

Deno.test("nip44Encrypt fails immediately when there is no relay to publish to", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK, relayUrls: [] })

  const result = await h.signer.nip44Encrypt(USER_PK, "secret")
  if (result.success) throw new Error("expected failure")
  assertEquals(result.error.type, "disconnected")
})

Deno.test("signEvent returns disconnected immediately when no relay accepts the request envelope", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })
  h.rejectPublishes()

  const result = await h.signer.signEvent({ kind: 1, created_at: now(), tags: [], content: "hello" })
  assertEquals(!result.success && result.error.type, "disconnected")
})

Deno.test("nip44Encrypt maps a bunker error response to encrypt-failed", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })

  const resultPromise = h.signer.nip44Encrypt(USER_PK, "secret")
  await flush()
  h.injectBunkerResponse(0, { error: "nope" })

  const result = await resultPromise
  if (result.success) throw new Error("expected failure")
  assertEquals(result.error.type, "encrypt-failed")
  assertEquals(result.error.message, "nope")
})

Deno.test("nip44Decrypt maps a bunker error response to decrypt-failed", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })

  const resultPromise = h.signer.nip44Decrypt(USER_PK, "cipher")
  await flush()
  h.injectBunkerResponse(0, { error: "nope" })

  const result = await resultPromise
  if (result.success) throw new Error("expected failure")
  assertEquals(result.error.type, "decrypt-failed")
})

Deno.test("nip44Decrypt returns rejected when the bunker's error says the user denied it", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })

  const resultPromise = h.signer.nip44Decrypt(USER_PK, "cipher")
  await flush()
  h.injectBunkerResponse(0, { error: "permission denied" })

  assertEquals(await resultPromise, failure({ type: "rejected", message: "permission denied" }))
})

Deno.test("ignores a response from an author other than the remote signer", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK, timeoutMs: 50 })

  const unsigned: UnsignedEvent = { kind: 1, created_at: 100, tags: [], content: "hi" }
  const signPromise = h.signer.signEvent(unsigned)
  await flush()

  const forged = makeSigned(unsigned, USER_PK)
  h.injectBunkerResponse(0, { result: JSON.stringify(forged) }, publicKeyFixture("d".repeat(64)))

  assertEquals(await signPromise, failure({ type: "disconnected", message: "bunker request timed out" }))
})

Deno.test("publishes each request to every configured relay", async () => {
  const relayA = relayUrlFixture("ws://127.0.0.1:1")
  const relayB = relayUrlFixture("ws://127.0.0.1:2")
  const h = createHarness({ initialUserPubkey: USER_PK, relayUrls: [relayA, relayB] })

  const pendingSign = h.signer.signEvent({ kind: 1, created_at: 100, tags: [], content: "x" })
  await flush()

  assertEquals(h.published.length, 2)
  assertEquals([...h.publishedRelays].sort(), [relayA, relayB].sort())

  h.signer.disconnect()
  await pendingSign
})

Deno.test("subscription filter targets kind 24133 addressed to client", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })

  const pendingSign = h.signer.signEvent({ kind: 1, created_at: 100, tags: [], content: "x" })
  await flush()

  assert(h.published.length >= 1)
  const [publishedEvent] = h.published
  if (!publishedEvent) throw new Error("expected a published event")
  assertEquals(publishedEvent.kind, KIND_NOSTR_CONNECT)
  assertEquals(publishedEvent.tags[0], ["p", BUNKER_PK])

  h.signer.disconnect()
  await pendingSign
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
  assertEquals(result.success && result.value.content, "one")

  const secondPromise = h.signer.signEvent({ kind: 1, created_at: 101, tags: [], content: "two" })
  await flush()

  const secondRequest = h.published[1]
  assert(secondRequest !== undefined)
  assert(secondRequest.content.startsWith("NIP04:"), "second request follows the learned NIP-04 cipher")

  h.signer.disconnect()
  assertEquals((await secondPromise).success, false)
})

Deno.test("signEvent - rejects with InvalidArgumentError for a template that is not a NIP-01 event, sending no request", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })
  for (const template of [{ kind: 70000, created_at: 1 }, { kind: 1, created_at: 1.5 }, { kind: 1, created_at: -5 }]) {
    await assertRejects(() => h.signer.signEvent({ ...template, content: "", tags: [] }), InvalidArgumentError)
  }
  await flush()
  assertEquals(h.published.length, 0)
})
