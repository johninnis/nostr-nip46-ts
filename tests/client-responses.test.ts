import { assertEquals, assertRejects } from "@std/assert"
import type { Result, SignerFailure, UnsignedEvent } from "@innis/nostr-core"
import { failure, KIND_NOSTR_CONNECT, now, ok } from "@innis/nostr-core"
import { flush } from "./_helpers/fakes.ts"
import { BUNKER_PK, CLIENT_PK, createHarness, fakeTools, makeSigned, USER_PK } from "./_helpers/client-harness.ts"

const UNSIGNED: UnsignedEvent = { kind: 1, created_at: 100, tags: [], content: "hi" }

const challengeFor = (requestId: string, url: string): ReturnType<typeof makeSigned> =>
  makeSigned({
    kind: KIND_NOSTR_CONNECT,
    created_at: now(),
    tags: [["p", CLIENT_PK]],
    content: fakeTools.nip44Encrypt(
      new Uint8Array(32),
      JSON.stringify({ id: requestId, result: "auth_url", error: url }),
    ),
  }, BUNKER_PK)

Deno.test("auth_url challenge redelivered by several relays reaches the host once", async () => {
  const urls: Array<string> = []
  const h = createHarness({ initialUserPubkey: USER_PK, onAuthChallenge: (url) => urls.push(url) })
  const signing = h.signer.signEvent(UNSIGNED)
  await flush()
  const challenge = challengeFor("req-1", "https://auth.example/approve")
  h.deliver(challenge)
  h.deliver(challenge)
  await flush()
  assertEquals(urls, ["https://auth.example/approve"])
  h.signer.disconnect()
  await signing
})

Deno.test("auth_url challenge re-issued as a new event reaches the host again", async () => {
  const urls: Array<string> = []
  const h = createHarness({ initialUserPubkey: USER_PK, onAuthChallenge: (url) => urls.push(url) })
  const signing = h.signer.signEvent(UNSIGNED)
  await flush()
  h.deliver(challengeFor("req-1", "https://auth.example/approve"))
  h.deliver(challengeFor("req-1", "https://auth.example/approve"))
  await flush()
  assertEquals(urls.length, 2)
  h.signer.disconnect()
  await signing
})

Deno.test("a response redelivered by several relays settles its request once", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })
  const signing = h.signer.signEvent(UNSIGNED)
  await flush()
  const signed = makeSigned(UNSIGNED, USER_PK)
  const response = makeSigned({
    kind: KIND_NOSTR_CONNECT,
    created_at: now(),
    tags: [["p", CLIENT_PK]],
    content: fakeTools.nip44Encrypt(
      new Uint8Array(32),
      JSON.stringify({ id: "req-1", result: JSON.stringify(signed) }),
    ),
  }, BUNKER_PK)
  h.deliver(response)
  h.deliver(response)
  const result = await signing
  assertEquals(result.success && result.value.content, "hi")
})

Deno.test("a transport fault while publishing a request rejects the call instead of returning a failure", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })
  h.breakPublishes()
  await assertRejects(() => h.signer.signEvent(UNSIGNED), Error, "socket torn down mid-write")
})

Deno.test("a response with neither a result nor an error fails the request in its own mode", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })
  const encrypting = h.signer.nip44Encrypt(BUNKER_PK, "hi")
  await flush()
  h.injectBunkerResponse(0, {})
  assertEquals(await encrypting, failure({ type: "encrypt-failed", message: "bunker answered with no result" }))
})

Deno.test("a response whose result is not a string is ignored, leaving the request pending", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK, timeoutMs: 20 })
  const encrypting = h.signer.nip44Encrypt(BUNKER_PK, "hi")
  await flush()
  h.deliver(makeSigned({
    kind: KIND_NOSTR_CONNECT,
    created_at: now(),
    tags: [["p", CLIENT_PK]],
    content: fakeTools.nip44Encrypt(new Uint8Array(32), JSON.stringify({ id: "req-1", result: 7 })),
  }, BUNKER_PK))
  assertEquals((await encrypting).success ? null : "disconnected", "disconnected")
})

const RECEIVED_AT = 1_700_000_000
const TEN_MINUTES = 600

const sealedResponseCreatedAt = (createdAt: number): ReturnType<typeof makeSigned> =>
  makeSigned({
    kind: KIND_NOSTR_CONNECT,
    created_at: createdAt,
    tags: [["p", CLIENT_PK]],
    content: fakeTools.nip44Encrypt(new Uint8Array(32), JSON.stringify({ id: "req-1", result: "sealed" })),
  }, BUNKER_PK)

const encryptAnsweredBy = async (createdAt: number): Promise<Result<string, SignerFailure>> => {
  const h = createHarness({ initialUserPubkey: USER_PK, timeoutMs: 50, now: () => RECEIVED_AT })
  const encrypting = h.signer.nip44Encrypt(BUNKER_PK, "hi")
  await flush()
  h.deliver(sealedResponseCreatedAt(createdAt))
  return encrypting
}

const TIMED_OUT: Result<string, SignerFailure> = failure({ type: "disconnected", message: "bunker request timed out" })

Deno.test("a response envelope created more than ten minutes before the client's clock is dropped", async () => {
  assertEquals(await encryptAnsweredBy(RECEIVED_AT - TEN_MINUTES - 1), TIMED_OUT)
})

Deno.test("a response envelope created more than ten minutes after the client's clock is dropped", async () => {
  assertEquals(await encryptAnsweredBy(RECEIVED_AT + TEN_MINUTES + 1), TIMED_OUT)
})

Deno.test("a response envelope created exactly ten minutes before the client's clock settles its request", async () => {
  assertEquals(await encryptAnsweredBy(RECEIVED_AT - TEN_MINUTES), ok("sealed"))
})

Deno.test("a response envelope created exactly ten minutes after the client's clock settles its request", async () => {
  assertEquals(await encryptAnsweredBy(RECEIVED_AT + TEN_MINUTES), ok("sealed"))
})

Deno.test("a stale response envelope is not remembered, so it settles its request once within the window", async () => {
  let clock = RECEIVED_AT
  const h = createHarness({ initialUserPubkey: USER_PK, now: () => clock })
  const encrypting = h.signer.nip44Encrypt(BUNKER_PK, "hi")
  let settled = false
  void encrypting.then(() => settled = true)
  await flush()
  const response = sealedResponseCreatedAt(RECEIVED_AT + TEN_MINUTES + 1)
  h.deliver(response)
  await flush()
  const settledWhenStale = settled
  clock += 2
  h.deliver(response)
  assertEquals({ settledWhenStale, result: await encrypting }, { settledWhenStale: false, result: ok("sealed") })
})

Deno.test("the client verifies a response envelope's signature before judging its age", async () => {
  let verified = 0
  const h = createHarness({
    initialUserPubkey: USER_PK,
    now: () => RECEIVED_AT,
    verifyEventSignature: () => {
      verified++
      return true
    },
  })
  const encrypting = h.signer.nip44Encrypt(BUNKER_PK, "hi")
  await flush()
  h.deliver(sealedResponseCreatedAt(RECEIVED_AT - TEN_MINUTES - 1))
  await flush()
  h.signer.disconnect()
  await encrypting
  assertEquals(verified, 1)
})
