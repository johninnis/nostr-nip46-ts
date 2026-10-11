import { assertEquals, equal } from "@std/assert"
import { FakeTime } from "@std/testing/time"
import type { Result, SignerFailure, UnsignedEvent } from "@innis/nostr-core"
import { failure, ok } from "@innis/nostr-core"
import { elapse, flush } from "./_helpers/fakes.ts"
import { BUNKER_PK, createHarness, makeSigned, USER_PK } from "./_helpers/client-harness.ts"

interface AuthUrlVectors {
  readonly vectors: ReadonlyArray<readonly [string | null, string | null]>
}

interface ChallengeOutcome {
  readonly handedOver: ReadonlyArray<string>
  readonly failure: string | null
}

const VECTORS: AuthUrlVectors = JSON.parse(
  await Deno.readTextFile(new URL("./auth-url-vectors.json", import.meta.url)),
)

const UNSIGNED: UnsignedEvent = { kind: 1, created_at: 100, tags: [], content: "hi" }
const NOT_A_WEB_URL = "bunker sent an authentication URL that is not a web URL"
const APPROVAL_URL = "https://bunker.example/authorise"
const TIMED_OUT: Result<string, SignerFailure> = failure({ type: "disconnected", message: "bunker request timed out" })
const FIVE_MINUTES_MS = 300_000

const ignoreChallenge = (): void => undefined

const challengeCarrying = (error: string | null): { result: string; error?: string } =>
  error === null ? { result: "auth_url" } : { result: "auth_url", error }

const outcomeWithListener = async (error: string | null): Promise<ChallengeOutcome> => {
  const handedOver: Array<string> = []
  const h = createHarness({ initialUserPubkey: USER_PK, onAuthChallenge: (url) => handedOver.push(url) })
  const signing = h.signer.signEvent(UNSIGNED)
  await flush()
  h.injectBunkerResponse(0, challengeCarrying(error))
  await flush()
  h.signer.disconnect()
  const result = await signing
  return { handedOver, failure: result.success ? null : result.error.message }
}

const failureWithoutListener = async (error: string | null): Promise<string | null> => {
  const h = createHarness({ initialUserPubkey: USER_PK })
  const signing = h.signer.signEvent(UNSIGNED)
  await flush()
  h.injectBunkerResponse(0, challengeCarrying(error))
  const result = await signing
  return result.success ? null : result.error.message
}

Deno.test("auth_url vectors - every shared vector is loaded", () => {
  assertEquals(VECTORS.vectors.length, 71)
})

Deno.test("auth_url challenge - a listener is handed each shared vector's url as received, and nothing else", async () => {
  const disagreements: Array<string | null> = []
  for (const [error, handedOver] of VECTORS.vectors) {
    const expected: ChallengeOutcome = handedOver === null
      ? { handedOver: [], failure: NOT_A_WEB_URL }
      : { handedOver: [handedOver], failure: "bunker disconnected" }
    if (!equal(await outcomeWithListener(error), expected)) disagreements.push(error)
  }
  assertEquals(disagreements, [])
})

Deno.test("auth_url challenge - with no listener each shared vector fails its request with or without its url", async () => {
  const disagreements: Array<string | null> = []
  for (const [error, handedOver] of VECTORS.vectors) {
    const expected = handedOver === null ? NOT_A_WEB_URL : `bunker requires authentication: ${handedOver}`
    if (await failureWithoutListener(error) !== expected) disagreements.push(error)
  }
  assertEquals(disagreements, [])
})

Deno.test("auth_url challenge with a non-web url fails the request in the method's own mode", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK, timeoutMs: 1_000 })
  const encrypting = h.signer.nip44Encrypt(BUNKER_PK, "hi")
  await flush()
  h.injectBunkerResponse(0, { result: "auth_url", error: "javascript:alert(1)" })
  assertEquals(await encrypting, failure({ type: "encrypt-failed", message: NOT_A_WEB_URL }))
})

Deno.test("auth_url challenge with no listener is not read as a decline whatever words its url holds", async () => {
  assertEquals(
    await failureWithoutListener("https://auth.example/denied?cancel=rejected"),
    "bunker requires authentication: https://auth.example/denied?cancel=rejected",
  )
})

Deno.test("auth_url challenge - a listener that throws is reported, and its request still settles with the reply", async () => {
  const reported: Array<unknown> = []
  const capture = (event: ErrorEvent): void => {
    event.preventDefault()
    reported.push(event.error)
  }
  globalThis.addEventListener("error", capture)
  try {
    const h = createHarness({
      initialUserPubkey: USER_PK,
      onAuthChallenge: () => {
        throw new Error("host cannot open a window")
      },
    })
    const signing = h.signer.signEvent(UNSIGNED)
    await flush()
    h.injectBunkerResponse(0, { result: "auth_url", error: "https://bunker.example/authorise" })
    await flush()
    h.injectBunkerResponse(0, { result: JSON.stringify(makeSigned(UNSIGNED, USER_PK)) })
    const result = await signing
    assertEquals({ reported: reported.length, settled: result.success }, { reported: 1, settled: true })
  } finally {
    globalThis.removeEventListener("error", capture)
  }
})

Deno.test("auth_url challenge - a reply after the request timeout but within the approval window settles the request", async () => {
  const h = createHarness({
    initialUserPubkey: USER_PK,
    timeoutMs: 100,
    approvalWindowMs: 1_000,
    onAuthChallenge: ignoreChallenge,
  })
  const encrypting = h.signer.nip44Encrypt(BUNKER_PK, "hi")
  await flush()
  h.injectBunkerResponse(0, { result: "auth_url", error: APPROVAL_URL })
  await elapse(250)
  h.injectBunkerResponse(0, { result: "sealed" })
  assertEquals(await encrypting, ok("sealed"))
})

Deno.test("auth_url challenge - a request still unanswered when the approval window closes fails as a timeout", async () => {
  const h = createHarness({
    initialUserPubkey: USER_PK,
    timeoutMs: 100,
    approvalWindowMs: 200,
    onAuthChallenge: ignoreChallenge,
  })
  const encrypting = h.signer.nip44Encrypt(BUNKER_PK, "hi")
  await flush()
  h.injectBunkerResponse(0, { result: "auth_url", error: APPROVAL_URL })
  assertEquals(await encrypting, TIMED_OUT)
})

Deno.test("auth_url challenge - a further challenge restarts the approval window", async () => {
  const h = createHarness({
    initialUserPubkey: USER_PK,
    timeoutMs: 100,
    approvalWindowMs: 400,
    onAuthChallenge: ignoreChallenge,
  })
  const encrypting = h.signer.nip44Encrypt(BUNKER_PK, "hi")
  await flush()
  h.injectBunkerResponse(0, { result: "auth_url", error: APPROVAL_URL })
  await elapse(250)
  h.injectBunkerResponse(0, { result: "auth_url", error: APPROVAL_URL })
  await elapse(250)
  h.injectBunkerResponse(0, { result: "sealed" })
  assertEquals(await encrypting, ok("sealed"))
})

Deno.test("auth_url challenge - a request no challenge answered times out at the request timeout, not the approval window", async () => {
  const h = createHarness({
    initialUserPubkey: USER_PK,
    timeoutMs: 100,
    approvalWindowMs: 1_000,
    onAuthChallenge: ignoreChallenge,
  })
  const encrypting = h.signer.nip44Encrypt(BUNKER_PK, "hi")
  await elapse(250)
  h.injectBunkerResponse(0, { result: "sealed" })
  assertEquals(await encrypting, TIMED_OUT)
})

Deno.test("auth_url challenge - the default approval window outlasts the request timeout", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK, timeoutMs: 100, onAuthChallenge: ignoreChallenge })
  const encrypting = h.signer.nip44Encrypt(BUNKER_PK, "hi")
  await flush()
  h.injectBunkerResponse(0, { result: "auth_url", error: APPROVAL_URL })
  await elapse(250)
  h.injectBunkerResponse(0, { result: "sealed" })
  assertEquals(await encrypting, ok("sealed"))
})

const encryptAnsweredAfterTheDefaultWindowMinus = async (
  earlierMs: number,
): Promise<Result<string, SignerFailure>> => {
  using time = new FakeTime()
  const h = createHarness({ initialUserPubkey: USER_PK, timeoutMs: 100, onAuthChallenge: ignoreChallenge })
  const encrypting = h.signer.nip44Encrypt(BUNKER_PK, "hi")
  await time.runMicrotasks()
  h.injectBunkerResponse(0, { result: "auth_url", error: APPROVAL_URL })
  await time.runMicrotasks()
  await time.tickAsync(FIVE_MINUTES_MS - earlierMs)
  h.injectBunkerResponse(0, { result: "sealed" })
  return await encrypting
}

Deno.test("auth_url challenge - a reply just inside the default five-minute approval window settles the request", async () => {
  assertEquals(await encryptAnsweredAfterTheDefaultWindowMinus(1), ok("sealed"))
})

Deno.test("auth_url challenge - a reply just outside the default five-minute approval window arrives too late", async () => {
  assertEquals(await encryptAnsweredAfterTheDefaultWindowMinus(-1), TIMED_OUT)
})
