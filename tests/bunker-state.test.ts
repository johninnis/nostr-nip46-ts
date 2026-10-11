import { assert, assertEquals } from "@std/assert"
import { createBoundedMap, createSeenEventIds } from "../src/bounded-map.ts"
import { PENDING_REQUEST_LIMIT } from "../src/bunker-session.ts"
import { flush } from "./_helpers/fakes.ts"
import { ATTACKER_PK, CLIENT_PK, createHarness, USER_PK } from "./_helpers/bunker-harness.ts"

const SIGN_EVENT = JSON.stringify({ kind: 1, content: "hi" })
const RECEIVED_AT = 1_700_000_000
const TEN_MINUTES = 600

const pingDeliveredAt = async (offsetFromCreation: number): Promise<number> => {
  let clock = RECEIVED_AT
  const h = createHarness("supersecret", { now: () => clock })
  try {
    const envelope = await h.envelope(CLIENT_PK, { id: "t1", method: "ping" })
    clock += offsetFromCreation
    h.deliver(envelope)
    await flush()
    return h.published.length
  } finally {
    h.stop()
  }
}

Deno.test("bunker - drops a request envelope created more than ten minutes before its clock, without replying", async () => {
  assertEquals(await pingDeliveredAt(TEN_MINUTES + 1), 0)
})

Deno.test("bunker - drops a request envelope created more than ten minutes after its clock, without replying", async () => {
  assertEquals(await pingDeliveredAt(-TEN_MINUTES - 1), 0)
})

Deno.test("bunker - answers a request envelope created exactly ten minutes before its clock", async () => {
  assertEquals(await pingDeliveredAt(TEN_MINUTES), 1)
})

Deno.test("bunker - answers a request envelope created exactly ten minutes after its clock", async () => {
  assertEquals(await pingDeliveredAt(-TEN_MINUTES), 1)
})

Deno.test("bunker - a stale request envelope is not remembered, so it is answered once it is within the window", async () => {
  let clock = RECEIVED_AT
  const h = createHarness("supersecret", { now: () => clock })
  try {
    const envelope = await h.envelope(CLIENT_PK, { id: "t2", method: "ping" })
    clock -= TEN_MINUTES + 1
    h.deliver(envelope)
    await flush()
    const answeredWhenStale = h.published.length
    clock += 2
    h.deliver(envelope)
    await flush()
    assertEquals({ answeredWhenStale, answered: h.published.length }, { answeredWhenStale: 0, answered: 1 })
  } finally {
    h.stop()
  }
})

Deno.test("bunker - verifies a request envelope's signature before judging its age", async () => {
  let clock = RECEIVED_AT
  let verified = 0
  const h = createHarness("supersecret", {
    now: () => clock,
    verifyEventSignature: () => {
      verified++
      return true
    },
  })
  try {
    const envelope = await h.envelope(CLIENT_PK, { id: "t3", method: "ping" })
    clock += TEN_MINUTES + 1
    h.deliver(envelope)
    await flush()
    assertEquals(verified, 1)
  } finally {
    h.stop()
  }
})

Deno.test("bunker - drops a request envelope whose signature fails verification, without remembering it", async () => {
  let verdict = true
  const h = createHarness("supersecret", { verifyEventSignature: () => verdict })
  try {
    const envelope = await h.envelope(CLIENT_PK, { id: "s1", method: "ping" })
    verdict = false
    h.deliver(envelope)
    await flush()
    assertEquals(h.published.length, 0)
    verdict = true
    h.deliver(envelope)
    await flush()
    assertEquals(h.lastResponse()?.result, "pong")
  } finally {
    h.stop()
  }
})

Deno.test("bunker - two clients using the same request id are queued and answered independently", async () => {
  const h = createHarness("supersecret")
  try {
    for (const [client, secret] of [[CLIENT_PK, "supersecret"], [ATTACKER_PK, "second-secret"]] as const) {
      h.bunker.issueSecret(secret)
      await h.send(client, { id: "c", method: "connect", params: [USER_PK, secret] })
      await h.send(client, { id: "1", method: "sign_event", params: [SIGN_EVENT] })
    }
    const queued = h.pending()
    assertEquals(queued.map((request) => request.requestId), ["1", "1"])
    const second = queued.find((request) => request.clientPubkey === ATTACKER_PK)
    assert(second !== undefined)
    await h.bunker.reject(second.id)
    assertEquals(h.pending().map((request) => request.clientPubkey), [CLIENT_PK])
  } finally {
    h.stop()
  }
})

Deno.test("bunker - a queued request is identified by the event that carried it", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "c", method: "connect", params: [USER_PK, "supersecret"] })
    const carrier = await h.envelope(CLIENT_PK, { id: "1", method: "sign_event", params: [SIGN_EVENT] })
    h.deliver(carrier)
    await flush()
    assertEquals(h.pending().map((request) => request.id), [carrier.id])
  } finally {
    h.stop()
  }
})

Deno.test("bunker - a request redelivered by a second relay is handled once", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "c", method: "connect", params: [USER_PK, "supersecret"] })
    const carrier = await h.envelope(CLIENT_PK, { id: "1", method: "sign_event", params: [SIGN_EVENT] })
    h.deliver(carrier)
    h.deliver(carrier)
    await flush()
    assertEquals(h.pending().length, 1)
  } finally {
    h.stop()
  }
})

Deno.test("bunker - a full queue refuses a new request with too many pending requests", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "c", method: "connect", params: [USER_PK, "supersecret"] })
    for (let i = 0; i < PENDING_REQUEST_LIMIT; i++) {
      h.deliver(await h.envelope(CLIENT_PK, { id: `q${i}`, method: "sign_event", params: [SIGN_EVENT] }))
    }
    await flush()
    await h.send(CLIENT_PK, { id: "overflow", method: "sign_event", params: [SIGN_EVENT] })
    assertEquals({ queued: h.pending().length, response: h.lastResponse() }, {
      queued: PENDING_REQUEST_LIMIT,
      response: { id: "overflow", error: "too many pending requests" },
    })
  } finally {
    h.stop()
  }
})

Deno.test("createBoundedMap - evicts the oldest entry once past its limit", () => {
  const map = createBoundedMap<number>(2)
  map.set("a", 1)
  map.set("b", 2)
  map.set("c", 3)
  assertEquals([map.has("a"), map.get("b"), map.get("c")], [false, 2, 3])
})

Deno.test("createBoundedMap - forgets an entry on request", () => {
  const map = createBoundedMap<number>(2)
  map.set("a", 1)
  map.forget("a")
  assertEquals(map.get("a"), undefined)
})

Deno.test("createSeenEventIds - remembers an id once and evicts the oldest past its limit", () => {
  const seen = createSeenEventIds(2)
  const first = [seen.remember("a"), seen.remember("a"), seen.remember("b"), seen.remember("c")]
  assertEquals([...first, seen.remember("a")], [true, false, true, true, true])
})
