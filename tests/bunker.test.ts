import { assert, assertEquals, assertThrows } from "@std/assert"
import type { NostrEvent, Signer } from "@innis/nostr-core"
import { createLocalSigner, failure, InvalidArgumentError, KIND_NOSTR_CONNECT } from "@innis/nostr-core"
import { eventIdFixture, sigFixture } from "@innis/nostr-core/testing"
import { createNip46Bunker } from "../src/bunker.ts"
import { parseBunkerUrl } from "../src/bunker-url.ts"
import type { Nip46Transport } from "../src/transport.ts"
import { flush } from "./_helpers/fakes.ts"
import {
  ATTACKER_PK,
  BUNKER_PK,
  BUNKER_SK,
  CLIENT_PK,
  createHarness,
  fakeTools,
  grantAllButSigning,
  isSignedEventBody,
  RELAY,
  USER_PK,
} from "./_helpers/bunker-harness.ts"
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

Deno.test("bunker - connect with an empty signer pubkey and correct secret authenticates", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "es1", method: "connect", params: ["", "supersecret"] })
    assertEquals(h.lastResponse()?.result, "ack")
    await h.send(CLIENT_PK, { id: "es2", method: "get_public_key" })
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
      id: eventIdFixture("a".repeat(64)),
      pubkey: CLIENT_PK,
      created_at: 1700000000,
      kind: KIND_NOSTR_CONNECT,
      tags: [["p", USER_PK]],
      content: "garbage-ciphertext-matching-neither-cipher",
      sig: sigFixture("0".repeat(128)),
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
    assertEquals(h.lastResponse()?.result, "NIP04:hello?iv=AAAA")
  } finally {
    h.stop()
  }
})

Deno.test("bunker - nip04_decrypt round-trips through the signer once authenticated", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "13", method: "connect", params: [USER_PK, "supersecret"] })
    assertEquals(h.lastResponse()?.result, "ack")
    await h.send(CLIENT_PK, { id: "14", method: "nip04_decrypt", params: [USER_PK, "NIP04:hello?iv=AAAA"] })
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

Deno.test("bunker - start on an empty relay set is a fault", () => {
  const transport: Nip46Transport = {
    subscribe: () => ({ abort: () => {} }),
    publish: () => Promise.resolve({ ok: true }),
  }
  const bunker = createNip46Bunker({
    transport,
    signer: createLocalSigner(BUNKER_SK, fakeTools),
    isAuthorised: grantAllButSigning,
  })

  assertThrows(() => bunker.start(USER_PK, [], "secret"), InvalidArgumentError)
})

Deno.test("bunker - start with an empty secret is a no-op and emits no URL", () => {
  const transport: Nip46Transport = {
    subscribe: () => ({ abort: () => {} }),
    publish: () => Promise.resolve({ ok: true }),
  }
  const bunker = createNip46Bunker({
    transport,
    signer: createLocalSigner(BUNKER_SK, fakeTools),
    isAuthorised: grantAllButSigning,
  })

  bunker.start(USER_PK, [RELAY], "")
  assertEquals(bunker.getBunkerUrl(), null)
  bunker.stop()
})

Deno.test("bunker - URL-encodes the secret in getBunkerUrl", () => {
  const transport: Nip46Transport = {
    subscribe: () => ({ abort: () => {} }),
    publish: () => Promise.resolve({ ok: true }),
  }
  const bunkerSigner = createLocalSigner(BUNKER_SK, fakeTools)
  const bunker = createNip46Bunker({ transport, signer: bunkerSigner, isAuthorised: grantAllButSigning })

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

Deno.test("bunker - approve replies user rejected when the signer declines to sign", async () => {
  const localSigner = createLocalSigner(BUNKER_SK, fakeTools)
  const decliningSigner: Signer = {
    ...localSigner,
    signEvent: (event) =>
      event.kind === KIND_NOSTR_CONNECT
        ? localSigner.signEvent(event)
        : Promise.resolve(failure({ type: "rejected", message: "User rejected the request" })),
  }
  const h = createHarness("supersecret", { signer: decliningSigner })
  try {
    await h.send(CLIENT_PK, { id: "d1", method: "connect", params: [USER_PK, "supersecret"] })
    await h.send(CLIENT_PK, { id: "d2", method: "sign_event", params: [SIGN_EVENT] })
    const pendingId = h.pending()[0]?.id
    if (!pendingId) throw new Error("expected pending request")
    await h.bunker.approve(pendingId)
    assertEquals(h.lastResponse()?.error, "user rejected")
  } finally {
    h.stop()
  }
})

Deno.test("bunker - approve replies signing failed when the signer fails to sign", async () => {
  const localSigner = createLocalSigner(BUNKER_SK, fakeTools)
  const failingSigner: Signer = {
    ...localSigner,
    signEvent: (event) =>
      event.kind === KIND_NOSTR_CONNECT
        ? localSigner.signEvent(event)
        : Promise.resolve(failure({ type: "sign-failed", message: "wallet locked" })),
  }
  const h = createHarness("supersecret", { signer: failingSigner })
  try {
    await h.send(CLIENT_PK, { id: "f1", method: "connect", params: [USER_PK, "supersecret"] })
    await h.send(CLIENT_PK, { id: "f2", method: "sign_event", params: [SIGN_EVENT] })
    const pendingId = h.pending()[0]?.id
    if (!pendingId) throw new Error("expected pending request")
    await h.bunker.approve(pendingId)
    assertEquals(h.lastResponse()?.error, "signing failed")
  } finally {
    h.stop()
  }
})

Deno.test("bunker - onUpdate fires when a request is queued and resolved, and stops after unsubscribe", async () => {
  const h = createHarness("supersecret")
  let updates = 0
  await h.send(CLIENT_PK, { id: "u1", method: "connect", params: [USER_PK, "supersecret"] })
  const unsubscribe = h.bunker.onUpdate(() => updates++)
  try {
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
  const h = createHarness("supersecret", { now: () => clock })
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
    assertEquals(h.pending().map((p) => p.requestId), ["p2", "p1"])
  } finally {
    h.stop()
  }
})

Deno.test("bunker - queues a sign_event whose event arrives as a raw object, not a JSON string", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "obj1", method: "connect", params: [USER_PK, "supersecret"] })
    await h.send(CLIENT_PK, { id: "obj2", method: "sign_event", params: [{ kind: 1, content: "from object client" }] })
    const pending = h.pending()
    assertEquals(pending.length, 1)
    const detail = pending[0]?.detail
    assert(detail?.method === "sign_event")
    assertEquals([detail.eventToSign.kind, detail.eventToSign.content], [1, "from object client"])
  } finally {
    h.stop()
  }
})

Deno.test("bunker - answers switch_relays with the JSON list of the relays it serves on", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "sr1", method: "connect", params: [USER_PK, "supersecret"] })
    await h.send(CLIENT_PK, { id: "sr2", method: "switch_relays", params: [] })
    assertEquals(h.lastResponse(), { id: "sr2", result: JSON.stringify([RELAY]) })
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

Deno.test("bunker - sign_event with no event param replies invalid event", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "e5", method: "connect", params: [USER_PK, "supersecret"] })
    await h.send(CLIENT_PK, { id: "e6", method: "sign_event", params: [] })
    assertEquals(h.lastResponse()?.error, "invalid event")
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

for (
  const [label, event] of [
    ["a kind above 65535", { kind: 65536, content: "hi" }],
    ["a fractional kind", { kind: 1.5, content: "hi" }],
    ["a negative created_at", { kind: 1, created_at: -1, content: "hi" }],
    ["a fractional created_at", { kind: 1, created_at: 1.5, content: "hi" }],
    ["a null content", { kind: 1, content: null }],
  ] as const
) {
  Deno.test(`bunker - sign_event with ${label} replies invalid event and queues nothing`, async () => {
    const h = createHarness("supersecret")
    try {
      await h.send(CLIENT_PK, { id: "k1", method: "connect", params: [USER_PK, "supersecret"] })
      await h.send(CLIENT_PK, { id: "k2", method: "sign_event", params: [JSON.stringify(event)] })
      assertEquals({ error: h.lastResponse()?.error, pending: h.pending().length }, {
        error: "invalid event",
        pending: 0,
      })
    } finally {
      h.stop()
    }
  })
}

Deno.test("bunker - drops a request whose params is not an array without replying", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "p1", method: "ping", params: null })
    assertEquals(h.published.length, 0)
  } finally {
    h.stop()
  }
})

Deno.test("bunker - drops a request with an empty id without replying", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "", method: "ping" })
    assertEquals(h.published.length, 0)
  } finally {
    h.stop()
  }
})
