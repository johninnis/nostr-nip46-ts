import { assertEquals } from "@std/assert"
import type { UnsignedEvent } from "@innis/nostr-core"
import { failure, ok } from "@innis/nostr-core"
import { relayUrlFixture } from "@innis/nostr-core/testing"
import { flush } from "./_helpers/fakes.ts"
import { BUNKER_PK, createHarness, RELAY, USER_PK } from "./_helpers/client-harness.ts"

const NIP_RELAY_1 = relayUrlFixture("wss://relay1.example.com")
const NIP_RELAY_2 = relayUrlFixture("wss://relay2.example2.com")
const METADATA = { name: "My Client", url: "https://client.example", image: null }

const connectThroughHandshake = async (
  h: ReturnType<typeof createHarness>,
  switchReply: { result?: string | null; error?: string | null },
): Promise<void> => {
  h.injectBunkerResponse(0, { result: "ack" })
  await flush()
  h.injectBunkerResponse(1, switchReply)
  await flush()
  h.injectBunkerResponse(2, { result: USER_PK })
}

Deno.test("connect - sends the client metadata fourth, after an empty permission list", async () => {
  const h = createHarness({ secret: "s1", clientMetadata: METADATA })
  const connecting = h.signer.connect()
  await flush()
  assertEquals(h.requestAt(0).params, [
    BUNKER_PK,
    "s1",
    "",
    JSON.stringify({ name: "My Client", url: "https://client.example" }),
  ])
  h.signer.disconnect()
  await connecting
})

Deno.test("connect - sends an empty secret before the metadata when the bunker url carried none", async () => {
  const h = createHarness({ clientMetadata: { name: "My Client", url: null, image: null } })
  const connecting = h.signer.connect()
  await flush()
  assertEquals(h.requestAt(0).params, [BUNKER_PK, "", "", JSON.stringify({ name: "My Client" })])
  h.signer.disconnect()
  await connecting
})

Deno.test("connect - metadata with nothing in it is not sent", async () => {
  const h = createHarness({ secret: "s1", clientMetadata: { name: null, url: null, image: null } })
  const connecting = h.signer.connect()
  await flush()
  assertEquals(h.requestAt(0).params, [BUNKER_PK, "s1"])
  h.signer.disconnect()
  await connecting
})

Deno.test("connect - sends the requested permissions third", async () => {
  const h = createHarness({ secret: "s1", requestedPerms: ["sign_event:1", "nip44_encrypt"] })
  const connecting = h.signer.connect()
  await flush()
  assertEquals(h.requestAt(0).params, [BUNKER_PK, "s1", "sign_event:1,nip44_encrypt"])
  h.signer.disconnect()
  await connecting
})

Deno.test("connect - keeps the empty permission list before the metadata", async () => {
  const h = createHarness({ secret: "s1", clientMetadata: METADATA, requestedPerms: ["sign_event:1"] })
  const connecting = h.signer.connect()
  await flush()
  assertEquals(h.requestAt(0).params, [
    BUNKER_PK,
    "s1",
    "sign_event:1",
    JSON.stringify({ name: "My Client", url: "https://client.example" }),
  ])
  h.signer.disconnect()
  await connecting
})

Deno.test("connect - asks the bunker to switch relays as soon as it acknowledges the connection", async () => {
  const h = createHarness({ secret: "s1" })
  const connecting = h.signer.connect()
  await flush()
  h.injectBunkerResponse(0, { result: "ack" })
  await flush()
  assertEquals({ method: h.requestAt(1).method, params: h.requestAt(1).params }, {
    method: "switch_relays",
    params: [],
  })
  h.signer.disconnect()
  await connecting
})

Deno.test("connect - adopts the relays switch_relays returns for every later request", async () => {
  const h = createHarness({ secret: "s1" })
  const connecting = h.signer.connect()
  await flush()
  await connectThroughHandshake(h, { result: JSON.stringify([NIP_RELAY_1, NIP_RELAY_2]) })
  assertEquals(await connecting, ok(undefined))
  assertEquals({ getPublicKeySentTo: h.publishedRelays.slice(2), relays: h.signer.getRelayUrls() }, {
    getPublicKeySentTo: [NIP_RELAY_1, NIP_RELAY_2],
    relays: [NIP_RELAY_1, NIP_RELAY_2],
  })
})

Deno.test("connect - listens for responses on the switched relays only", async () => {
  const h = createHarness({ secret: "s1" })
  const connecting = h.signer.connect()
  await flush()
  await connectThroughHandshake(h, { result: JSON.stringify([NIP_RELAY_1]) })
  await connecting
  assertEquals({ active: h.activeSubscriptionCount(), relays: h.subscriptions.at(-1)?.relays }, {
    active: 1,
    relays: [NIP_RELAY_1],
  })
  h.signer.disconnect()
})

Deno.test("connect - keeps its own relays when switch_relays returns null", async () => {
  const h = createHarness({ secret: "s1" })
  const connecting = h.signer.connect()
  await flush()
  await connectThroughHandshake(h, { result: "null" })
  assertEquals(
    { connected: await connecting, relays: h.signer.getRelayUrls(), subscriptions: h.subscriptions.length },
    {
      connected: ok(undefined),
      relays: [RELAY],
      subscriptions: 1,
    },
  )
})

Deno.test("connect - keeps its own relays when switch_relays answers with a JSON null result", async () => {
  const h = createHarness({ secret: "s1" })
  const connecting = h.signer.connect()
  await flush()
  await connectThroughHandshake(h, { result: null })
  assertEquals({ connected: await connecting, relays: h.signer.getRelayUrls() }, {
    connected: ok(undefined),
    relays: [RELAY],
  })
})

Deno.test("connect - keeps its own relays and connects when the bunker refuses switch_relays", async () => {
  const h = createHarness({ secret: "s1" })
  const connecting = h.signer.connect()
  await flush()
  await connectThroughHandshake(h, { error: "unsupported method: switch_relays" })
  assertEquals({ connected: await connecting, relays: h.signer.getRelayUrls() }, {
    connected: ok(undefined),
    relays: [RELAY],
  })
})

Deno.test("connect - keeps its own relays when switch_relays names no usable relay", async () => {
  const h = createHarness({ secret: "s1" })
  const connecting = h.signer.connect()
  await flush()
  await connectThroughHandshake(h, { result: JSON.stringify(["not a relay", 7]) })
  assertEquals({ connected: await connecting, relays: h.signer.getRelayUrls() }, {
    connected: ok(undefined),
    relays: [RELAY],
  })
})

Deno.test("connect - a restored session does not ask to switch relays", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })
  assertEquals({ connected: await h.signer.connect(), published: h.published.length }, {
    connected: ok(undefined),
    published: 0,
  })
  h.signer.disconnect()
})

Deno.test("logout - sends logout and resolves once the bunker acknowledges", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })
  const loggingOut = h.signer.logout()
  await flush()
  const request = h.requestAt(0)
  h.injectBunkerResponse(0, { result: "ack" })
  assertEquals({ result: await loggingOut, method: request.method, params: request.params }, {
    result: ok(undefined),
    method: "logout",
    params: [],
  })
})

Deno.test("logout - tears the session down once acknowledged", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })
  const loggingOut = h.signer.logout()
  await flush()
  h.injectBunkerResponse(0, { result: "ack" })
  await loggingOut
  const unsigned: UnsignedEvent = { kind: 1, created_at: 100, tags: [], content: "hello" }
  assertEquals({ active: h.activeSubscriptionCount(), sign: await h.signer.signEvent(unsigned) }, {
    active: 0,
    sign: failure({ type: "disconnected", message: "bunker not connected — call connect() before signEvent" }),
  })
})

Deno.test("logout - an answer other than ack is a failure, and the session is torn down anyway", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })
  const loggingOut = h.signer.logout()
  await flush()
  h.injectBunkerResponse(0, { result: "pong" })
  assertEquals({ result: await loggingOut, active: h.activeSubscriptionCount() }, {
    result: failure({ type: "disconnected", message: "bunker answered logout with pong rather than ack" }),
    active: 0,
  })
})

Deno.test("logout - a bunker error is a failure, and the session is torn down anyway", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })
  const loggingOut = h.signer.logout()
  await flush()
  h.injectBunkerResponse(0, { error: "not connected" })
  assertEquals({ result: await loggingOut, active: h.activeSubscriptionCount() }, {
    result: failure({ type: "disconnected", message: "not connected" }),
    active: 0,
  })
})

Deno.test("logout - a transport fault still tears the session down before rejecting", async () => {
  const h = createHarness({ initialUserPubkey: USER_PK })
  h.breakPublishes()
  const outcome = await h.signer.logout().then(() => "resolved", () => "rejected")
  assertEquals({ outcome, active: h.activeSubscriptionCount() }, { outcome: "rejected", active: 0 })
})
