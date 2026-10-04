import { assertEquals } from "@std/assert"
import { createLocalSigner } from "@innis/nostr-core"
import { publicKeyFixture, relayUrlFixture } from "@innis/nostr-core/testing"
import { createNip46Bunker } from "../src/bunker.ts"
import type { NostrConnectUrl } from "../src/nostr-connect-url.ts"
import { createCapturingTransport, flush } from "./_helpers/fakes.ts"
import {
  ATTACKER_PK,
  BUNKER_SK,
  CLIENT_PK,
  createHarness,
  fakeTools,
  grantAllButSigning,
  RELAY,
  USER_PK,
} from "./_helpers/bunker-harness.ts"

const CLIENT_RELAY = relayUrlFixture("wss://client.example")

const pairing = (overrides: Partial<NostrConnectUrl> = {}): NostrConnectUrl => ({
  clientPubkey: CLIENT_PK,
  relays: [CLIENT_RELAY, RELAY],
  secret: "0s8j2djs",
  perms: [],
  name: "My Client",
  url: null,
  image: null,
  ...overrides,
})

Deno.test("bunker - accepting a nostrconnect url answers the client with a connect response carrying its secret", async () => {
  const h = createHarness("supersecret")
  try {
    await h.bunker.acceptNostrConnect(pairing())
    const response = h.lastResponse()
    assertEquals({ result: response?.result, error: response?.error, p: h.published[0]?.tags }, {
      result: "0s8j2djs",
      error: undefined,
      p: [["p", CLIENT_PK]],
    })
  } finally {
    h.stop()
  }
})

Deno.test("bunker - a client paired by nostrconnect is connected without sending connect", async () => {
  const h = createHarness("supersecret")
  try {
    await h.bunker.acceptNostrConnect(pairing())
    await h.send(CLIENT_PK, { id: "g", method: "get_public_key" })
    assertEquals(h.lastResponse(), { id: "g", result: USER_PK })
  } finally {
    h.stop()
  }
})

Deno.test("bunker - a paired client is answered on the signer's relays and its own", async () => {
  const h = createHarness("supersecret")
  try {
    await h.bunker.acceptNostrConnect(pairing())
    assertEquals([...h.publishedRelays].sort(), [CLIENT_RELAY, RELAY].sort())
  } finally {
    h.stop()
  }
})

Deno.test("bunker - an unpaired client is answered on the signer's relays only", async () => {
  const h = createHarness("supersecret")
  try {
    await h.bunker.acceptNostrConnect(pairing())
    const before = h.publishedRelays.length
    await h.send(ATTACKER_PK, { id: "p", method: "ping" })
    assertEquals(h.publishedRelays.slice(before), [RELAY])
  } finally {
    h.stop()
  }
})

Deno.test("bunker - pairing subscribes only on the relays it is not already listening on", async () => {
  const h = createHarness("supersecret")
  try {
    await h.bunker.acceptNostrConnect(pairing())
    await h.bunker.acceptNostrConnect(pairing({ clientPubkey: ATTACKER_PK }))
    assertEquals(h.subscriptions.map((subscription) => subscription.relays), [[RELAY], [CLIENT_RELAY]])
  } finally {
    h.stop()
  }
})

Deno.test("bunker - stop cancels the pairing subscriptions as well as its own", async () => {
  const h = createHarness("supersecret")
  await h.bunker.acceptNostrConnect(pairing())
  h.stop()
  assertEquals(h.activeSubscriptionCount(), 0)
})

Deno.test("bunker - switch_relays reports the signer's own relays to a client paired on others", async () => {
  const h = createHarness("supersecret")
  try {
    await h.bunker.acceptNostrConnect(pairing({ relays: [CLIENT_RELAY] }))
    await h.send(CLIENT_PK, { id: "s", method: "switch_relays" })
    assertEquals(h.lastResponse(), { id: "s", result: JSON.stringify([RELAY]) })
  } finally {
    h.stop()
  }
})

Deno.test("bunker - the permissions a nostrconnect url requests are not granted by pairing", async () => {
  const h = createHarness("supersecret")
  try {
    await h.bunker.acceptNostrConnect(pairing({ perms: ["sign_event"] }))
    await h.send(CLIENT_PK, { id: "s", method: "sign_event", params: [JSON.stringify({ kind: 1, content: "hi" })] })
    assertEquals(h.pending().map((request) => request.requestId), ["s"])
  } finally {
    h.stop()
  }
})

Deno.test("bunker - restoring a pairing reconnects the client without echoing the secret", async () => {
  const h = createHarness("supersecret")
  try {
    const restored = h.bunker.restorePairing(CLIENT_PK, [CLIENT_RELAY])
    const publishedOnRestore = h.published.length
    await h.send(CLIENT_PK, { id: "g", method: "get_public_key" })
    assertEquals({ restored, publishedOnRestore, response: h.lastResponse() }, {
      restored: true,
      publishedOnRestore: 0,
      response: { id: "g", result: USER_PK },
    })
  } finally {
    h.stop()
  }
})

Deno.test("bunker - pairing before start publishes nothing and reports why", async () => {
  const capturing = createCapturingTransport()
  const bunker = createNip46Bunker({
    transport: capturing.transport,
    signer: createLocalSigner(BUNKER_SK, fakeTools),
    isAuthorised: grantAllButSigning,
  })
  const accepted = await bunker.acceptNostrConnect(pairing())
  await flush()
  assertEquals({
    accepted: accepted.success ? null : accepted.error.type,
    restored: bunker.restorePairing(publicKeyFixture("e".repeat(64)), [RELAY]),
    published: capturing.published.length,
  }, { accepted: "delivery-failed", restored: false, published: 0 })
})
