import { assert, assertEquals, assertThrows } from "@std/assert"
import type { NostrEvent, PublicKey, UnsignedEvent } from "@innis/nostr-core"
import { createLocalSigner, failure, InvalidArgumentError, KIND_NOSTR_CONNECT, now, ok } from "@innis/nostr-core"
import { publicKeyFixture, relayUrlFixture } from "@innis/nostr-core/testing"
import { createNip46Bunker } from "../src/bunker.ts"
import { createNip46ClientSigner } from "../src/client-signer.ts"
import { formatNostrConnectUrl, parseNostrConnectUrl } from "../src/nostr-connect-url.ts"
import { createCapturingTransport, createLoopbackTransport, flush } from "./_helpers/fakes.ts"
import {
  BUNKER_PK,
  BUNKER_SK,
  CLIENT_PK,
  CLIENT_SK,
  fakeTools,
  isConnectRequestBody,
  makeSigned,
} from "./_helpers/client-harness.ts"

const RELAY = relayUrlFixture("wss://client.example")
const SECRET = "0s8j2djs"
const STRANGER_PK = publicKeyFixture("d".repeat(64))

const pairingClient = (timeoutMs = 30_000): {
  readonly signer: ReturnType<typeof createNip46ClientSigner>
  readonly capturing: ReturnType<typeof createCapturingTransport>
} => {
  const capturing = createCapturingTransport()
  const signer = createNip46ClientSigner({
    tools: fakeTools,
    transport: capturing.transport,
    clientSecretKey: CLIENT_SK,
    remoteSignerPubkey: null,
    relayUrls: [RELAY],
    secret: SECRET,
    timeoutMs,
    verifyEventSignature: () => true,
    generateRequestId: (() => {
      let n = 0
      return () => `req-${++n}`
    })(),
  })
  return { signer, capturing }
}

const envelopeFrom = (author: PublicKey, body: Record<string, string>): NostrEvent =>
  makeSigned({
    kind: KIND_NOSTR_CONNECT,
    created_at: now(),
    tags: [["p", CLIENT_PK]],
    content: fakeTools.nip44Encrypt(new Uint8Array(32), JSON.stringify(body)),
  }, author)

const requestIdOf = (event: NostrEvent | undefined): string => {
  assert(event !== undefined)
  const body: unknown = JSON.parse(fakeTools.nip44Decrypt(new Uint8Array(32), event.content))
  assert(typeof body === "object" && body !== null && "id" in body && typeof body.id === "string")
  return body.id
}

Deno.test("nostrconnect client - listens for any signer addressing it and publishes nothing while pairing", async () => {
  const { signer, capturing } = pairingClient()
  const connecting = signer.connect()
  await flush()
  assertEquals({ filter: capturing.subscriptions[0]?.filter.authors, published: capturing.published.length }, {
    filter: undefined,
    published: 0,
  })
  signer.disconnect()
  await connecting
})

Deno.test("nostrconnect client - learns the remote signer from the connect response that echoes its secret", async () => {
  const { signer, capturing } = pairingClient()
  const connecting = signer.connect()
  await flush()
  capturing.deliver(envelopeFrom(BUNKER_PK, { id: "anything", result: SECRET }))
  await flush()
  capturing.deliver(envelopeFrom(BUNKER_PK, { id: requestIdOf(capturing.published[0]), result: "null" }))
  await flush()
  const request = capturing.published[1]
  assert(request !== undefined)
  const body: unknown = JSON.parse(fakeTools.nip44Decrypt(new Uint8Array(32), request.content))
  assert(isConnectRequestBody(body))
  assertEquals({ method: body.method, to: request.tags, signer: signer.getRemoteSignerPubkey() }, {
    method: "get_public_key",
    to: [["p", BUNKER_PK]],
    signer: BUNKER_PK,
  })
  capturing.deliver(envelopeFrom(BUNKER_PK, { id: requestIdOf(request), result: "f".repeat(64) }))
  assertEquals(await connecting, ok(undefined))
})

Deno.test("nostrconnect client - asks the learned signer to switch relays before anything else", async () => {
  const { signer, capturing } = pairingClient()
  const connecting = signer.connect()
  await flush()
  capturing.deliver(envelopeFrom(BUNKER_PK, { id: "anything", result: SECRET }))
  await flush()
  const request = capturing.published[0]
  assert(request !== undefined)
  const body: unknown = JSON.parse(fakeTools.nip44Decrypt(new Uint8Array(32), request.content))
  assert(isConnectRequestBody(body))
  assertEquals({ method: body.method, to: request.tags }, { method: "switch_relays", to: [["p", BUNKER_PK]] })
  signer.disconnect()
  await connecting
})

Deno.test("nostrconnect client - ignores a connect response whose secret does not match", async () => {
  const { signer, capturing } = pairingClient(50)
  const connecting = signer.connect()
  await flush()
  capturing.deliver(envelopeFrom(STRANGER_PK, { id: "x", result: "guessed" }))
  assertEquals(await connecting, failure({ type: "disconnected", message: "bunker pairing timed out" }))
  assertEquals(signer.getRemoteSignerPubkey(), null)
})

Deno.test("nostrconnect client - once paired, ignores responses from any other author", async () => {
  const { signer, capturing } = pairingClient(50)
  const connecting = signer.connect()
  await flush()
  capturing.deliver(envelopeFrom(BUNKER_PK, { id: "a", result: SECRET }))
  await flush()
  capturing.deliver(envelopeFrom(STRANGER_PK, { id: requestIdOf(capturing.published[0]), result: "e".repeat(64) }))
  assertEquals(await connecting, failure({ type: "disconnected", message: "bunker request timed out" }))
})

Deno.test("nostrconnect client - disconnect ends a pairing still waiting for the signer", async () => {
  const { signer } = pairingClient()
  const connecting = signer.connect()
  signer.disconnect()
  assertEquals(await connecting, failure({ type: "disconnected", message: "bunker disconnected" }))
})

Deno.test("nostrconnect client - a request before pairing fails without publishing", async () => {
  const { signer, capturing } = pairingClient()
  const result = await signer.nip44Encrypt(STRANGER_PK, "hi")
  assertEquals({ type: result.success ? null : result.error.type, published: capturing.published.length }, {
    type: "disconnected",
    published: 0,
  })
})

Deno.test("nostrconnect client - cannot be built without a secret for the signer to echo", () => {
  assertThrows(
    () =>
      createNip46ClientSigner({
        tools: fakeTools,
        transport: createCapturingTransport().transport,
        clientSecretKey: CLIENT_SK,
        remoteSignerPubkey: null,
        relayUrls: [RELAY],
        secret: null,
      }),
    InvalidArgumentError,
    "secret",
  )
})

Deno.test("nostrconnect pairing round-trips between the client signer and the bunker", async () => {
  const transport = createLoopbackTransport()
  const bunker = createNip46Bunker({
    transport,
    signer: createLocalSigner(BUNKER_SK, fakeTools),
    isAuthorised: () => true,
  })
  bunker.start(BUNKER_PK, [relayUrlFixture("wss://signer.example")], "bunker-secret")
  const client = createNip46ClientSigner({
    tools: fakeTools,
    transport,
    clientSecretKey: CLIENT_SK,
    remoteSignerPubkey: null,
    relayUrls: [RELAY],
    secret: SECRET,
    verifyEventSignature: () => true,
  })
  try {
    const connecting = client.connect()
    const pasted = parseNostrConnectUrl(formatNostrConnectUrl({
      clientPubkey: client.getClientPubkey(),
      relays: [RELAY],
      secret: SECRET,
      perms: ["sign_event:1"],
      name: "Round Trip",
      url: null,
      image: null,
    }))
    assert(pasted !== null)
    await bunker.acceptNostrConnect(pasted)
    assertEquals(await connecting, ok(undefined))
    const unsigned: UnsignedEvent = { kind: 1, created_at: 100, tags: [], content: "paired" }
    const signed = await client.signEvent(unsigned)
    assertEquals({
      user: await client.getPublicKey(),
      content: signed.success && signed.value.content,
      relays: client.getRelayUrls(),
    }, {
      user: ok(BUNKER_PK),
      content: "paired",
      relays: [relayUrlFixture("wss://signer.example")],
    })
  } finally {
    client.disconnect()
    bunker.stop()
  }
})
