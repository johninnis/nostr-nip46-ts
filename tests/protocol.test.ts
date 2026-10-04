import { assert, assertEquals, assertRejects } from "@std/assert"
import type { NostrEvent, RelayUrl } from "@innis/nostr-core"
import { createLocalSigner, failure, now, ok } from "@innis/nostr-core"
import { createStubSigner, publicKeyFixture, relayUrlFixture } from "@innis/nostr-core/testing"
import { decryptEnvelopeJson, sendEnvelope } from "../src/protocol.ts"
import type { Nip46Transport } from "../src/transport.ts"
import { createCapturingTransport, makeFakeTools } from "./_helpers/fakes.ts"

const SENDER_SK = new Uint8Array(32).fill(2)
const SENDER_PK = publicKeyFixture("b".repeat(64))
const PEER_PK = publicKeyFixture("c".repeat(64))
const RELAY_A = relayUrlFixture("ws://127.0.0.1:1")
const RELAY_B = relayUrlFixture("ws://127.0.0.1:2")

const fakeTools = makeFakeTools(() => SENDER_PK)
const signer = createLocalSigner(SENDER_SK, fakeTools)

const send = (transport: Nip46Transport, relays: ReadonlyArray<RelayUrl>): ReturnType<typeof sendEnvelope> =>
  sendEnvelope({ signer, transport, relays, peerPubkey: PEER_PK, payload: { id: "1" }, now })

Deno.test("sendEnvelope - succeeds when a relay accepts the envelope", async () => {
  const { transport, published } = createCapturingTransport()

  const result = await send(transport, [RELAY_A])

  assert(result.success)
  assertEquals(published.length, 1)
})

Deno.test("sendEnvelope - fails as delivery-failed when no relay accepts the envelope", async () => {
  const capturing = createCapturingTransport()
  capturing.rejectPublishes()

  const result = await send(capturing.transport, [RELAY_A, RELAY_B])

  assert(!result.success)
  assertEquals(result.error, { type: "delivery-failed", message: "no relay accepted the NIP-46 envelope (tried 2)" })
})

Deno.test("sendEnvelope - fails as delivery-failed when there is no relay to publish to", async () => {
  const { transport, published } = createCapturingTransport()

  const result = await send(transport, [])

  assert(!result.success)
  assertEquals(result.error.type, "delivery-failed")
  assertEquals(published.length, 0)
})

Deno.test("sendEnvelope - fails as sign-failed without publishing when the signer does not sign the envelope", async () => {
  const { transport, published } = createCapturingTransport()
  const decliningSigner = createStubSigner({
    pubkey: SENDER_PK,
    nip44Encrypt: (_pubkey, plaintext) => ok(plaintext),
    signEvent: () => failure({ type: "rejected", message: "user rejected" }),
  })

  const result = await sendEnvelope({
    signer: decliningSigner,
    transport,
    relays: [RELAY_A],
    peerPubkey: PEER_PK,
    payload: { id: "1" },
    now,
  })

  assertEquals(
    result,
    failure({ type: "sign-failed", message: "failed to sign NIP-46 envelope (rejected): user rejected" }),
  )
  assertEquals(published.length, 0)
})

Deno.test("sendEnvelope - one accepting relay is enough", async () => {
  const attempted: Array<RelayUrl> = []
  const transport: Nip46Transport = {
    subscribe: () => ({ abort: () => {} }),
    publish: (url: RelayUrl, _event: NostrEvent) => {
      attempted.push(url)
      return Promise.resolve({ ok: url === RELAY_A })
    },
  }

  const result = await send(transport, [RELAY_A, RELAY_B])

  assert(result.success)
  assertEquals(attempted, [RELAY_A, RELAY_B])
})

Deno.test("sendEnvelope - a publish that rejects is a transport fault and propagates", async () => {
  const transport: Nip46Transport = {
    subscribe: () => ({ abort: () => {} }),
    publish: (url: RelayUrl) =>
      url === RELAY_B ? Promise.reject(new Error("socket dead")) : Promise.resolve({ ok: true }),
  }

  await assertRejects(() => send(transport, [RELAY_A, RELAY_B]), Error, "socket dead")
})

const decryptingSigner = (calls: Array<string>): ReturnType<typeof createStubSigner> =>
  createStubSigner({
    pubkey: SENDER_PK,
    nip04Decrypt: () => {
      calls.push("nip04")
      return ok('{"id":"1"}')
    },
    nip44Decrypt: () => {
      calls.push("nip44")
      return ok('{"id":"1"}')
    },
  })

Deno.test("decryptEnvelopeJson - decrypts a NIP-04 envelope with NIP-04 only", async () => {
  const calls: Array<string> = []

  const decoded = await decryptEnvelopeJson({
    signer: decryptingSigner(calls),
    peerPubkey: PEER_PK,
    ciphertext: "Y2lwaGVy?iv=aXY=",
  })

  assertEquals({ cipher: decoded?.cipher, calls }, { cipher: "nip04", calls: ["nip04"] })
})

Deno.test("decryptEnvelopeJson - decrypts any other envelope with NIP-44 only", async () => {
  const calls: Array<string> = []

  const decoded = await decryptEnvelopeJson({
    signer: decryptingSigner(calls),
    peerPubkey: PEER_PK,
    ciphertext: "AgQ=",
  })

  assertEquals({ cipher: decoded?.cipher, calls }, { cipher: "nip44", calls: ["nip44"] })
})
