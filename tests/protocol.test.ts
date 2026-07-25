import { assert, assertEquals } from "@std/assert"
import type { NostrEvent, RelayUrl } from "@innis/nostr-core"
import { createLocalSigner, now, parsePublicKey, parseRelayUrl } from "@innis/nostr-core"
import { Nip46SendError, sendEnvelope } from "../src/protocol.ts"
import type { Nip46Transport } from "../src/transport.ts"
import { createCapturingTransport, makeFakeTools } from "./_helpers/fakes.ts"

const SENDER_SK = new Uint8Array(32).fill(2)
const SENDER_PK = parsePublicKey("b".repeat(64))
const PEER_PK = parsePublicKey("c".repeat(64))
const RELAY_A = parseRelayUrl("ws://127.0.0.1:1")
const RELAY_B = parseRelayUrl("ws://127.0.0.1:2")

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
  assert(result.error instanceof Nip46SendError)
  assertEquals(result.error.tag, "delivery-failed")
})

Deno.test("sendEnvelope - fails as delivery-failed when there is no relay to publish to", async () => {
  const { transport, published } = createCapturingTransport()

  const result = await send(transport, [])

  assert(!result.success)
  assertEquals(result.error.tag, "delivery-failed")
  assertEquals(published.length, 0)
})

Deno.test("sendEnvelope - one accepting relay is enough", async () => {
  const attempted: Array<RelayUrl> = []
  const transport: Nip46Transport = {
    subscribe: () => ({ abort: () => {} }),
    publish: (url: RelayUrl, _event: NostrEvent) => {
      attempted.push(url)
      return url === RELAY_B ? Promise.reject(new Error("socket dead")) : Promise.resolve({ ok: true })
    },
  }

  const result = await send(transport, [RELAY_A, RELAY_B])

  assert(result.success)
  assertEquals(attempted, [RELAY_A, RELAY_B])
})
