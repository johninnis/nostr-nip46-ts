import { assert, assertEquals } from "@std/assert"
import { createLocalSigner, parsePublicKey, parseRelayUrl } from "@innis/nostr-core"
import { createNip46Bunker } from "../src/bunker.ts"
import { createCapturingTransport, makeFakeTools } from "./_helpers/fakes.ts"

const BUNKER_SK = new Uint8Array(32).fill(2)
const BUNKER_PK = parsePublicKey("b".repeat(64))
const USER_PK = parsePublicKey("f".repeat(64))
const RELAY = parseRelayUrl("ws://127.0.0.1:0")

const fakeTools = makeFakeTools(() => BUNKER_PK)
const makeBunker = (transport: ReturnType<typeof createCapturingTransport>["transport"]) =>
  createNip46Bunker({ transport, signer: createLocalSigner(BUNKER_SK, fakeTools) })

Deno.test("subscription status is closed before start", () => {
  const { transport } = createCapturingTransport()
  assertEquals(makeBunker(transport).getSubscriptionStatus(), "closed")
})

Deno.test("subscription status reflects transport transitions and notifies", () => {
  const { transport, emitStatus } = createCapturingTransport()
  const bunker = makeBunker(transport)

  let updates = 0
  bunker.onUpdate(() => updates++)
  bunker.start(USER_PK, [RELAY], "supersecret")

  emitStatus("pending")
  assertEquals(bunker.getSubscriptionStatus(), "pending")

  emitStatus("active")
  assertEquals(bunker.getSubscriptionStatus(), "active")

  assert(updates >= 2)
  bunker.stop()
})

Deno.test("subscription status returns to closed after stop", () => {
  const { transport, emitStatus } = createCapturingTransport()
  const bunker = makeBunker(transport)

  bunker.start(USER_PK, [RELAY], "supersecret")
  emitStatus("active")
  assertEquals(bunker.getSubscriptionStatus(), "active")

  bunker.stop()
  assertEquals(bunker.getSubscriptionStatus(), "closed")
})
