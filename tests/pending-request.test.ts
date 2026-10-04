import { assertEquals } from "@std/assert"
import { createLocalSigner, ok, serialiseEvent, type Signer } from "@innis/nostr-core"
import { answerDetail } from "../src/pending-request.ts"
import { BUNKER_SK, fakeTools, USER_PK } from "./_helpers/bunker-harness.ts"

const localSigner = createLocalSigner(BUNKER_SK, fakeTools)

const addingSigner: Signer = {
  ...localSigner,
  signEvent: async (template) => {
    const signed = await localSigner.signEvent(template)
    return signed.success ? ok({ ...signed.value, relays: ["wss://relay.example"] }) : signed
  },
}

Deno.test("answerDetail - a signed event is answered as its seven NIP-01 fields, whatever else the signer returns", async () => {
  const eventToSign = { kind: 1, created_at: 1700000000, tags: [], content: "hi" }
  const answer = await answerDetail({ method: "sign_event", eventToSign }, "s1", {
    signer: addingSigner,
    userPubkey: USER_PK,
    now: () => 1700000000,
  })
  const signed = await localSigner.signEvent(eventToSign)
  if (!signed.success) throw new Error(signed.error.message)
  assertEquals(answer, { id: "s1", result: serialiseEvent(signed.value) })
})
