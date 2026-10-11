import { assertEquals } from "@std/assert"
import type { NostrEvent, Result, SignerFailure, UnsignedEvent } from "@innis/nostr-core"
import { failure, KIND_NOSTR_CONNECT } from "@innis/nostr-core"
import { flush } from "./_helpers/fakes.ts"
import { createHarness, makeSigned, USER_PK } from "./_helpers/client-harness.ts"

const TEMPLATE: UnsignedEvent = {
  kind: 1,
  created_at: 100,
  tags: [["e", "a".repeat(64), "", "root"], ["t", "x"]],
  content: "hello",
}

const DIFFERS_FROM_TEMPLATE: Result<NostrEvent, SignerFailure> = failure({
  type: "sign-failed",
  message: "Signer returned an event that differs from the template it was asked to sign",
})

const signedAs = async (
  template: UnsignedEvent,
  returned: UnsignedEvent,
  opts: { readonly pubkey?: string; readonly verifyEventSignature?: (event: NostrEvent) => boolean } = {},
): Promise<Result<NostrEvent, SignerFailure>> => {
  const h = createHarness({
    initialUserPubkey: USER_PK,
    verifyEventSignature: opts.verifyEventSignature ?? ((): boolean => true),
  })
  const signing = h.signer.signEvent(template)
  await flush()
  h.injectBunkerResponse(0, { result: JSON.stringify(makeSigned(returned, opts.pubkey ?? USER_PK)) })
  return signing
}

for (
  const [label, returned] of [
    ["another kind", { ...TEMPLATE, kind: 7 }],
    ["other content", { ...TEMPLATE, content: "hello!" }],
    ["another created_at", { ...TEMPLATE, created_at: 101 }],
    ["a tag added", { ...TEMPLATE, tags: [...TEMPLATE.tags, ["client", "bunker"]] }],
    ["a tag removed", { ...TEMPLATE, tags: TEMPLATE.tags.slice(0, 1) }],
    ["its tags reordered", { ...TEMPLATE, tags: [...TEMPLATE.tags].reverse() }],
    ["a tag with an element added", { ...TEMPLATE, tags: [["e", "a".repeat(64), "", "root", "x"], ["t", "x"]] }],
    ["a tag with an element changed", { ...TEMPLATE, tags: [["e", "a".repeat(64), "", "reply"], ["t", "x"]] }],
  ] as const
) {
  Deno.test(`signEvent - refuses a bunker-signed event with ${label} as differing from the template`, async () => {
    assertEquals(await signedAs(TEMPLATE, returned), DIFFERS_FROM_TEMPLATE)
  })
}

Deno.test("signEvent - accepts an addressable event carrying the d tag the client added to the template it sent", async () => {
  const template: UnsignedEvent = { kind: 30023, created_at: 100, tags: [], content: "article" }
  const result = await signedAs(template, { ...template, tags: [["d", ""]] })
  assertEquals(result.success, true)
})

Deno.test("signEvent - refuses an addressable event without the d tag the client added to the template it sent", async () => {
  const template: UnsignedEvent = { kind: 30023, created_at: 100, tags: [], content: "article" }
  assertEquals(await signedAs(template, template), DIFFERS_FROM_TEMPLATE)
})

Deno.test("signEvent - reports a pubkey mismatch before a difference from the template", async () => {
  const result = await signedAs(TEMPLATE, { ...TEMPLATE, content: "changed" }, { pubkey: "d".repeat(64) })
  assertEquals(result.success ? null : result.error.type, "pubkey-mismatch")
})

Deno.test("signEvent - reports a difference from the template before an invalid signature", async () => {
  const result = await signedAs(TEMPLATE, { ...TEMPLATE, content: "changed" }, {
    verifyEventSignature: (event) => event.kind === KIND_NOSTR_CONNECT,
  })
  assertEquals(result, DIFFERS_FROM_TEMPLATE)
})
