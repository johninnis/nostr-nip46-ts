/**
 * Walkthrough of the main features of @innis/nostr-nip46.
 *
 * Run with: `deno run examples/walkthrough.ts` (no permissions required — the bunker and the client
 * talk over an in-memory relay, so everything runs locally). Each step asserts what it shows.
 *
 * @module
 */

import { assert, assertEquals } from "@std/assert"
import {
  buildTextNote,
  compileFilter,
  createLocalSigner,
  defaultLocalSignerTools,
  generateSecretKey,
  parseRelayUrl,
  verifyEventSignature,
} from "@innis/nostr-core"
import type { NostrEvent } from "@innis/nostr-core"
import { createNip46Bunker, createNip46ClientSigner, parseBunkerUrl } from "../mod.ts"
import type { Nip46SubscribeOptions, Nip46Transport } from "../mod.ts"

const relay = parseRelayUrl("wss://relay.example")
assert(relay !== null)

const subscribers = new Set<Nip46SubscribeOptions>()
const inMemoryRelay: Nip46Transport = {
  subscribe: (options) => {
    subscribers.add(options)
    options.onStatus?.("active")
    return { abort: () => subscribers.delete(options) }
  },
  publish: (_relayUrl, event: NostrEvent) => {
    for (const subscriber of subscribers) {
      if (compileFilter(subscriber.filter).matches(event)) queueMicrotask(() => subscriber.onEvent(event))
    }
    return Promise.resolve({ ok: true })
  },
}

const user = createLocalSigner(generateSecretKey())
const userKey = await user.getPublicKey()
assert(userKey.success)

const bunker = createNip46Bunker({ transport: inMemoryRelay, signer: user, isAuthorised: () => true })
bunker.start(userKey.value, [relay], "one-time-secret")
const pasted = parseBunkerUrl(bunker.getBunkerUrl() ?? "")
assert(pasted !== null)
assertEquals(pasted.remoteSignerPubkey, userKey.value)

const client = createNip46ClientSigner({
  tools: defaultLocalSignerTools,
  transport: inMemoryRelay,
  clientSecretKey: generateSecretKey(),
  remoteSignerPubkey: pasted.remoteSignerPubkey,
  relayUrls: pasted.relays,
  secret: pasted.secret,
})
assertEquals((await client.connect()).success, true)
assertEquals(await client.getPublicKey(), { success: true, value: userKey.value })
assertEquals(bunker.getBunkerUrl(), null)

const signed = await client.signEvent(buildTextNote("signed by the bunker", 1700000000))
assert(signed.success && signed.value.pubkey === userKey.value && verifyEventSignature(signed.value))

client.disconnect()
bunker.stop()
