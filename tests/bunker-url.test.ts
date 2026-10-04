import { assertEquals } from "@std/assert"
import { publicKeyFixture, relayUrlFixture } from "@innis/nostr-core/testing"
import { formatBunkerUrl, parseBunkerUrl } from "../src/bunker-url.ts"

const PK = "a".repeat(64)

Deno.test("parseBunkerUrl - valid URL with single relay and secret", () => {
  const result = parseBunkerUrl(`bunker://${PK}?relay=wss%3A%2F%2Frelay.example&secret=abc123`)
  assertEquals(result?.remoteSignerPubkey, PK)
  assertEquals(result?.relays, [relayUrlFixture("wss://relay.example")])
  assertEquals(result?.secret, "abc123")
})

Deno.test("parseBunkerUrl - multiple relay params preserved in order", () => {
  const result = parseBunkerUrl(`bunker://${PK}?relay=wss%3A%2F%2Fa.example&relay=wss%3A%2F%2Fb.example&secret=x`)
  assertEquals(result?.relays, [relayUrlFixture("wss://a.example"), relayUrlFixture("wss://b.example")])
})

Deno.test("parseBunkerUrl - returns null without bunker prefix", () => {
  assertEquals(parseBunkerUrl(`nostr://${PK}?relay=wss://x`), null)
})

Deno.test("parseBunkerUrl - returns null for invalid pubkey", () => {
  assertEquals(parseBunkerUrl("bunker://not-a-pubkey?relay=wss://x"), null)
})

Deno.test("parseBunkerUrl - returns null when no relays given", () => {
  assertEquals(parseBunkerUrl(`bunker://${PK}?secret=x`), null)
})

Deno.test("parseBunkerUrl - secret is null when omitted", () => {
  const result = parseBunkerUrl(`bunker://${PK}?relay=wss%3A%2F%2Fx`)
  assertEquals(result?.secret, null)
})

Deno.test("parseBunkerUrl - refuses a pubkey that is not NIP-01 lowercase hex", () => {
  const upper = "ABCDEF" + "0".repeat(58)
  assertEquals(parseBunkerUrl(`bunker://${upper}?relay=wss%3A%2F%2Fx`), null)
})

Deno.test("parseBunkerUrl - trims surrounding whitespace", () => {
  const result = parseBunkerUrl(`  bunker://${PK}?relay=wss%3A%2F%2Fx  `)
  assertEquals(result?.remoteSignerPubkey, PK)
})

Deno.test("parseBunkerUrl - rejects non-websocket relay schemes", () => {
  const result = parseBunkerUrl(`bunker://${PK}?relay=javascript%3Aalert(1)`)
  assertEquals(result, null)
})

Deno.test("parseBunkerUrl - filters invalid relay URLs but keeps valid ones", () => {
  const result = parseBunkerUrl(`bunker://${PK}?relay=javascript%3Aalert(1)&relay=wss%3A%2F%2Fok.example`)
  assertEquals(result?.relays, [relayUrlFixture("wss://ok.example")])
})

Deno.test("parseBunkerUrl - returns null when all relays are invalid", () => {
  const result = parseBunkerUrl(`bunker://${PK}?relay=http%3A%2F%2Fbad&relay=ftp%3A%2F%2Falso-bad`)
  assertEquals(result, null)
})

Deno.test("formatBunkerUrl - round-trips through parseBunkerUrl with multiple relays and a secret", () => {
  const original = {
    remoteSignerPubkey: publicKeyFixture(PK),
    relays: [relayUrlFixture("wss://a.example"), relayUrlFixture("wss://b.example")],
    secret: "secret with spaces & symbols=#",
  }
  assertEquals(parseBunkerUrl(formatBunkerUrl(original)), original)
})

Deno.test("formatBunkerUrl - percent-encodes the query, never form-encodes it", () => {
  const url = formatBunkerUrl({
    remoteSignerPubkey: publicKeyFixture(PK),
    relays: [relayUrlFixture("wss://a.example")],
    secret: "secret with spaces & symbols=#",
  })
  assertEquals(url.includes("secret=secret%20with%20spaces%20%26%20symbols%3D%23"), true)
})

Deno.test("formatBunkerUrl - omits the secret param when secret is null", () => {
  const url = formatBunkerUrl({
    remoteSignerPubkey: publicKeyFixture(PK),
    relays: [relayUrlFixture("wss://a.example")],
    secret: null,
  })
  assertEquals(url.includes("secret="), false)
  assertEquals(parseBunkerUrl(url)?.secret, null)
})
