import { assertEquals } from "@std/assert"
import { publicKeyFixture, relayUrlFixture } from "@innis/nostr-core/testing"
import { formatNostrConnectUrl, parseNostrConnectUrl } from "../src/nostr-connect-url.ts"

const NIP46_EXAMPLE =
  "nostrconnect://83f3b2ae6aa368e8275397b9c26cf550101d63ebaab900d19dd4a4429f5ad8f5?relay=wss%3A%2F%2Frelay1.example.com&perms=nip44_encrypt%2Cnip44_decrypt%2Csign_event%3A13%2Csign_event%3A14%2Csign_event%3A1059&name=My+Client&secret=0s8j2djs&relay=wss%3A%2F%2Frelay2.example2.com"

const CLIENT_PK = publicKeyFixture("83f3b2ae6aa368e8275397b9c26cf550101d63ebaab900d19dd4a4429f5ad8f5")
const RELAY_1 = relayUrlFixture("wss://relay1.example.com")
const RELAY_2 = relayUrlFixture("wss://relay2.example2.com")

Deno.test("parseNostrConnectUrl - reads the NIP-46 example into its client key, relays, secret and metadata", () => {
  assertEquals(parseNostrConnectUrl(NIP46_EXAMPLE), {
    clientPubkey: CLIENT_PK,
    relays: [RELAY_1, RELAY_2],
    secret: "0s8j2djs",
    perms: ["nip44_encrypt", "nip44_decrypt", "sign_event:13", "sign_event:14", "sign_event:1059"],
    name: "My Client",
    url: null,
    image: null,
  })
})

Deno.test("parseNostrConnectUrl - rejects a url without the required secret", () => {
  assertEquals(parseNostrConnectUrl(`nostrconnect://${CLIENT_PK}?relay=wss%3A%2F%2Frelay1.example.com`), null)
})

Deno.test("parseNostrConnectUrl - rejects a url without the required relay", () => {
  assertEquals(parseNostrConnectUrl(`nostrconnect://${CLIENT_PK}?secret=0s8j2djs`), null)
})

Deno.test("parseNostrConnectUrl - rejects a url whose origin is not a public key", () => {
  assertEquals(parseNostrConnectUrl("nostrconnect://not-a-key?relay=wss%3A%2F%2Frelay1.example.com&secret=x"), null)
})

Deno.test("parseNostrConnectUrl - rejects a bunker url", () => {
  assertEquals(parseNostrConnectUrl(`bunker://${CLIENT_PK}?relay=wss%3A%2F%2Frelay1.example.com&secret=x`), null)
})

Deno.test("parseNostrConnectUrl - drops requested permissions it does not recognise", () => {
  const parsed = parseNostrConnectUrl(
    `nostrconnect://${CLIENT_PK}?relay=wss%3A%2F%2Frelay1.example.com&secret=x&perms=sign_event,nip44_decrypt:1,launch_missiles,sign_event:x,sign_event:65536,get_public_key,ping`,
  )
  assertEquals(parsed?.perms, ["sign_event", "get_public_key", "ping"])
})

Deno.test("parseNostrConnectUrl - keeps each requested permission once", () => {
  const parsed = parseNostrConnectUrl(
    `nostrconnect://${CLIENT_PK}?relay=wss%3A%2F%2Frelay1.example.com&secret=x&perms=sign_event:1,sign_event:01,nip44_encrypt,nip44_encrypt`,
  )
  assertEquals(parsed?.perms, ["sign_event:1", "nip44_encrypt"])
})

Deno.test("parseNostrConnectUrl - refuses a client pubkey that is not NIP-01 lowercase hex", () => {
  const upper = CLIENT_PK.toUpperCase()
  assertEquals(parseNostrConnectUrl(`nostrconnect://${upper}?relay=wss%3A%2F%2Frelay1.example.com&secret=x`), null)
})

Deno.test("formatNostrConnectUrl - round-trips through parseNostrConnectUrl", () => {
  const url = {
    clientPubkey: CLIENT_PK,
    relays: [RELAY_1, RELAY_2],
    secret: "s3cr=t &",
    perms: ["nip44_encrypt", "sign_event:1"] as const,
    name: "My Client",
    url: "https://client.example",
    image: "https://client.example/icon.png",
  }
  assertEquals(parseNostrConnectUrl(formatNostrConnectUrl(url)), url)
})

Deno.test("formatNostrConnectUrl - leaves out metadata that is absent", () => {
  const formatted = formatNostrConnectUrl({
    clientPubkey: CLIENT_PK,
    relays: [RELAY_1],
    secret: "0s8j2djs",
    perms: [],
    name: null,
    url: null,
    image: null,
  })
  assertEquals(formatted, `nostrconnect://${CLIENT_PK}?relay=wss%3A%2F%2Frelay1.example.com&secret=0s8j2djs`)
})
