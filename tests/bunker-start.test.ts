import { assertEquals, assertThrows } from "@std/assert"
import { createLocalSigner, InvalidArgumentError } from "@innis/nostr-core"
import { createNip46Bunker } from "../src/bunker.ts"
import { parseBunkerUrl } from "../src/bunker-url.ts"
import type { Nip46Transport } from "../src/transport.ts"
import {
  BUNKER_SK,
  CLIENT_PK,
  createHarness,
  fakeTools,
  grantAllButSigning,
  USER_PK,
} from "./_helpers/bunker-harness.ts"

Deno.test("bunker - start on an empty relay set is a fault", () => {
  const transport: Nip46Transport = {
    subscribe: () => ({ abort: () => {} }),
    publish: () => Promise.resolve({ ok: true }),
  }
  const bunker = createNip46Bunker({
    transport,
    signer: createLocalSigner(BUNKER_SK, fakeTools),
    isAuthorised: grantAllButSigning,
  })

  assertThrows(() => bunker.start(USER_PK, [], "secret"), InvalidArgumentError)
})

Deno.test("bunker - a start on an empty relay set leaves the running bunker answering", async () => {
  const h = createHarness("supersecret")
  try {
    assertThrows(() => h.bunker.start(USER_PK, [], "other"), InvalidArgumentError)
    await h.send(CLIENT_PK, { id: "1", method: "ping" })
    assertEquals(h.lastResponse(), { id: "1", result: "pong" })
  } finally {
    h.stop()
  }
})

Deno.test("bunker - a start on an empty relay set leaves the running bunker's url advertised", () => {
  const h = createHarness("supersecret")
  try {
    const advertised = h.bunker.getBunkerUrl()
    assertThrows(() => h.bunker.start(USER_PK, [], "other"), InvalidArgumentError)
    assertEquals(h.bunker.getBunkerUrl(), advertised)
  } finally {
    h.stop()
  }
})

Deno.test("bunker - start with an empty secret advertises no URL", () => {
  const h = createHarness("")
  try {
    assertEquals(h.bunker.getBunkerUrl(), null)
  } finally {
    h.stop()
  }
})

Deno.test("bunker - start with an empty secret serves a restored client", async () => {
  const h = createHarness("")
  try {
    h.bunker.restorePairing(CLIENT_PK, [])
    await h.send(CLIENT_PK, { id: "g", method: "get_public_key" })
    assertEquals(h.lastResponse(), { id: "g", result: USER_PK })
  } finally {
    h.stop()
  }
})

Deno.test("bunker - start with an empty secret can be issued one to advertise", () => {
  const h = createHarness("")
  try {
    h.bunker.issueSecret("fresh-secret")
    assertEquals(parseBunkerUrl(h.bunker.getBunkerUrl() ?? "")?.secret, "fresh-secret")
  } finally {
    h.stop()
  }
})

Deno.test("bunker - start with an empty secret connects no client presenting an empty one", async () => {
  const h = createHarness("")
  try {
    await h.send(CLIENT_PK, { id: "c", method: "connect", params: [USER_PK, ""] })
    assertEquals(h.lastResponse(), { id: "c", error: "invalid secret" })
  } finally {
    h.stop()
  }
})
