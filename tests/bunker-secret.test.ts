import { assertEquals } from "@std/assert"
import type { PublicKey } from "@innis/nostr-core"
import { createLocalSigner } from "@innis/nostr-core"
import { createNip46Bunker } from "../src/bunker.ts"
import { parseBunkerUrl } from "../src/bunker-url.ts"
import { createCapturingTransport } from "./_helpers/fakes.ts"
import {
  ATTACKER_PK,
  BUNKER_SK,
  CLIENT_PK,
  createHarness,
  fakeTools,
  grantAllButSigning,
  RELAY,
  USER_PK,
} from "./_helpers/bunker-harness.ts"

const SECRET = "0s8j2djs"
const FRESH_SECRET = "a1b2c3d4"

Deno.test("bunker - a second client presenting a used secret is ignored, not answered", async () => {
  const h = createHarness(SECRET)
  try {
    await h.send(CLIENT_PK, { id: "1", method: "connect", params: [USER_PK, SECRET] })
    const publishedAfterFirst = h.published.length
    await h.send(ATTACKER_PK, { id: "2", method: "connect", params: [USER_PK, SECRET] })
    assertEquals(h.published.length, publishedAfterFirst)
  } finally {
    h.stop()
  }
})

Deno.test("bunker - a client ignored for a used secret stays unconnected", async () => {
  const h = createHarness(SECRET)
  try {
    await h.send(CLIENT_PK, { id: "1", method: "connect", params: [USER_PK, SECRET] })
    await h.send(ATTACKER_PK, { id: "2", method: "connect", params: [USER_PK, SECRET] })
    await h.send(ATTACKER_PK, { id: "3", method: "get_public_key" })
    assertEquals(h.lastResponse(), { id: "3", error: "not connected" })
  } finally {
    h.stop()
  }
})

Deno.test("bunker - the client that used a secret is acknowledged again when it repeats connect", async () => {
  const h = createHarness(SECRET)
  try {
    await h.send(CLIENT_PK, { id: "1", method: "connect", params: [USER_PK, SECRET] })
    await h.send(CLIENT_PK, { id: "2", method: "connect", params: [USER_PK, SECRET] })
    assertEquals(h.lastResponse(), { id: "2", result: "ack" })
  } finally {
    h.stop()
  }
})

Deno.test("bunker - a client that logged out cannot reconnect with the secret it used", async () => {
  const h = createHarness(SECRET)
  try {
    await h.send(CLIENT_PK, { id: "1", method: "connect", params: [USER_PK, SECRET] })
    await h.send(CLIENT_PK, { id: "2", method: "logout" })
    const publishedAfterLogout = h.published.length
    await h.send(CLIENT_PK, { id: "3", method: "connect", params: [USER_PK, SECRET] })
    assertEquals(h.published.length, publishedAfterLogout)
  } finally {
    h.stop()
  }
})

Deno.test("bunker - using the secret tells the host which client used it", async () => {
  const used: Array<[string, PublicKey]> = []
  const h = createHarness(SECRET, { onSecretUsed: (secret, client) => used.push([secret, client]) })
  try {
    await h.send(CLIENT_PK, { id: "1", method: "connect", params: [USER_PK, SECRET] })
    assertEquals(used, [[SECRET, CLIENT_PK]])
  } finally {
    h.stop()
  }
})

Deno.test("bunker - a used secret leaves no bunker url until the host issues a fresh one", async () => {
  const h = createHarness(SECRET)
  let updates = 0
  const unsubscribe = h.bunker.onUpdate(() => updates++)
  try {
    await h.send(CLIENT_PK, { id: "1", method: "connect", params: [USER_PK, SECRET] })
    assertEquals({ url: h.bunker.getBunkerUrl(), updates }, { url: null, updates: 1 })
  } finally {
    unsubscribe()
    h.stop()
  }
})

Deno.test("bunker - a freshly issued secret connects one new client and is then used up", async () => {
  const h = createHarness(SECRET)
  try {
    await h.send(CLIENT_PK, { id: "1", method: "connect", params: [USER_PK, SECRET] })
    const issued = h.bunker.issueSecret(FRESH_SECRET)
    await h.send(ATTACKER_PK, { id: "2", method: "connect", params: [USER_PK, FRESH_SECRET] })
    assertEquals({
      issued,
      advertised: parseBunkerUrl(h.bunker.getBunkerUrl() ?? "")?.secret ?? null,
      response: h.lastResponse(),
    }, { issued: true, advertised: null, response: { id: "2", result: "ack" } })
  } finally {
    h.stop()
  }
})

Deno.test("bunker - an issued secret replaces the advertised one", () => {
  const h = createHarness(SECRET)
  try {
    h.bunker.issueSecret(FRESH_SECRET)
    assertEquals(parseBunkerUrl(h.bunker.getBunkerUrl() ?? "")?.secret, FRESH_SECRET)
  } finally {
    h.stop()
  }
})

Deno.test("bunker - an unused secret the host replaced is refused as invalid", async () => {
  const h = createHarness(SECRET)
  try {
    h.bunker.issueSecret(FRESH_SECRET)
    await h.send(CLIENT_PK, { id: "1", method: "connect", params: [USER_PK, SECRET] })
    assertEquals(h.lastResponse(), { id: "1", error: "invalid secret" })
  } finally {
    h.stop()
  }
})

Deno.test("bunker - issueSecret refuses a used secret and an empty one", async () => {
  const h = createHarness(SECRET)
  try {
    await h.send(CLIENT_PK, { id: "1", method: "connect", params: [USER_PK, SECRET] })
    assertEquals([h.bunker.issueSecret(SECRET), h.bunker.issueSecret("")], [false, false])
  } finally {
    h.stop()
  }
})

Deno.test("bunker - issueSecret before start issues nothing", () => {
  const bunker = createNip46Bunker({
    transport: createCapturingTransport().transport,
    signer: createLocalSigner(BUNKER_SK, fakeTools),
    isAuthorised: grantAllButSigning,
  })
  assertEquals({ issued: bunker.issueSecret(FRESH_SECRET), url: bunker.getBunkerUrl() }, { issued: false, url: null })
})

Deno.test("bunker - a used secret stays used when the bunker is restarted with it", async () => {
  const h = createHarness(SECRET)
  try {
    await h.send(CLIENT_PK, { id: "1", method: "connect", params: [USER_PK, SECRET] })
    h.bunker.start(USER_PK, [RELAY], SECRET)
    const publishedAfterRestart = h.published.length
    await h.send(ATTACKER_PK, { id: "2", method: "connect", params: [USER_PK, SECRET] })
    assertEquals({ url: h.bunker.getBunkerUrl(), published: h.published.length }, {
      url: null,
      published: publishedAfterRestart,
    })
  } finally {
    h.stop()
  }
})

Deno.test("bunker - a host callback that throws on a used secret still lets the client be acknowledged", async () => {
  const reported: Array<unknown> = []
  const capture = (event: ErrorEvent): void => {
    event.preventDefault()
    reported.push(event.error)
  }
  globalThis.addEventListener("error", capture)
  const h = createHarness(SECRET, {
    onSecretUsed: () => {
      throw new Error("host storage unavailable")
    },
  })
  try {
    await h.send(CLIENT_PK, { id: "1", method: "connect", params: [USER_PK, SECRET] })
    assertEquals({ response: h.lastResponse(), reported: reported.length }, {
      response: { id: "1", result: "ack" },
      reported: 1,
    })
  } finally {
    globalThis.removeEventListener("error", capture)
    h.stop()
  }
})
