import { assert, assertEquals } from "@std/assert"
import type { PublicKey } from "@innis/nostr-core"
import type { Nip46Permission } from "../src/pending-request.ts"
import { CLIENT_PK, createHarness, isSignedEventBody, USER_PK } from "./_helpers/bunker-harness.ts"

const denyAll = (): boolean => false

const connected = async (
  isAuthorised: (client: PublicKey, permission: Nip46Permission) => boolean,
): Promise<ReturnType<typeof createHarness>> => {
  const h = createHarness("supersecret", { isAuthorised })
  await h.send(CLIENT_PK, { id: "c", method: "connect", params: [USER_PK, "supersecret"] })
  return h
}

Deno.test("bunker - an ungranted get_public_key is queued for a decision rather than answered", async () => {
  const h = await connected(denyAll)
  try {
    await h.send(CLIENT_PK, { id: "g1", method: "get_public_key" })
    assertEquals(h.lastResponse()?.id, "c")
    assertEquals(h.pending().map((request) => [request.requestId, request.detail.method]), [["g1", "get_public_key"]])
  } finally {
    h.stop()
  }
})

Deno.test("bunker - approving a queued get_public_key answers the user pubkey", async () => {
  const h = await connected(denyAll)
  try {
    await h.send(CLIENT_PK, { id: "g2", method: "get_public_key" })
    const queued = h.pending()[0]
    assert(queued !== undefined)
    await h.bunker.approve(queued.id)
    assertEquals(h.lastResponse(), { id: "g2", result: USER_PK })
  } finally {
    h.stop()
  }
})

Deno.test("bunker - an ungranted nip44_decrypt is queued with its counterparty and payload", async () => {
  const h = await connected(denyAll)
  try {
    const ciphertext = "ENC:" + btoa("hello")
    await h.send(CLIENT_PK, { id: "d1", method: "nip44_decrypt", params: [USER_PK, ciphertext] })
    assertEquals(h.pending()[0]?.detail, { method: "nip44_decrypt", counterparty: USER_PK, payload: ciphertext })
  } finally {
    h.stop()
  }
})

Deno.test("bunker - approving a queued nip44_decrypt answers the plaintext", async () => {
  const h = await connected(denyAll)
  try {
    await h.send(CLIENT_PK, { id: "d2", method: "nip44_decrypt", params: [USER_PK, "ENC:" + btoa("hello")] })
    const queued = h.pending()[0]
    assert(queued !== undefined)
    await h.bunker.approve(queued.id)
    assertEquals(h.lastResponse(), { id: "d2", result: "hello" })
  } finally {
    h.stop()
  }
})

Deno.test("bunker - a sign_event whose kind is granted is answered at once with the signed event", async () => {
  const asked: Array<Nip46Permission> = []
  const h = await connected((_client, permission) => {
    asked.push(permission)
    return permission === "sign_event:1"
  })
  try {
    await h.send(CLIENT_PK, { id: "s1", method: "sign_event", params: [JSON.stringify({ kind: 1, content: "hi" })] })
    const response = h.lastResponse()
    assert(response?.result !== undefined)
    const signed: unknown = JSON.parse(response.result)
    assert(isSignedEventBody(signed))
    assertEquals({ asked, queued: h.pending().length, kind: signed.kind }, {
      asked: ["sign_event:1"],
      queued: 0,
      kind: 1,
    })
  } finally {
    h.stop()
  }
})

Deno.test("bunker - the authoriser is asked about the requesting client and the method it needs", async () => {
  const asked: Array<[PublicKey, Nip46Permission]> = []
  const h = await connected((client, permission) => {
    asked.push([client, permission])
    return true
  })
  try {
    await h.send(CLIENT_PK, { id: "e1", method: "nip04_encrypt", params: [USER_PK, "hi"] })
    assertEquals(asked, [[CLIENT_PK, "nip04_encrypt"]])
  } finally {
    h.stop()
  }
})

Deno.test("bunker - ping, switch_relays and logout are answered without consulting the authoriser", async () => {
  const h = await connected(() => {
    throw new Error("the authoriser must not be consulted")
  })
  try {
    await h.send(CLIENT_PK, { id: "p", method: "ping" })
    await h.send(CLIENT_PK, { id: "s", method: "switch_relays" })
    await h.send(CLIENT_PK, { id: "l", method: "logout" })
    assertEquals([h.responseAt(1)?.result, h.responseAt(3)?.result], ["pong", "ack"])
  } finally {
    h.stop()
  }
})

Deno.test("bunker - unparseable parameters are answered with an error and never queued", async () => {
  const h = await connected(denyAll)
  try {
    await h.send(CLIENT_PK, { id: "x", method: "nip44_encrypt", params: ["not-a-pubkey", "hi"] })
    assertEquals({ response: h.lastResponse(), queued: h.pending().length }, {
      response: { id: "x", error: "invalid params" },
      queued: 0,
    })
  } finally {
    h.stop()
  }
})

Deno.test("bunker - logout replies ack and then treats the client as not connected", async () => {
  const h = await connected(() => true)
  try {
    await h.send(CLIENT_PK, { id: "l1", method: "logout" })
    await h.send(CLIENT_PK, { id: "l2", method: "get_public_key" })
    assertEquals([h.responseAt(1), h.responseAt(2)], [
      { id: "l1", result: "ack" },
      { id: "l2", error: "not connected" },
    ])
  } finally {
    h.stop()
  }
})
