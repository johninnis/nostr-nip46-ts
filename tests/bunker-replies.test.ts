import { assertEquals, assertRejects } from "@std/assert"
import type { Signer } from "@innis/nostr-core"
import { createLocalSigner, failure, ok } from "@innis/nostr-core"
import { eventIdFixture } from "@innis/nostr-core/testing"
import { flush } from "./_helpers/fakes.ts"
import { BUNKER_SK, CLIENT_PK, createHarness, fakeTools, USER_PK } from "./_helpers/bunker-harness.ts"

const SIGN_EVENT = JSON.stringify({ kind: 1, content: "hi" })

Deno.test("bunker - approve returns ok once the reply reached a relay", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "o1", method: "connect", params: [USER_PK, "supersecret"] })
    await h.send(CLIENT_PK, { id: "o2", method: "sign_event", params: [SIGN_EVENT] })
    const pendingId = h.pending()[0]?.id
    if (!pendingId) throw new Error("expected pending request")
    assertEquals(await h.bunker.approve(pendingId), ok(undefined))
  } finally {
    h.stop()
  }
})

Deno.test("bunker - approve returns the delivery failure when no relay accepted the reply", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "n1", method: "connect", params: [USER_PK, "supersecret"] })
    await h.send(CLIENT_PK, { id: "n2", method: "sign_event", params: [SIGN_EVENT] })
    const pendingId = h.pending()[0]?.id
    if (!pendingId) throw new Error("expected pending request")
    h.rejectPublishes()
    const result = await h.bunker.approve(pendingId)
    assertEquals(result.success ? null : result.error.type, "delivery-failed")
  } finally {
    h.stop()
  }
})

Deno.test("bunker - reject returns the delivery failure when no relay accepted the reply", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "n3", method: "connect", params: [USER_PK, "supersecret"] })
    await h.send(CLIENT_PK, { id: "n4", method: "sign_event", params: [SIGN_EVENT] })
    const pendingId = h.pending()[0]?.id
    if (!pendingId) throw new Error("expected pending request")
    h.rejectPublishes()
    const result = await h.bunker.reject(pendingId)
    assertEquals(result.success ? null : result.error.type, "delivery-failed")
  } finally {
    h.stop()
  }
})

Deno.test("bunker - approve and reject of an unknown id return ok without replying", async () => {
  const h = createHarness("supersecret")
  try {
    const missing = eventIdFixture("e".repeat(64))
    assertEquals([await h.bunker.approve(missing), await h.bunker.reject(missing)], [ok(undefined), ok(undefined)])
    assertEquals(h.published.length, 0)
  } finally {
    h.stop()
  }
})

Deno.test("bunker - an automatic reply no relay accepted is dropped, not reported as a fault", async () => {
  const h = createHarness("supersecret")
  const faults: Array<unknown> = []
  const onFault = (event: Event): void => {
    faults.push(event)
    event.preventDefault()
  }
  globalThis.addEventListener("unhandledrejection", onFault)
  globalThis.addEventListener("error", onFault)
  try {
    h.rejectPublishes()
    await h.send(CLIENT_PK, { id: "p1", method: "ping" })
    await flush()
    assertEquals(faults, [])
  } finally {
    globalThis.removeEventListener("unhandledrejection", onFault)
    globalThis.removeEventListener("error", onFault)
    h.stop()
  }
})

const localSigner = createLocalSigner(BUNKER_SK, fakeTools)

const grantAll = (): boolean => true

Deno.test("bunker - a nip44_decrypt the signer cannot decrypt is answered decryption failed", async () => {
  const h = createHarness("supersecret", { isAuthorised: grantAll })
  try {
    await h.send(CLIENT_PK, { id: "c", method: "connect", params: [USER_PK, "supersecret"] })
    await h.send(CLIENT_PK, { id: "d", method: "nip44_decrypt", params: [USER_PK, "not-a-ciphertext"] })
    assertEquals(h.lastResponse(), { id: "d", error: "decryption failed" })
  } finally {
    h.stop()
  }
})

Deno.test("bunker - a nip44_encrypt the signer cannot encrypt is answered encryption failed", async () => {
  const refusing: Signer = {
    ...localSigner,
    nip44Encrypt: (peer, plaintext) =>
      plaintext === "too long"
        ? Promise.resolve(failure({ type: "encrypt-failed", message: "plaintext over 65535 bytes" }))
        : localSigner.nip44Encrypt(peer, plaintext),
  }
  const h = createHarness("supersecret", { signer: refusing, isAuthorised: grantAll })
  try {
    await h.send(CLIENT_PK, { id: "c", method: "connect", params: [USER_PK, "supersecret"] })
    await h.send(CLIENT_PK, { id: "e", method: "nip44_encrypt", params: [USER_PK, "too long"] })
    assertEquals(h.lastResponse(), { id: "e", error: "encryption failed" })
  } finally {
    h.stop()
  }
})

Deno.test("bunker - a cipher request the signer declines is answered user rejected", async () => {
  const declining: Signer = {
    ...localSigner,
    nip04Decrypt: () => Promise.resolve(failure({ type: "rejected", message: "User rejected the request" })),
  }
  const h = createHarness("supersecret", { signer: declining, isAuthorised: grantAll })
  try {
    await h.send(CLIENT_PK, { id: "c", method: "connect", params: [USER_PK, "supersecret"] })
    await h.send(CLIENT_PK, { id: "r", method: "nip04_decrypt", params: [USER_PK, "NIP04:hi?iv=AAAA"] })
    assertEquals(h.lastResponse(), { id: "r", error: "user rejected" })
  } finally {
    h.stop()
  }
})

const sealingLimited = (limit: number, attempts: Array<number>): Signer => ({
  ...localSigner,
  nip44Encrypt: (peer, plaintext) => {
    attempts.push(plaintext.length)
    return plaintext.length > limit
      ? Promise.resolve(failure({ type: "encrypt-failed", message: "plaintext over the cipher's limit" }))
      : localSigner.nip44Encrypt(peer, plaintext)
  },
})

Deno.test("bunker - a result too large to seal is replaced by the error response too large", async () => {
  const h = createHarness("supersecret", { signer: sealingLimited(200, []) })
  try {
    await h.send(CLIENT_PK, { id: "c", method: "connect", params: [USER_PK, "supersecret"] })
    await h.send(CLIENT_PK, {
      id: "big",
      method: "sign_event",
      params: [JSON.stringify({ kind: 1, content: "x".repeat(500) })],
    })
    const queued = h.pending()[0]
    if (!queued) throw new Error("expected a queued request")
    assertEquals(await h.bunker.approve(queued.id), ok(undefined))
    assertEquals(h.lastResponse(), { id: "big", error: "response too large" })
  } finally {
    h.stop()
  }
})

Deno.test("bunker - an error response that cannot be sealed is dropped after one attempt", async () => {
  const attempts: Array<number> = []
  const h = createHarness("supersecret", { signer: sealingLimited(0, attempts) })
  try {
    await h.send(CLIENT_PK, { id: "g", method: "get_public_key" })
    assertEquals({ published: h.published.length, attempts: attempts.length }, { published: 0, attempts: 1 })
  } finally {
    h.stop()
  }
})

Deno.test("bunker - approve rejects when the transport faults rather than reporting a delivery failure", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "c", method: "connect", params: [USER_PK, "supersecret"] })
    await h.send(CLIENT_PK, { id: "s", method: "sign_event", params: [SIGN_EVENT] })
    const queued = h.pending()[0]
    if (!queued) throw new Error("expected a queued request")
    h.breakPublishes()
    await assertRejects(() => h.bunker.approve(queued.id), Error, "socket torn down mid-write")
  } finally {
    h.stop()
  }
})

Deno.test("bunker - a transport fault on an automatic reply is reported, not swallowed", async () => {
  const h = createHarness("supersecret")
  const faults: Array<unknown> = []
  const onFault = (event: Event): void => {
    faults.push(event)
    event.preventDefault()
  }
  globalThis.addEventListener("unhandledrejection", onFault)
  globalThis.addEventListener("error", onFault)
  try {
    h.breakPublishes()
    await h.send(CLIENT_PK, { id: "p", method: "ping" })
    await flush()
    assertEquals(faults.length, 1)
  } finally {
    globalThis.removeEventListener("unhandledrejection", onFault)
    globalThis.removeEventListener("error", onFault)
    h.stop()
  }
})
