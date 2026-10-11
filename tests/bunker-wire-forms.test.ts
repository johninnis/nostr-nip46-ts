import { assert, assertEquals } from "@std/assert"
import { CLIENT_PK, createHarness, USER_PK } from "./_helpers/bunker-harness.ts"

Deno.test("bunker - queues a sign_event whose event arrives as a raw object, not a JSON string", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "obj1", method: "connect", params: [USER_PK, "supersecret"] })
    await h.send(CLIENT_PK, { id: "obj2", method: "sign_event", params: [{ kind: 1, content: "from object client" }] })
    const pending = h.pending()
    assertEquals(pending.length, 1)
    const detail = pending[0]?.detail
    assert(detail?.method === "sign_event")
    assertEquals([detail.eventToSign.kind, detail.eventToSign.content], [1, "from object client"])
  } finally {
    h.stop()
  }
})

for (
  const [label, params] of [
    ["a sign_event whose event is a JSON array", [[1, "hi"]]],
    ["a sign_event whose event is a number", [7]],
    ["a sign_event whose event is null", [null]],
    ["a sign_event whose second parameter is not a string", [{ kind: 1, content: "hi" }, 5]],
  ] as const
) {
  Deno.test(`bunker - drops ${label} without replying or queueing it`, async () => {
    const h = createHarness("supersecret")
    try {
      await h.send(CLIENT_PK, { id: "w1", method: "connect", params: [USER_PK, "supersecret"] })
      await h.send(CLIENT_PK, { id: "w2", method: "sign_event", params })
      assertEquals({ published: h.published.length, queued: h.pending().length }, { published: 1, queued: 0 })
    } finally {
      h.stop()
    }
  })
}

Deno.test("bunker - drops a request of another method carrying an object parameter without replying", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "w3", method: "ping", params: [{ kind: 1 }] })
    assertEquals(h.published.length, 0)
  } finally {
    h.stop()
  }
})

Deno.test("bunker - drops a request whose params is not an array without replying", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "p1", method: "ping", params: null })
    assertEquals(h.published.length, 0)
  } finally {
    h.stop()
  }
})

Deno.test("bunker - drops a request with an empty id without replying", async () => {
  const h = createHarness("supersecret")
  try {
    await h.send(CLIENT_PK, { id: "", method: "ping" })
    assertEquals(h.published.length, 0)
  } finally {
    h.stop()
  }
})
