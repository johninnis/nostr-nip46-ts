# @innis/nostr-nip46

[![CI](https://github.com/johninnis/nostr-nip46-ts/actions/workflows/ci.yml/badge.svg)](https://github.com/johninnis/nostr-nip46-ts/actions/workflows/ci.yml)

NIP-46 ("Nostr Connect" / "bunker"). Two roles, both implemented:

- **Client** — the app holds no secret key; it asks a remote signer to sign events over a Nostr relay. Implements `Signer` from `@innis/nostr-core` so application code can't tell whether it's talking to a NIP-07 extension or a remote bunker.
- **Bunker** — the *signer* role: a process that holds a secret key and answers `sign_event` / `nip44_*` / `nip04_*` requests. Used by the in-app bunker mode where the user's logged-in browser session can serve as a remote signer for another device. NIP-04 support is for legacy clients only — new code should use NIP-44.

## Public surface

### `createNip46ClientSigner(deps)` — the client `Signer`

```ts
interface Nip46ClientSignerDeps {
    readonly tools: LocalSignerTools                 // crypto primitives from @innis/nostr-core
    readonly transport: Nip46Transport
    readonly clientSecretKey: Uint8Array             // per-session ephemeral key
    readonly remoteSignerPubkey: PublicKey
    readonly relayUrls: ReadonlyArray<RelayUrl>      // every relay the bunker:// URL advertised
    readonly secret: string | null                   // initial pairing secret from bunker:// URL
    readonly initialUserPubkey?: PublicKey | null
    readonly timeoutMs?: number                      // default 5 min
    readonly now?: () => number
    readonly generateRequestId?: () => string
    readonly verifyEventSignature?: (event: NostrEvent) => Promise<boolean> // default: @innis/nostr-core
    readonly onPubkeyMismatch?: (expected: PublicKey, actual: PublicKey) => void
    readonly onAuthChallenge?: (url: string) => void // bunker asked the user to authorise at this URL
}

interface Nip46ClientSigner extends Signer {
    readonly connect: () => Promise<void>
    readonly disconnect: () => void
    readonly getClientPubkey: () => PublicKey
}
```

Each call to `signEvent` / `nip44Encrypt` / `nip44Decrypt` / `nip04Encrypt` / `nip04Decrypt` becomes:

1. JSON-encode `{ id, method, params }`.
2. Encrypt to the remote signer's pubkey using NIP-44 (signed by the *client* secret key — the user's pubkey never appears in the envelope).
3. Publish as a kind 24133 event to every configured relay, p-tagged to `remoteSignerPubkey`. Mirrors the bunker, which subscribes and broadcasts on every relay in the `bunker://` URL — both roles model the relay set the same way, so a single dead relay never strands a request. The encrypt → wrap → sign → broadcast step is owned by a single internal `sendEnvelope` (in `protocol.ts`) that both the client and the bunker call — there is exactly one on-wire send path, so the two roles cannot drift.
4. Wait on a single subscription spanning all relays (`kinds: [24133], authors: [remoteSignerPubkey], #p: [clientPubkey]`) for the response with the matching `id`. Responses from any author other than `remoteSignerPubkey` are ignored, so a third party cannot inject a reply even if it learns the client pubkey.
5. Decrypt the response envelope, surface `result` / `error`.

`connect()` runs the initial NIP-46 `connect` handshake with the pairing secret, then fetches the user pubkey through the same `getPublicKey()` the public method uses — one acquisition path, no duplicated handshake logic. **Must succeed before any signing call.** `disconnect()` rejects all pending requests with `SigningError("bunker disconnected")` and tears down the transport subscription.

**Reload path / `initialUserPubkey`.** Passing `initialUserPubkey` (e.g. restoring a persisted session) makes `connect()` skip the `connect` handshake entirely — it assumes the remote signer still has this client authenticated. That is deliberate: the pairing secret is one-shot and the bunker's authorised-client set is its own in-memory state. The trade-off: if the remote signer has since dropped the session, the client only discovers this when the first `signEvent`/crypto call comes back as a bunker error (`"not connected"`); there is no automatic re-pair. Hosts that persist `initialUserPubkey` should treat such an error as "re-pair required" rather than retrying.

**Auth challenges.** A signer that needs the user to approve in a browser answers any request with `{ result: "auth_url", error: "<url>" }`. When that arrives the in-flight request is kept open and `onAuthChallenge(url)` fires so the host app can open the URL; the request resolves once the signer re-sends the real reply (or times out). If no `onAuthChallenge` is supplied, the request rejects with `SigningError("bunker requires authentication: <url>")` rather than hanging. The client emits NIP-44 envelopes and accepts replies in either NIP-44 or NIP-04.

`signEvent` runs the same pubkey-mismatch check as `@innis/nostr-nip07`: after the bunker returns a signed event, the signed `pubkey` is compared to the user pubkey captured at connect time. On mismatch, the optional `onPubkeyMismatch(expected, actual)` callback fires and `signEvent` throws `PubkeyMismatchError`. A host app typically wires this callback to log the user out — the same response the NIP-07 signer warrants — so an account switch on either backend never silently signs as the wrong identity.

After the pubkey check, `signEvent` verifies the returned event's Schnorr signature with `verifyEventSignature` from `@innis/nostr-core` and throws `SigningError` if it does not validate. This is fail-fast defence-in-depth against a malfunctioning signer, surfacing a bad signature at the call boundary rather than later when a relay rejects the publish — it is *not* the wire-injection guard (that is the NIP-44 envelope's authenticated encryption plus the `remoteSignerPubkey` author pin). The check is injectable via `verifyEventSignature` for tests and hardware-accelerated verifiers; it defaults to the core implementation.

### `createNip46Bunker(deps)` — the bunker (signer-side) role

```ts
interface BunkerDeps {
    readonly transport: Nip46Transport
    readonly signer: Signer        // the signer that actually approves requests (NIP-07, local, etc.)
    readonly now?: () => number
}
```

Lets a logged-in app session act as a remote signer for another device. Subscribes to incoming NIP-46 requests, queues them as `PendingSignRequest`s, and exposes:

- `start(userPubkey, relayUrls, secret)` / `stop()` — lifecycle. The bunker subscribes on every URL in `relayUrls` and broadcasts each response on all of them. `start` is a no-op if `relayUrls` is empty or `secret` is empty — a bunker without a pairing secret would authenticate anyone, so it refuses to run.
- `getBunkerUrl()` — emits the `bunker://...?relay=&relay=&secret=` URL the user pastes into another device (one `relay=` param per relay).
- `getPending()` — UI reads these to render an approval queue.
- `approve(id)` / `reject(id)` — answer a queued request.
- `onUpdate(listener)` — subscribe to queue changes.

Approval signs the requested event using the supplied `Signer` (in practice the user's normal logged-in NIP-07 signer or local signer) and publishes the response back over the transport.

### `parseBunkerUrl(raw)` / `formatBunkerUrl(url)` — `bunker-url.ts`

`parseBunkerUrl` reads `bunker://<remoteSignerPubkey>?relay=wss://...&relay=wss://...&secret=...` into `{ remoteSignerPubkey, relays, secret }`, returning `null` for malformed URLs. `formatBunkerUrl` is its inverse and the single owner of the on-wire format — `Nip46Bunker.getBunkerUrl()` builds its URL through it, so parse and format can never drift.

### Transport — `transport.ts`

```ts
interface Nip46Transport {
    readonly subscribe: (params: { filter, relays, onEvent }) => { abort: () => void }
    readonly publish: (relayUrl, event) => Promise<unknown>
}
```

The transport is the *only* Nostr-on-the-wire surface this lib touches. It's an injected port so the lib can be ported to other environments and tested without a real relay pool. `publish` returns `Promise<unknown>` by design: the library never reads the resolved value (it fires-and-forgets to every relay), but real implementations such as `@innis/nostr-relay-pool`'s `pool.publish` return a `PublishResponse`. Typing the port as `Promise<void>` would force every adapter to discard that value at the boundary; `unknown` lets implementations return whatever they have while the lib stays indifferent to it.

A typical host wires this port directly to a relay pool's `subscribe` / `publish` (for example `@innis/nostr-relay-pool`). Bunker comms are transport-level RPC, not application content — keep them off whatever content cache and publish pipeline your app uses for ordinary events.

### Crypto adapter — `LocalSignerTools`

The client signer (above) takes `tools: LocalSignerTools` because every outgoing request envelope is *itself* a signed-and-NIP-44-encrypted Nostr event — the client signs it with its own per-session `clientSecretKey`, never the user's key. The lib delegates that crypto to the same `LocalSignerTools` adapter `@innis/nostr-core` defines (raw Schnorr `schnorrSign` over a hex id, secp256k1 `getPublicKey`, NIP-44 v2 round-trip). `@innis/nostr-core`'s `createLocalSigner` handles event-id derivation itself via `computeEventId`, so the bag stays raw-crypto-only.

See [`@innis/nostr-core` on JSR](https://jsr.io/@innis/nostr-core) for the `createLocalSigner` / `LocalSignerTools` interface shape and a usage example. The bunker role does **not** need `LocalSignerTools` — it takes a `Signer` directly, since the signing key already lives behind whichever `Signer` you pass it.

## Lifecycle

```
parseBunkerUrl -> { remoteSignerPubkey, relays, secret }
            |
            v
createNip46ClientSigner({ ..., transport })
            |
            v
        connect()      -- initial NIP-46 handshake, sends `connect` method
            |
            v
   signEvent / nip44* / nip04*  -- per-call RPC over kind 24133
            |
            v
       disconnect()    -- on logout / session end
```

The client secret key is per-session and ephemeral: it's the key the *client* uses to sign request envelopes, not the user's secret key. It never leaves the device. Loss means re-pairing with the bunker. Persisting it across reloads is the host app's responsibility — keep it in one place alongside the rest of your login state.

## Anti-patterns

- **Calling `transport.publish` directly to send application events.** The transport is for kind 24133 envelopes only. Use your app's normal publish path for ordinary content.
- **Caching a `Nip46ClientSigner` across logout/login.** The signer holds a per-session subscription and a pending-request map. Call `disconnect()` on logout and construct a fresh signer on the next session — don't reuse one across sessions.
- **Storing the bunker `clientSecretKey` in a different place from the rest of your login state.** It must round-trip the same way as everything else you persist for a session.
- **Implementing the transport with a fresh, single-purpose pool.** Reuse the relay pool your app already runs; the bunker connection benefits from its reconnect/backoff/AUTH handling.
