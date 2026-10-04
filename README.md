# @innis/nostr-nip46

[![CI](https://github.com/johninnis/nostr-nip46-ts/actions/workflows/ci.yml/badge.svg)](https://github.com/johninnis/nostr-nip46-ts/actions/workflows/ci.yml)

NIP-46 ("Nostr Connect" / "bunker"). Two roles, both implemented:

- **Client** — the app holds no secret key; it asks a remote signer to sign events over a Nostr relay. Implements `Signer` from `@innis/nostr-core` so application code can't tell whether it's talking to a NIP-07 extension or a remote bunker.
- **Bunker** — the *signer* role: a process that holds a secret key and answers `sign_event` / `nip44_*` / `nip04_*` requests. Used by the in-app bunker mode where the user's logged-in browser session can serve as a remote signer for another device. NIP-04 support is for legacy clients only — new code should use NIP-44.

## Install

```bash
deno add jsr:@innis/nostr-nip46
```

## Public surface

### `createNip46ClientSigner(deps)` — the client `Signer`

```ts
interface Nip46ClientSignerDeps {
    readonly tools: LocalSignerTools                 // crypto primitives from @innis/nostr-core
    readonly transport: Nip46Transport
    readonly clientSecretKey: Uint8Array             // per-session ephemeral key
    readonly remoteSignerPubkey: PublicKey | null    // null for a client-initiated nostrconnect:// pairing
    readonly relayUrls: ReadonlyArray<RelayUrl>      // every relay the bunker:// URL advertised, or the nostrconnect:// URL names
    readonly secret: string | null                   // bunker:// secret, or the (required) nostrconnect:// secret
    readonly initialUserPubkey?: PublicKey | null
    readonly timeoutMs?: number                      // default 60 s
    readonly now?: () => number
    readonly generateRequestId?: () => string
    readonly verifyEventSignature?: (event: NostrEvent) => boolean // default: @innis/nostr-core
    readonly onPubkeyMismatch?: (expected: PublicKey, actual: PublicKey) => void
    readonly onAuthChallenge?: (url: string) => void // bunker asked the user to authorise at this URL
    readonly clientMetadata?: Nip46ClientMetadata    // { name, url, image }, sent with a bunker:// connect
    readonly requestedPerms?: ReadonlyArray<Nip46Permission> // asked for with a bunker:// connect — a hint, never a grant
}

interface Nip46ClientSigner extends Signer {
    readonly connect: () => Promise<Result<void, SignerFailure>>
    readonly disconnect: () => void
    readonly logout: () => Promise<Result<void, SignerFailure>>
    readonly getRelayUrls: () => ReadonlyArray<RelayUrl>
    readonly getClientPubkey: () => PublicKey
    readonly getRemoteSignerPubkey: () => PublicKey | null
}
```

Each call to `signEvent` / `nip44Encrypt` / `nip44Decrypt` / `nip04Encrypt` / `nip04Decrypt` becomes:

1. JSON-encode `{ id, method, params }`.
2. Encrypt to the remote signer's pubkey using NIP-44 (signed by the *client* secret key — the user's pubkey never appears in the envelope).
3. Publish as a kind 24133 event to every configured relay, p-tagged to `remoteSignerPubkey`. Mirrors the bunker, which subscribes and broadcasts on every relay in the `bunker://` URL — both roles model the relay set the same way, so a single dead relay never strands a request. The encrypt → wrap → sign → broadcast step is owned by a single internal `sendEnvelope` (in `protocol.ts`) that both the client and the bunker call — there is exactly one on-wire send path, so the two roles cannot drift.
4. Wait on a single subscription spanning all relays (`kinds: [24133], authors: [remoteSignerPubkey], #p: [clientPubkey]`) for the response with the matching `id`. Responses from any author other than `remoteSignerPubkey` are ignored, so a third party cannot inject a reply even if it learns the client pubkey.
5. Decrypt the response envelope, surface `result` / `error`. An event redelivered by several relays is handled once: the client remembers the last 10,000 event ids it has seen and drops a repeat before decrypting it.

`connect()` runs the initial NIP-46 `connect` handshake with the pairing secret — plus any `requestedPerms` as `optional_requested_perms` and, when `clientMetadata` has anything in it, the JSON-stringified metadata as `optional_client_metadata`, so the bunker can label the connection — then asks the bunker to `switch_relays`, then fetches the user pubkey through the same `getPublicKey()` the public method uses — one acquisition path, no duplicated handshake logic. It returns `Promise<Result<void, SignerFailure>>`. **Must succeed before any signing call** — a `signEvent` made before it returns `disconnected`. `disconnect()` settles all pending requests with a `disconnected` failure and tears down the transport subscription.

**Switching relays.** Straight after the connection is established, `connect()` sends `switch_relays`. A list with at least one valid relay replaces the client's relays: every later request goes there and the subscription is reopened there. `null`, an error, a timeout or an unusable answer keeps the client's own relays and the handshake carries on. `getRelayUrls()` returns the relays in use — persist them with the session, because a restored session (`initialUserPubkey`) does not ask again.

**Logging out.** `logout()` sends `logout`, waits for the bunker's `"ack"`, and then tears the session down exactly as `disconnect()` does — whether or not the bunker acknowledged. It returns `ok` for `"ack"` and a `disconnected` (or `rejected`) failure for anything else. NIP-46 makes `logout` a courtesy: the host must still delete its stored client secret key on logout, whatever `logout()` returns.

**Failures, not throws.** A transport whose `publish` rejects is broken rather than refused, and the call rejects with that fault; everything else is returned. Every method returns a `Result` whose failure is `@innis/nostr-core`'s `SignerFailure`: `disconnected` when a request timed out, was cut off by `disconnect()`, or reached no relay; `rejected` when the bunker's `error` says the user declined — NIP-46 defines no error code, so the words decide, through `isUserRejection` from `@innis/nostr-core`; `pubkey-mismatch` and `sign-failed` from `signEvent` as described below; otherwise the method's own mode (`public-key-failed` for `connect` / `getPublicKey`, `sign-failed`, `encrypt-failed`, `decrypt-failed`) carrying the bunker's error.

**Reload path / `initialUserPubkey`.** Passing `initialUserPubkey` (e.g. restoring a persisted session) makes `connect()` skip the `connect` handshake entirely — it assumes the remote signer still has this client authenticated. That is deliberate: the pairing secret is one-shot and the bunker's authorised-client set is its own in-memory state. The trade-off: if the remote signer has since dropped the session, the client only discovers this when the first `signEvent`/crypto call comes back as a bunker error (`"not connected"`); there is no automatic re-pair. Hosts that persist `initialUserPubkey` should treat such an error as "re-pair required" rather than retrying.

**Auth challenges.** A signer that needs the user to approve in a browser answers any request with `{ result: "auth_url", error: "<url>" }`. When that arrives the in-flight request is kept open and `onAuthChallenge(url)` fires so the host app can open the URL; the request resolves once the signer re-sends the real reply (or times out). Only an absolute `http:` or `https:` URL with a host is ever passed, in its normalised form — a challenge carrying a `javascript:`, `data:`, `file:` or any other URL is dropped, so the host can open what it receives. Each challenge event fires the callback once, however many relays deliver it. If no `onAuthChallenge` is supplied, the request returns the method's failure mode with the message `bunker requires authentication: <url>` rather than hanging. The client emits NIP-44 envelopes and accepts replies in either NIP-44 or NIP-04.

**Client-initiated pairing (`nostrconnect://`).** Pass `remoteSignerPubkey: null`, the relays the client will listen on, and a random `secret`. Call `connect()` first — it opens the subscription at once, and kind 24133 events are not stored by relays — then show the user `formatNostrConnectUrl({ clientPubkey: signer.getClientPubkey(), relays, secret, perms, name, url, image })` to paste into their signer. `connect()` resolves once a signer answers with a `connect` response whose result is that secret (anything else is ignored), learns the signer's key from that response's author, and fetches the user pubkey; no `connect` request is sent. `getRemoteSignerPubkey()` then returns the signer's key, so the host can persist the pairing and restore it later as a `bunker://` pairing (`formatBunkerUrl({ remoteSignerPubkey, relays: signer.getRelayUrls(), secret: null })`) with `initialUserPubkey`.

```ts
const signer = createNip46ClientSigner({ tools, transport, clientSecretKey, remoteSignerPubkey: null, relayUrls, secret })
const connecting = signer.connect()
showQrCode(formatNostrConnectUrl({ clientPubkey: signer.getClientPubkey(), relays: relayUrls, secret, perms: ["sign_event:1"], name: "My App", url: null, image: null }))
const connected = await connecting
```

`signEvent` runs the same pubkey-mismatch check as `@innis/nostr-nip07`: after the bunker returns a signed event, the signed `pubkey` is compared to the user pubkey captured at connect time. On mismatch, the optional `onPubkeyMismatch(expected, actual)` callback fires and `signEvent` returns a `pubkey-mismatch` failure. A host app typically wires this callback to log the user out — the same response the NIP-07 signer warrants — so an account switch on either backend never silently signs as the wrong identity.

After the pubkey check, `signEvent` verifies the returned event's Schnorr signature with `verifyEventSignature` from `@innis/nostr-core` and returns a `sign-failed` failure if it does not validate. This is fail-fast defence-in-depth against a malfunctioning signer, surfacing a bad signature at the call boundary rather than later when a relay rejects the publish — it is *not* the wire-injection guard (that is the NIP-44 envelope's authenticated encryption plus the `remoteSignerPubkey` author pin). The check is injectable via `verifyEventSignature` for tests and hardware-accelerated verifiers; it defaults to the core implementation.

### `createNip46Bunker(deps)` — the bunker (signer-side) role

```ts
interface BunkerDeps {
    readonly transport: Nip46Transport
    readonly signer: Signer        // the signer that answers as the user (NIP-07, local, etc.)
    readonly isAuthorised: (clientPubkey: PublicKey, permission: Nip46Permission) => boolean
    readonly now?: () => number
    readonly onSecretUsed?: (secret: string, clientPubkey: PublicKey) => void
}
```

Lets a logged-in app session act as a remote signer for another device. Subscribes to incoming NIP-46 requests, answers or queues them, and exposes:

- `start(userPubkey, relayUrls, secret)` / `stop()` — lifecycle. The bunker subscribes on every URL in `relayUrls` and answers on all of them. `start` throws `InvalidArgumentError` if `relayUrls` is empty — a bunker on no relays can never be reached, so that is a caller's bug — and is a no-op if `secret` is empty: a bunker without a pairing secret would authenticate anyone, so it refuses to run.
- `getBunkerUrl()` — emits the `bunker://...?relay=&relay=&secret=` URL the user pastes into another device (one `relay=` param per relay), or `null` once its secret has been used.
- `issueSecret(secret)` — makes `secret` the one the next `connect` must present, retiring any unused one. Returns `false` before `start`, or for an empty or already used secret.
- `acceptNostrConnect(url)` — accepts a client-initiated pairing: pass `parseNostrConnectUrl(pasted)` once the user agrees. The client is connected from then on, its relays are listened on and answered on alongside the bunker's own, and the URL's secret is sent back to it as a `connect` response. The URL's `perms`, `name`, `url` and `image` are the client's unauthenticated description of itself — show them, but they grant nothing. `restorePairing(clientPubkey, relays)` re-establishes such a pairing after a restart without sending the secret again.
- `getPending()` — the requests awaiting a decision, newest first. Each `PendingRequest` has an `id` (the id of the event that carried it, unique across clients), the client's `requestId`, `clientPubkey`, `receivedAt`, and a `detail` discriminated by `method`: `get_public_key`; `sign_event` with `eventToSign`; or a `nip04_*` / `nip44_*` method with `counterparty` and `payload`.
- `approve(id)` / `reject(id)` — answer a queued request by its `id`. `approve` answers as the method does (the user pubkey, the signed event, the cipher result), or `user rejected` / `signing failed` / `encryption failed` / `decryption failed` when the signer declines or fails; `reject` replies `user rejected`. Both resolve to a `Result`: the `Nip46SendFailure` when the reply reached no relay, `ok` otherwise (and for an unknown id). An automatic reply that reaches no relay is dropped; the client's own timeout is its outcome.
- `onUpdate(listener)` — subscribe to queue and subscription-status changes.

**Each secret connects one client.** The first `connect` presenting the current secret connects its client and uses the secret up. A later `connect` presenting a used secret is ignored — no reply — unless it comes from the client that used it while still connected, which is acknowledged again so a lost reply can be retried. The bunker remembers used secrets across `stop` / `start` (the last 10,000), so restarting it with a used secret does not revive it: it serves its paired clients and advertises no URL. When a secret is used, `onSecretUsed(secret, clientPubkey)` and `onUpdate` fire, and the host should:

1. generate a fresh random secret, store it in place of the used one, and call `issueSecret(fresh)` so `getBunkerUrl()` has a URL to show again;
2. persist `clientPubkey`, and after every `start` call `restorePairing(clientPubkey, [])` for each persisted client, because `stop` forgets connected clients and a `bunker://` client cannot connect again with its used secret.

The record of used secrets lives in memory, so across a reload the host's own storage is what keeps a used secret from being offered to `start` again.

**What is answered, and what is asked.** `connect` is checked against the current, unused secret, and `ping` is always answered; everything else needs a connected client. `switch_relays` is answered with the JSON list of the bunker's own relays and switches nothing; `logout` is answered `ack` and disconnects the client. For `get_public_key`, `sign_event` and the `nip04_*` / `nip44_*` methods the bunker asks `isAuthorised(clientPubkey, permission)`, where `permission` is `get_public_key`, `sign_event:<kind>` or the cipher method's name: a granted request is answered at once, an ungranted one is queued for `approve` / `reject` — nothing is refused for want of a grant. A host that wants to decide everything by hand returns `false`; one that only wants to be asked about signing returns `!permission.startsWith("sign_event")`.

**Every accepted request gets a reply.** A result too large to encrypt is replaced by the error `response too large`. The queue holds at most 1,000 requests; beyond that a request is answered `too many pending requests`. Everything else the bunker remembers per client — connected clients, their ciphers and relays, and the event ids it has seen — is bounded at 10,000 entries, oldest evicted first; an evicted client simply connects again.

### `parseBunkerUrl(raw)` / `formatBunkerUrl(url)` — `bunker-url.ts`

`parseBunkerUrl` reads `bunker://<remoteSignerPubkey>?relay=wss://...&relay=wss://...&secret=...` into `{ remoteSignerPubkey, relays, secret }`, returning `null` for malformed URLs. `formatBunkerUrl` is its inverse and the single owner of the on-wire format — `Nip46Bunker.getBunkerUrl()` builds its URL through it, so parse and format can never drift.

### `parseNostrConnectUrl(raw)` / `formatNostrConnectUrl(url)` — `nostr-connect-url.ts`

`parseNostrConnectUrl` reads `nostrconnect://<client-pubkey>?relay=...&secret=...&perms=...&name=...&url=...&image=...` into `{ clientPubkey, relays, secret, perms, name, url, image }`, returning `null` without a valid pubkey, at least one valid relay, and a secret — NIP-46 requires both. `perms` keeps each well-formed `method[:params]` permission once — any NIP-46 method, or `sign_event:<kind>` for a kind from 0 to 65535 — and drops anything else. `formatNostrConnectUrl` is its inverse.

### Transport — `transport.ts`

```ts
interface Nip46Transport {
    readonly subscribe: (params: { filter, relays, onEvent }) => { abort: () => void }
    readonly publish: (relayUrl, event) => Promise<{ ok: boolean }>
}
```

The transport is the *only* Nostr-on-the-wire surface this lib touches. It's an injected port so the lib can be ported to other environments and tested without a real relay pool. `publish` resolves with whether that relay accepted the envelope; the shape is a structural subset of `@innis/nostr-relay-pool`'s `PublishResponse`, so a host can forward the pool's result unchanged. An envelope no relay accepted can never be answered, so `sendEnvelope` returns a `Nip46SendFailure` of type `delivery-failed` and the client fails the pending request as `disconnected` straight away rather than leaving it to expire at `timeoutMs`. One accepting relay is enough — a partial success is a send. A relay that refuses, times out or cannot be reached must be reported as `{ ok: false }`; `publish` rejects only when the transport itself is broken, and that rejection propagates to the caller rather than being counted as a refusal.

A typical host wires this port directly to a relay pool's `subscribe` / `publish` (for example `@innis/nostr-relay-pool`). Bunker comms are transport-level RPC, not application content — keep them off whatever content cache and publish pipeline your app uses for ordinary events.

### Crypto adapter — `LocalSignerTools`

The client signer (above) takes `tools: LocalSignerTools` because every outgoing request envelope is *itself* a signed-and-NIP-44-encrypted Nostr event — the client signs it with its own per-session `clientSecretKey`, never the user's key. The lib delegates that crypto to the same `LocalSignerTools` adapter `@innis/nostr-core` defines (raw Schnorr `schnorrSign` over a hex id, secp256k1 `getPublicKey`, NIP-44 v2 round-trip). `@innis/nostr-core`'s `createLocalSigner` derives the event id itself through `buildRumour`, so the bag stays raw-crypto-only.

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
        logout()       -- on logout: tells the bunker, then tears down (disconnect() on any other session end)
```

The client secret key is per-session and ephemeral: it's the key the *client* uses to sign request envelopes, not the user's secret key. It never leaves the device. Loss means re-pairing with the bunker. Persisting it across reloads is the host app's responsibility — keep it in one place alongside the rest of your login state.

## Anti-patterns

- **Calling `transport.publish` directly to send application events.** The transport is for kind 24133 envelopes only. Use your app's normal publish path for ordinary content.
- **Caching a `Nip46ClientSigner` across logout/login.** The signer holds a per-session subscription and a pending-request map. Call `logout()` on logout (and delete the stored client secret key), `disconnect()` on any other session end, and construct a fresh signer on the next session — don't reuse one across sessions.
- **Storing the bunker `clientSecretKey` in a different place from the rest of your login state.** It must round-trip the same way as everything else you persist for a session.
- **Implementing the transport with a fresh, single-purpose pool.** Reuse the relay pool your app already runs; the bunker connection benefits from its reconnect/backoff/AUTH handling.
