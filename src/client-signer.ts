import type {
  CipherScheme,
  LocalSignerTools,
  NostrEvent,
  PublicKey,
  RelayUrl,
  Result,
  Signer,
  SignerFailure,
  UnsignedEvent,
} from "@innis/nostr-core"
import {
  buildUnsignedEvent,
  checkPubkeyMatches,
  constantTimeEqual,
  createLocalSigner,
  failure,
  InvalidArgumentError,
  isOk,
  isUserRejection,
  KIND_NOSTR_CONNECT,
  now as defaultNow,
  ok,
  parseJson,
  parseNostrEvent,
  parsePublicKey,
  parseRelayUrl,
  verifyEventSignature as defaultVerifyEventSignature,
} from "@innis/nostr-core"
import { reportUnhandledError } from "./unhandled-error.ts"
import { parseAuthUrl } from "./auth-url.ts"
import { createSeenEventIds } from "./bounded-map.ts"
import { clientMetadataEntries, type Nip46ClientMetadata } from "./nostr-connect-url.ts"
import type { Nip46Permission } from "./permission.ts"
import {
  CLOCK_SKEW_TOLERANCE_SECONDS,
  decryptEnvelopeJson,
  isEncryptMethod,
  type Nip46CryptoMethod,
  type Nip46Request,
  type Nip46Response,
  parseResponse,
  sendEnvelope,
} from "./protocol.ts"
import type { Nip46Subscription, Nip46Transport } from "./transport.ts"

export type { Nip46ClientMetadata } from "./nostr-connect-url.ts"

/** Dependencies for {@link createNip46ClientSigner}. */
export interface Nip46ClientSignerDeps {
  /** Pure-crypto primitives from `@innis/nostr-core` used to sign and encrypt request envelopes with the client key. */
  readonly tools: LocalSignerTools
  /** The Nostr-on-the-wire port the client publishes requests and subscribes for responses on. */
  readonly transport: Nip46Transport
  /** The per-session ephemeral secret key the client signs request envelopes with — never the user's key. */
  readonly clientSecretKey: Uint8Array
  /**
   * The remote signer's public key, taken from the `bunker://` URL — or `null` for a client-initiated
   * (`nostrconnect://`) pairing, where {@link Nip46ClientSigner.connect} learns it from the author of the `connect`
   * response that returns `secret`.
   */
  readonly remoteSignerPubkey: PublicKey | null
  /**
   * Every relay the `bunker://` URL advertised, or that the client's `nostrconnect://` URL names; requests broadcast
   * to all, responses awaited across all, until the remote signer's answer to `switch_relays` replaces them.
   */
  readonly relayUrls: ReadonlyArray<RelayUrl>
  /**
   * The pairing secret: the one from the `bunker://` URL, sent with `connect` (or `null` if it carried none), or —
   * when `remoteSignerPubkey` is `null` — the `nostrconnect://` URL's secret, which must be present and which the
   * remote signer's `connect` response must return.
   */
  readonly secret: string | null
  /** A previously known user pubkey (e.g. a restored session); when set, {@link Nip46ClientSigner.connect} skips the handshake. */
  readonly initialUserPubkey?: PublicKey | null
  /**
   * Per-request timeout in milliseconds. Defaults to 60000 (1 minute) — long enough for a human
   * to approve a prompt in their bunker, short enough that a dropped response surfaces as a
   * failure while the user is still looking at the request.
   */
  readonly timeoutMs?: number
  /** Clock returning Unix seconds; injectable for tests. Defaults to the core `now`. */
  readonly now?: () => number
  /** Factory for unique request ids. Defaults to `crypto.randomUUID()`. */
  readonly generateRequestId?: () => string
  /** Verifier for the Schnorr signature of bunker-signed events. Defaults to the core `verifyEventSignature`. */
  readonly verifyEventSignature?: (event: NostrEvent) => boolean
  /** Fired when {@link Nip46ClientSigner.signEvent} returns `pubkey-mismatch` because a signed event's pubkey differs from the known user pubkey. */
  readonly onPubkeyMismatch?: ((expected: PublicKey, actual: PublicKey) => void) | undefined
  /**
   * Fired with the URL of an `auth_url` challenge so the host can open it; the request stays pending for the real
   * reply. Only an absolute `http:` or `https:` URL with a host is ever passed, in its normalised form; a challenge
   * carrying anything else is dropped. Each challenge event fires it once, however many relays deliver it.
   */
  readonly onAuthChallenge?: ((url: string) => void) | undefined
  /**
   * How the client application describes itself to the remote signer, sent as the `optional_client_metadata` of a
   * `bunker://` pairing's `connect` request so the signer can label the connection. A `nostrconnect://` pairing
   * carries it in the URL instead.
   */
  readonly clientMetadata?: Nip46ClientMetadata | undefined
  /**
   * The permissions the client asks the remote signer to approve, sent as the `optional_requested_perms` of a
   * `bunker://` pairing's `connect` request — a display hint for the signer's user, never a grant. A
   * `nostrconnect://` pairing carries them in the URL's `perms` instead.
   */
  readonly requestedPerms?: ReadonlyArray<Nip46Permission> | undefined
}

/** A NIP-46 client that implements the core `Signer` interface, so app code cannot tell a remote bunker from a local key. */
export interface Nip46ClientSigner extends Signer {
  /**
   * Establishes the pairing (unless `initialUserPubkey` was supplied), asks the remote signer to `switch_relays`, and
   * fetches the user pubkey. For a `bunker://` pairing it sends `connect` with the secret, any
   * {@link Nip46ClientSignerDeps.requestedPerms} and any {@link Nip46ClientSignerDeps.clientMetadata}; for a
   * `nostrconnect://` pairing it opens the subscription and waits
   * for the remote signer's `connect` response returning the secret, so call it before showing the URL. The relays
   * `switch_relays` returns replace the client's own for every later request; a `null` answer, an error or an
   * unusable list keeps them. Must succeed before any signing call. A bunker that refuses the handshake or the pubkey
   * is `public-key-failed` (or `rejected`), an unreachable or silent one `disconnected`.
   */
  readonly connect: () => Promise<Result<void, SignerFailure>>
  /** Settles every in-flight request with a `disconnected` failure and tears down the subscription. */
  readonly disconnect: () => void
  /**
   * Ends the session: sends `logout`, waits for the remote signer's `"ack"`, and then — acknowledged or not — does
   * what {@link Nip46ClientSigner.disconnect} does. Any other answer, an error or a timeout is a `disconnected` (or
   * `rejected`) failure. Deleting the stored client secret key stays the host's job, whatever this returns.
   */
  readonly logout: () => Promise<Result<void, SignerFailure>>
  /**
   * The relays requests are sent and responses awaited on: the ones supplied, or those the remote signer's answer to
   * `switch_relays` put in their place, which a host restoring the session later should reuse.
   */
  readonly getRelayUrls: () => ReadonlyArray<RelayUrl>
  /** The ephemeral client public key derived from `clientSecretKey` — the origin of a `nostrconnect://` URL. */
  readonly getClientPubkey: () => PublicKey
  /** The remote signer's public key: the one supplied, or the one a `nostrconnect://` pairing learned; `null` until then. */
  readonly getRemoteSignerPubkey: () => PublicKey | null
}

interface PendingRequest {
  readonly settle: (result: Result<string, SignerFailure>) => void
  readonly failureType: SignerFailure["type"]
  readonly timer: ReturnType<typeof setTimeout>
}

interface PairingWaiter {
  readonly promise: Promise<Result<void, SignerFailure>>
  readonly resolve: (result: Result<void, SignerFailure>) => void
  readonly timer: ReturnType<typeof setTimeout>
}

const AUTH_URL = "auth_url"
const LOGOUT_ACK = "ack"

const disconnected = (message: string): Result<never, SignerFailure> => failure({ type: "disconnected", message })

const parseRelayList = (raw: string): ReadonlyArray<RelayUrl> | null => {
  const json = parseJson(raw)
  if (!isOk(json) || !Array.isArray(json.value)) return null
  const relays = json.value.map((entry: unknown) => typeof entry === "string" ? parseRelayUrl(entry) : null)
    .filter((relay) => relay !== null)
  return relays.length > 0 ? [...new Set(relays)] : null
}

const sameRelays = (a: ReadonlyArray<RelayUrl>, b: ReadonlyArray<RelayUrl>): boolean =>
  a.length === b.length && a.every((relay) => b.includes(relay))

const formatClientMetadata = (metadata: Nip46ClientMetadata | undefined): string | null => {
  const entries = metadata === undefined ? [] : clientMetadataEntries(metadata)
  return entries.length === 0 ? null : JSON.stringify(Object.fromEntries(entries))
}

const requirePairingSecret = (remoteSignerPubkey: PublicKey | null, secret: string | null): string | null => {
  if (remoteSignerPubkey !== null) return null
  if (secret === null || secret.length === 0) {
    throw new InvalidArgumentError("a nostrconnect:// pairing needs a non-empty secret for the remote signer to return")
  }
  return secret
}

/**
 * The bunker's free-text `error` as a `SignerFailure`: `rejected` when its words say the user declined — NIP-46 defines
 * no error code, so `isUserRejection` from `@innis/nostr-core` decides — otherwise the request's own failure mode.
 */
const bunkerErrorFailure = (error: string, failureType: SignerFailure["type"]): SignerFailure => ({
  type: isUserRejection(error) ? "rejected" : failureType,
  message: error,
})

/**
 * Construct a {@link Nip46ClientSigner}. Each `signEvent` / `nip04*` / `nip44*` call is JSON-encoded, NIP-44
 * encrypted to the remote signer, signed with the ephemeral client key, and published as a kind 24133 event
 * to every relay; the matching response is awaited on one subscription spanning all relays. `signEvent`
 * additionally checks the returned pubkey against the user pubkey ({@link Nip46ClientSignerDeps.onPubkeyMismatch})
 * and verifies the event signature before resolving. An event redelivered by several relays is handled once.
 *
 * No method throws an anticipated outcome; each returns a `Failure(SignerFailure)`: `disconnected` when the request
 * timed out, was cut off by {@link Nip46ClientSigner.disconnect}, never reached a relay, or was made before
 * {@link Nip46ClientSigner.connect}; `rejected` when the bunker's error says the user declined; `pubkey-mismatch`
 * when it signed as another key; otherwise the method's own mode (`public-key-failed`, `sign-failed`,
 * `encrypt-failed`, `decrypt-failed`) carrying the bunker's error or the defect in its answer. A transport whose
 * `publish` rejects is a fault, and the call rejects with it. A template that is not a NIP-01 event is the caller's
 * fault too: `buildUnsignedEvent` refuses it before any request is sent, and `signEvent` rejects with
 * `InvalidArgumentError`, as every `Signer` does. Throws if `remoteSignerPubkey` is `null` and there is
 * no secret for a `nostrconnect://` pairing.
 */
export const createNip46ClientSigner = ({
  tools,
  transport,
  clientSecretKey,
  remoteSignerPubkey,
  relayUrls,
  secret,
  initialUserPubkey = null,
  timeoutMs = 60_000,
  now = defaultNow,
  generateRequestId = () => globalThis.crypto.randomUUID(),
  verifyEventSignature = defaultVerifyEventSignature,
  onPubkeyMismatch,
  onAuthChallenge,
  clientMetadata,
  requestedPerms = [],
}: Nip46ClientSignerDeps): Nip46ClientSigner => {
  const pairingSecret = requirePairingSecret(remoteSignerPubkey, secret)
  const connectMetadata = formatClientMetadata(clientMetadata)
  const clientPubkey = tools.getPublicKey(clientSecretKey)
  const envelopeSigner = createLocalSigner(clientSecretKey, tools)
  const pending = new Map<string, PendingRequest>()
  const seenEventIds = createSeenEventIds()
  let remoteSigner: PublicKey | null = remoteSignerPubkey
  let relays: ReadonlyArray<RelayUrl> = relayUrls
  let userPubkey: PublicKey | null = initialUserPubkey
  let peerCipher: CipherScheme = "nip44"
  let subscription: Nip46Subscription | null = null
  let pairing: PairingWaiter | null = null

  const settlePending = (id: string, result: Result<string, SignerFailure>): void => {
    const request = pending.get(id)
    if (!request) return
    pending.delete(id)
    clearTimeout(request.timer)
    request.settle(result)
  }

  const settlePairing = (result: Result<void, SignerFailure>): void => {
    const waiter = pairing
    if (waiter === null) return
    pairing = null
    clearTimeout(waiter.timer)
    waiter.resolve(result)
  }

  const completePairing = (author: PublicKey, response: Nip46Response, cipher: CipherScheme): void => {
    if (pairingSecret === null || response.result === undefined) return
    if (!constantTimeEqual(response.result, pairingSecret)) return
    remoteSigner = author
    peerCipher = cipher
    settlePairing(ok(undefined))
  }

  const handleChallenge = (response: Nip46Response, request: PendingRequest): void => {
    const url = parseAuthUrl(response.error ?? "")
    if (url === null) return
    if (onAuthChallenge) {
      onAuthChallenge(url)
      return
    }
    settlePending(
      response.id,
      failure({ type: request.failureType, message: `bunker requires authentication: ${url}` }),
    )
  }

  const handleResponse = (response: Nip46Response): void => {
    const request = pending.get(response.id)
    if (!request) return
    if (response.result === AUTH_URL) {
      handleChallenge(response, request)
      return
    }
    if (response.error !== undefined) {
      settlePending(response.id, failure(bunkerErrorFailure(response.error, request.failureType)))
      return
    }
    if (response.result === undefined) {
      settlePending(response.id, failure({ type: request.failureType, message: "bunker answered with no result" }))
      return
    }
    settlePending(response.id, ok(response.result))
  }

  const isFromRemoteSigner = (author: PublicKey): boolean => remoteSigner === null || author === remoteSigner

  const handleEvent = async (event: NostrEvent): Promise<void> => {
    // Deliberate: redelivered events are dropped before decrypting, not left to the pending map — an auth_url challenge bypasses it — see ADR-0006
    if (!isFromRemoteSigner(event.pubkey) || !seenEventIds.remember(event.id)) return
    const decoded = await decryptEnvelopeJson({
      signer: envelopeSigner,
      peerPubkey: event.pubkey,
      ciphertext: event.content,
    })
    if (decoded === null) return
    const response = parseResponse(decoded.value)
    if (remoteSigner === null) {
      if (response !== null) completePairing(event.pubkey, response, decoded.cipher)
      return
    }
    if (event.pubkey !== remoteSigner) return
    peerCipher = decoded.cipher
    if (response !== null) handleResponse(response)
  }

  const ensureSubscription = (): void => {
    if (subscription) return
    subscription = transport.subscribe({
      filter: {
        kinds: [KIND_NOSTR_CONNECT],
        ...(remoteSigner === null ? {} : { authors: [remoteSigner] }),
        "#p": [clientPubkey],
        since: now() - CLOCK_SKEW_TOLERANCE_SECONDS,
      },
      relays,
      onEvent: (event) => {
        handleEvent(event).catch(reportUnhandledError)
      },
    })
  }

  const awaitPairing = (): Promise<Result<void, SignerFailure>> => {
    if (remoteSigner !== null) return Promise.resolve(ok(undefined))
    if (pairing !== null) return pairing.promise
    ensureSubscription()
    const { promise, resolve } = Promise.withResolvers<Result<void, SignerFailure>>()
    const timer = setTimeout(() => settlePairing(disconnected("bunker pairing timed out")), timeoutMs)
    pairing = { promise, resolve, timer }
    return promise
  }

  const sendRequest = (
    method: string,
    params: ReadonlyArray<string>,
    failureType: SignerFailure["type"],
  ): Promise<Result<string, SignerFailure>> => {
    const peerPubkey = remoteSigner
    if (peerPubkey === null) return Promise.resolve(disconnected("bunker not paired — call connect() first"))
    ensureSubscription()
    return new Promise<Result<string, SignerFailure>>((resolve, reject) => {
      const id = generateRequestId()
      const timer = setTimeout(() => settlePending(id, disconnected("bunker request timed out")), timeoutMs)
      pending.set(id, { settle: resolve, failureType, timer })
      ;(async () => {
        const payload: Nip46Request = { id, method, params }
        const sent = await sendEnvelope({
          signer: envelopeSigner,
          transport,
          relays,
          peerPubkey,
          payload,
          cipher: peerCipher,
          now,
        })
        if (sent.success) return
        const { type, message } = sent.error
        settlePending(id, type === "delivery-failed" ? disconnected(message) : failure({ type: failureType, message }))
      })().catch((err: unknown) => {
        if (!pending.delete(id)) return
        clearTimeout(timer)
        reject(err)
      })
    })
  }

  const connectParams = (peer: PublicKey): ReadonlyArray<string> => {
    const params = [peer, secret ?? "", requestedPerms.join(","), connectMetadata ?? ""]
    while (params.length > 1 && params[params.length - 1] === "") params.pop()
    return params
  }

  const sendConnect = (peer: PublicKey): Promise<Result<string, SignerFailure>> =>
    sendRequest("connect", connectParams(peer), "public-key-failed")

  const switchRelays = async (): Promise<void> => {
    const answer = await sendRequest("switch_relays", [], "disconnected")
    const switched = answer.success ? parseRelayList(answer.value) : null
    // Deliberate: a switch that fails or names no usable relay keeps the client's relays and does not fail connect — see ADR-0018
    if (switched === null || sameRelays(switched, relays)) return
    relays = switched
    subscription?.abort()
    subscription = null
    ensureSubscription()
  }

  const connect = async (): Promise<Result<void, SignerFailure>> => {
    if (userPubkey) {
      ensureSubscription()
      return ok(undefined)
    }
    const established = pairingSecret === null && remoteSigner !== null
      ? await sendConnect(remoteSigner)
      : await awaitPairing()
    if (!established.success) return established
    await switchRelays()
    const pubkey = await getPublicKey()
    return pubkey.success ? ok(undefined) : pubkey
  }

  const disconnect = (): void => {
    if (subscription) {
      subscription.abort()
      subscription = null
    }
    for (const { settle, timer } of pending.values()) {
      clearTimeout(timer)
      settle(disconnected("bunker disconnected"))
    }
    pending.clear()
    settlePairing(disconnected("bunker disconnected"))
    userPubkey = null
  }

  const logout = async (): Promise<Result<void, SignerFailure>> => {
    try {
      const answer = await sendRequest("logout", [], "disconnected")
      if (!answer.success) return answer
      if (answer.value === LOGOUT_ACK) return ok(undefined)
      return disconnected(`bunker answered logout with ${answer.value} rather than ack`)
    } finally {
      disconnect()
    }
  }

  const getPublicKey = async (): Promise<Result<PublicKey, SignerFailure>> => {
    if (userPubkey) return ok(userPubkey)
    const raw = await sendRequest("get_public_key", [], "public-key-failed")
    if (!raw.success) return raw
    const parsed = parsePublicKey(raw.value)
    if (parsed === null) return failure({ type: "public-key-failed", message: "bunker returned invalid public key" })
    userPubkey = parsed
    return ok(parsed)
  }

  const signEvent = async (event: UnsignedEvent): Promise<Result<NostrEvent, SignerFailure>> => {
    const template = buildUnsignedEvent(event)
    if (userPubkey === null) return disconnected("bunker not connected — call connect() before signEvent")
    const raw = await sendRequest("sign_event", [JSON.stringify(template)], "sign-failed")
    if (!raw.success) return raw
    const json = parseJson(raw.value)
    const signed = isOk(json) ? parseNostrEvent(json.value) : null
    if (!signed) return failure({ type: "sign-failed", message: "bunker returned invalid sign_event response" })
    const mismatch = checkPubkeyMatches(userPubkey, signed.pubkey)
    if (mismatch !== null) {
      onPubkeyMismatch?.(userPubkey, signed.pubkey)
      return failure(mismatch)
    }
    if (!verifyEventSignature(signed)) {
      return failure({ type: "sign-failed", message: "bunker returned an event with an invalid signature" })
    }
    return ok(signed)
  }

  const callRemote = (
    method: Nip46CryptoMethod,
    peerPubkey: PublicKey,
    payload: string,
  ): Promise<Result<string, SignerFailure>> =>
    sendRequest(method, [peerPubkey, payload], isEncryptMethod(method) ? "encrypt-failed" : "decrypt-failed")

  const nip44Encrypt = (peerPubkey: PublicKey, plaintext: string): Promise<Result<string, SignerFailure>> =>
    callRemote("nip44_encrypt", peerPubkey, plaintext)

  const nip44Decrypt = (peerPubkey: PublicKey, ciphertext: string): Promise<Result<string, SignerFailure>> =>
    callRemote("nip44_decrypt", peerPubkey, ciphertext)

  const nip04Encrypt = (peerPubkey: PublicKey, plaintext: string): Promise<Result<string, SignerFailure>> =>
    callRemote("nip04_encrypt", peerPubkey, plaintext)

  const nip04Decrypt = (peerPubkey: PublicKey, ciphertext: string): Promise<Result<string, SignerFailure>> =>
    callRemote("nip04_decrypt", peerPubkey, ciphertext)

  return Object.freeze({
    kind: "bunker",
    getPublicKey,
    signEvent,
    nip04Encrypt,
    nip04Decrypt,
    nip44Encrypt,
    nip44Decrypt,
    connect,
    disconnect,
    logout,
    getRelayUrls: () => relays,
    getClientPubkey: () => clientPubkey,
    getRemoteSignerPubkey: () => remoteSigner,
  })
}
