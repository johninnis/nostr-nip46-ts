import type { EventId, NostrEvent, PublicKey, RelayUrl, Result, Signer } from "@innis/nostr-core"
import {
  constantTimeEqual,
  failure,
  InvalidArgumentError,
  KIND_NOSTR_CONNECT,
  now as defaultNow,
  ok,
  verifyEventSignature as defaultVerifyEventSignature,
} from "@innis/nostr-core"
import { reportUnhandledError } from "./unhandled-error.ts"
import { createBoundedMap } from "./bounded-map.ts"
import { type BunkerSession, createBunkerSession } from "./bunker-session.ts"
import { formatBunkerUrl } from "./bunker-url.ts"
import type { NostrConnectUrl } from "./nostr-connect-url.ts"
import {
  answerDetail,
  type Nip46Permission,
  parseCipherDetail,
  parseSignEventDetail,
  type PendingRequest,
  type PendingRequestDetail,
  permissionFor,
  USER_REJECTED,
} from "./pending-request.ts"
import {
  CLOCK_SKEW_TOLERANCE_SECONDS,
  decryptEnvelopeJson,
  isNip46CryptoMethod,
  type Nip46Request,
  type Nip46Response,
  type Nip46SendFailure,
  parseRequest,
  sendEnvelope,
} from "./protocol.ts"
import type { Nip46Subscription, Nip46SubscriptionStatus, Nip46Transport } from "./transport.ts"

export type {
  CipherDetail,
  GetPublicKeyDetail,
  Nip46Permission,
  PendingRequest,
  PendingRequestDetail,
  SignEventDetail,
  UnsignedEventInput,
} from "./pending-request.ts"

/** Dependencies for {@link createNip46Bunker}. */
export interface BunkerDeps {
  /** The Nostr-on-the-wire port the bunker subscribes and publishes on. */
  readonly transport: Nip46Transport
  /** The signer that answers requests as the user (a NIP-07, local, or other `Signer`). */
  readonly signer: Signer
  /**
   * Whether the host has granted `permission` to the connected client `clientPubkey`. Asked for every
   * `get_public_key`, `sign_event` and `nip04_*` / `nip44_*` request: a granted request is answered at once, an
   * ungranted one is queued for {@link Nip46Bunker.approve} or {@link Nip46Bunker.reject}. A host that wants to
   * decide everything by hand returns `false`.
   */
  readonly isAuthorised: (clientPubkey: PublicKey, permission: Nip46Permission) => boolean
  /** Clock returning Unix seconds; injectable for tests. Defaults to the core `now`. */
  readonly now?: (() => number) | undefined
  /** Verifier for the Schnorr signature of inbound request events, checked before deduplication and decryption. Defaults to the core `verifyEventSignature`. */
  readonly verifyEventSignature?: ((event: NostrEvent) => boolean) | undefined
  /**
   * Fired when a client connects with the bunker's current secret. The secret is used up from then on — a later
   * `connect` presenting it is ignored — and {@link Nip46Bunker.getBunkerUrl} returns `null` until
   * {@link Nip46Bunker.issueSecret} supplies a fresh one. The host persists `clientPubkey` to
   * {@link Nip46Bunker.restorePairing} it after a restart, and replaces its stored secret so it never starts with a
   * used one.
   */
  readonly onSecretUsed?: ((secret: string, clientPubkey: PublicKey) => void) | undefined
}

/** The signer-side (bunker) role: subscribes to incoming requests, answers or queues them, and replies over the transport. */
export interface Nip46Bunker {
  /**
   * Begins serving as a remote signer for `userPubkey` on `relayUrls`, accepting one `connect` with `secret`. Throws
   * `InvalidArgumentError` if `relayUrls` is empty — a bunker on no relays can never be reached, so starting one is a
   * caller's bug. A no-op if `secret` is empty. A `secret` already used is not accepted again, even across
   * a restart of the same bunker: it serves its paired clients but advertises no URL until
   * {@link Nip46Bunker.issueSecret}.
   */
  readonly start: (userPubkey: PublicKey, relayUrls: ReadonlyArray<RelayUrl>, secret: string) => void
  /** Tears down every subscription and clears all session state; the record of used secrets is kept. */
  readonly stop: () => void
  /**
   * Replaces the secret the next `connect` must present, retiring any unused one. Returns `false`, changing nothing,
   * before {@link Nip46Bunker.start} or for an empty or already used secret.
   */
  readonly issueSecret: (secret: string) => boolean
  /**
   * The `bunker://...` URL to paste into another device, carrying the current unused secret — or `null` before
   * {@link Nip46Bunker.start}, or once the secret is used until {@link Nip46Bunker.issueSecret}.
   */
  readonly getBunkerUrl: () => string | null
  /** The requests awaiting a decision, ordered most-recently-received first. */
  readonly getPending: () => ReadonlyArray<PendingRequest>
  /**
   * Answers the queued request with this carrier event id as its method does — the user pubkey, the signed event,
   * the cipher result, or a correlated error when the signer declines or fails. Returns the {@link Nip46SendFailure}
   * when the reply reached no relay; `ok` for an unknown id, which it ignores. Rejects if the transport faults.
   */
  readonly approve: (id: EventId) => Promise<Result<void, Nip46SendFailure>>
  /**
   * Declines the queued request with this carrier event id, replying `user rejected`. Returns the
   * {@link Nip46SendFailure} when the reply reached no relay; `ok` for an unknown id, which it ignores.
   */
  readonly reject: (id: EventId) => Promise<Result<void, Nip46SendFailure>>
  /**
   * Accepts a client-initiated pairing the user pasted: the URL's client is connected from now on, its relays are
   * listened on and answered on alongside the bunker's own, and the URL's secret is returned to it as a `connect`
   * response. The URL's `perms` grant nothing. Returns `delivery-failed` before {@link Nip46Bunker.start}.
   */
  readonly acceptNostrConnect: (url: NostrConnectUrl) => Promise<Result<void, Nip46SendFailure>>
  /**
   * Re-establishes a pairing the host accepted before a restart, without sending the secret again: the client is
   * connected and its relays are listened on and answered on. Returns `false` before {@link Nip46Bunker.start}.
   */
  readonly restorePairing: (clientPubkey: PublicKey, relays: ReadonlyArray<RelayUrl>) => boolean
  /** The status of the subscription on the bunker's own relays — `closed` before {@link Nip46Bunker.start} and after {@link Nip46Bunker.stop}. */
  readonly getSubscriptionStatus: () => Nip46SubscriptionStatus
  /** Registers a listener fired whenever the queue, the subscription status or the advertised secret changes; returns an unsubscribe function. */
  readonly onUpdate: (listener: () => void) => () => void
}

interface IncomingRequest {
  readonly carrierId: EventId
  readonly clientPubkey: PublicKey
  readonly request: Nip46Request
}

type Sent = Promise<Result<void, Nip46SendFailure>>

const NOT_CONNECTED = "not connected"
const RESPONSE_TOO_LARGE = "response too large"
const TOO_MANY_PENDING_REQUESTS = "too many pending requests"
const OPEN_METHODS: ReadonlySet<string> = new Set(["connect", "ping"])
const USED_SECRET_LIMIT = 10_000

/**
 * Construct a {@link Nip46Bunker} — a remote signer that lets a logged-in session sign for another device.
 * It subscribes for kind 24133 requests p-tagged to the user and connects clients by the pairing secret
 * (`connect`), each secret once, or by an accepted `nostrconnect://` URL. It answers `ping`, `switch_relays` and `logout` itself, and
 * answers `get_public_key`, `sign_event` and the `nip04_*` / `nip44_*` methods at once when
 * {@link BunkerDeps.isAuthorised} grants them, queueing them for the host otherwise. Every accepted request gets a
 * correlated reply. A reply that reaches no relay is an anticipated outcome: `approve` and `reject` return it, and an
 * automatic reply has no caller to hear it, so it is dropped and the client's own timeout is its outcome.
 */
export const createNip46Bunker = (
  {
    transport,
    signer,
    isAuthorised,
    now = defaultNow,
    verifyEventSignature = defaultVerifyEventSignature,
    onSecretUsed,
  }: BunkerDeps,
): Nip46Bunker => {
  const listeners = new Set<() => void>()
  // Deliberate: used secrets outlive the session and are bounded; eviction can never re-admit one — see ADR-0017
  const usedSecrets = createBoundedMap<PublicKey>(USED_SECRET_LIMIT)

  let session: BunkerSession | null = null
  let secret: string | null = null
  let subscriptions: Array<Nip46Subscription> = []
  let subscriptionStatus: Nip46SubscriptionStatus = "closed"

  const callHost = (callback: () => void): void => {
    try {
      callback()
    } catch (err) {
      reportUnhandledError(err)
    }
  }

  const notify = (): void => {
    for (const listener of listeners) callHost(listener)
  }

  const seal = (active: BunkerSession, clientPubkey: PublicKey, payload: Nip46Response): Sent =>
    sendEnvelope({
      signer,
      transport,
      relays: active.relaysFor(clientPubkey),
      peerPubkey: clientPubkey,
      payload,
      cipher: active.cipherFor(clientPubkey),
      now,
    })

  const respond = async (active: BunkerSession, clientPubkey: PublicKey, response: Nip46Response): Sent => {
    const sent = await seal(active, clientPubkey, response)
    if (sent.success || sent.error.type !== "encrypt-failed" || response.result === undefined) return sent
    // Deliberate: a result too large to seal is replaced by a small correlated error so the client is not left waiting — see ADR-0004
    return seal(active, clientPubkey, { id: response.id, error: RESPONSE_TOO_LARGE })
  }

  const reply = (active: BunkerSession, incoming: IncomingRequest, response: Omit<Nip46Response, "id">): Sent =>
    respond(active, incoming.clientPubkey, { ...response, id: incoming.request.id })

  const answer = async (active: BunkerSession, request: PendingRequest): Sent =>
    respond(
      active,
      request.clientPubkey,
      await answerDetail(request.detail, request.requestId, { signer, userPubkey: active.userPubkey, now }),
    )

  // Deliberate: an ungranted request is queued for the host to decide, never refused — see ADR-0011
  const decide = (active: BunkerSession, incoming: IncomingRequest, detail: PendingRequestDetail): Sent => {
    const request: PendingRequest = {
      id: incoming.carrierId,
      requestId: incoming.request.id,
      clientPubkey: incoming.clientPubkey,
      receivedAt: now(),
      detail,
    }
    if (isAuthorised(incoming.clientPubkey, permissionFor(detail))) return answer(active, request)
    if (!active.queue(request)) return reply(active, incoming, { error: TOO_MANY_PENDING_REQUESTS })
    notify()
    return Promise.resolve(ok(undefined))
  }

  const reconnect = (active: BunkerSession, incoming: IncomingRequest, usedBy: PublicKey): Sent => {
    // Deliberate: the client that used a secret is acknowledged again, anyone else ignored — see ADR-0017
    if (usedBy === incoming.clientPubkey && active.isAuthenticated(usedBy)) {
      return reply(active, incoming, { result: "ack" })
    }
    return Promise.resolve(ok(undefined))
  }

  const useSecret = (active: BunkerSession, incoming: IncomingRequest, used: string): Sent => {
    usedSecrets.set(used, incoming.clientPubkey)
    secret = null
    active.authenticate(incoming.clientPubkey)
    if (onSecretUsed) callHost(() => onSecretUsed(used, incoming.clientPubkey))
    notify()
    return reply(active, incoming, { result: "ack" })
  }

  const connect = (active: BunkerSession, incoming: IncomingRequest): Sent => {
    const [requestedSigner = "", providedSecret = ""] = incoming.request.params
    // Deliberate: an empty signer key is accepted on the secret alone, as some deployed clients send it — see ADR-0016
    if (requestedSigner !== "" && requestedSigner !== active.userPubkey) {
      return reply(active, incoming, { error: "invalid signer" })
    }
    const usedBy = usedSecrets.get(providedSecret)
    if (usedBy !== undefined) return reconnect(active, incoming, usedBy)
    if (secret === null || !constantTimeEqual(providedSecret, secret)) {
      return reply(active, incoming, { error: "invalid secret" })
    }
    return useSecret(active, incoming, secret)
  }

  const logout = (active: BunkerSession, incoming: IncomingRequest): Sent => {
    const sent = reply(active, incoming, { result: "ack" })
    active.deauthenticate(incoming.clientPubkey)
    return sent
  }

  const signEvent = (active: BunkerSession, incoming: IncomingRequest): Sent => {
    const detail = parseSignEventDetail(incoming.request.params[0])
    return detail === null ? reply(active, incoming, { error: "invalid event" }) : decide(active, incoming, detail)
  }

  const dispatch = (active: BunkerSession, incoming: IncomingRequest): Sent => {
    const { method, params } = incoming.request
    if (!OPEN_METHODS.has(method) && !active.isAuthenticated(incoming.clientPubkey)) {
      return reply(active, incoming, { error: NOT_CONNECTED })
    }
    switch (method) {
      case "connect":
        return connect(active, incoming)
      case "ping":
        return reply(active, incoming, { result: "pong" })
      case "switch_relays":
        // Deliberate: reports the signer's own relays and switches nothing — see ADR-0012
        return reply(active, incoming, { result: JSON.stringify(active.relays) })
      case "logout":
        return logout(active, incoming)
      case "get_public_key":
        return decide(active, incoming, { method })
      case "sign_event":
        return signEvent(active, incoming)
    }
    if (!isNip46CryptoMethod(method)) return reply(active, incoming, { error: `unsupported method: ${method}` })
    const detail = parseCipherDetail(method, params)
    return detail === null ? reply(active, incoming, { error: "invalid params" }) : decide(active, incoming, detail)
  }

  const handleEvent = async (active: BunkerSession, event: NostrEvent): Promise<void> => {
    // Deliberate: the signature is verified before deduplication and decryption — it is what binds created_at and the event id a replay would freshen — see ADR-0021
    if (!verifyEventSignature(event)) return
    if (!active.rememberSeen(event.id)) return
    const decoded = await decryptEnvelopeJson({ signer, peerPubkey: event.pubkey, ciphertext: event.content })
    if (decoded === null || session !== active) return
    active.recordCipher(event.pubkey, decoded.cipher)
    const request = parseRequest(decoded.value)
    if (request === null) return
    await dispatch(active, { carrierId: event.id, clientPubkey: event.pubkey, request })
  }

  const listenOn = (
    active: BunkerSession,
    relays: ReadonlyArray<RelayUrl>,
    onStatus?: (status: Nip46SubscriptionStatus) => void,
  ): void => {
    if (relays.length === 0) return
    subscriptions.push(transport.subscribe({
      filter: { kinds: [KIND_NOSTR_CONNECT], "#p": [active.userPubkey], since: now() - CLOCK_SKEW_TOLERANCE_SECONDS },
      relays,
      onEvent: (event) => {
        handleEvent(active, event).catch(reportUnhandledError)
      },
      onStatus,
    }))
  }

  const pair = (active: BunkerSession, clientPubkey: PublicKey, relays: ReadonlyArray<RelayUrl>): void => {
    active.recordRelays(clientPubkey, relays)
    active.authenticate(clientPubkey)
    listenOn(active, active.startListeningOn(relays))
  }

  const stop = (): void => {
    for (const subscription of subscriptions) subscription.abort()
    subscriptions = []
    session = null
    secret = null
    subscriptionStatus = "closed"
    notify()
  }

  const start = (userPubkey: PublicKey, relayUrls: ReadonlyArray<RelayUrl>, initialSecret: string): void => {
    stop()
    if (relayUrls.length === 0) throw new InvalidArgumentError("a bunker cannot start on an empty relay set")
    if (initialSecret.length === 0) return
    const active = createBunkerSession({ userPubkey, relays: [...relayUrls] })
    session = active
    secret = usedSecrets.has(initialSecret) ? null : initialSecret
    listenOn(active, active.relays, (status) => {
      subscriptionStatus = status
      notify()
    })
  }

  const acceptNostrConnect = (url: NostrConnectUrl): Sent => {
    const active = session
    if (active === null) {
      return Promise.resolve(failure({ type: "delivery-failed", message: "the bunker is not started" }))
    }
    pair(active, url.clientPubkey, url.relays)
    return respond(active, url.clientPubkey, { id: globalThis.crypto.randomUUID(), result: url.secret })
  }

  const restorePairing = (clientPubkey: PublicKey, relays: ReadonlyArray<RelayUrl>): boolean => {
    const active = session
    if (active === null) return false
    pair(active, clientPubkey, relays)
    return true
  }

  const issueSecret = (fresh: string): boolean => {
    if (session === null || fresh.length === 0 || usedSecrets.has(fresh)) return false
    secret = fresh
    notify()
    return true
  }

  const getBunkerUrl = (): string | null =>
    session === null || secret === null ? null : formatBunkerUrl({
      remoteSignerPubkey: session.userPubkey,
      relays: session.relays,
      secret,
    })

  const getPending = (): ReadonlyArray<PendingRequest> =>
    [...(session?.pending() ?? [])].sort((a, b) => b.receivedAt - a.receivedAt)

  const settle = (id: EventId, respondTo: (active: BunkerSession, request: PendingRequest) => Sent): Sent => {
    const active = session
    const request = active?.take(id)
    if (active === null || request === undefined) return Promise.resolve(ok(undefined))
    notify()
    return respondTo(active, request)
  }

  const approve = (id: EventId): Sent => settle(id, answer)

  const reject = (id: EventId): Sent =>
    settle(
      id,
      (active, request) => respond(active, request.clientPubkey, { id: request.requestId, error: USER_REJECTED }),
    )

  const onUpdate = (listener: () => void): () => void => {
    listeners.add(listener)
    return (): void => {
      listeners.delete(listener)
    }
  }

  return Object.freeze({
    start,
    stop,
    issueSecret,
    getBunkerUrl,
    getPending,
    approve,
    reject,
    acceptNostrConnect,
    restorePairing,
    getSubscriptionStatus: (): Nip46SubscriptionStatus => subscriptionStatus,
    onUpdate,
  })
}
