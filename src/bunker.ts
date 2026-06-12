import type { NostrEvent, PublicKey, RelayUrl, Signer, Tag, UnsignedEvent } from "@innis/nostr-core"
import {
  constantTimeEqual,
  isRecord,
  isValidPublicKey,
  isValidTag,
  KIND_NOSTR_CONNECT,
  now as defaultNow,
  reportUnhandledError,
  tryParseJson,
} from "@innis/nostr-core"
import {
  CLOCK_SKEW_TOLERANCE_SECONDS,
  decryptEnvelopeJson,
  type EnvelopeCipher,
  type Nip46Request,
  type Nip46Response,
  parseRequest,
  sendEnvelope,
  signerCryptoMethodFor,
} from "./protocol.ts"
import { formatBunkerUrl } from "./bunker-url.ts"
import type { Nip46Subscription, Nip46Transport } from "./transport.ts"

/** A `sign_event` request body as received from a client — the fields the bunker will sign, with optional parts defaulted at approval time. */
export interface UnsignedEventInput {
  /** The event kind the client wants signed. */
  readonly kind: number
  /** The event timestamp; defaults to the approval-time clock when omitted. */
  readonly created_at?: number
  /** The event tags; defaults to an empty list when omitted. */
  readonly tags?: ReadonlyArray<Tag>
  /** The event content; defaults to an empty string when omitted. */
  readonly content?: string
}

/** A queued `sign_event` request awaiting the user's approval or rejection. */
export interface PendingSignRequest {
  /** The NIP-46 request id, echoed back in the response so the client can correlate it. */
  readonly id: string
  /** The public key of the client that sent the request. */
  readonly clientPubkey: PublicKey
  /** When the request was received, from the injected clock — used to order the queue newest-first. */
  readonly receivedAt: number
  /** The event the client is asking to have signed. */
  readonly eventToSign: UnsignedEventInput
}

/** Dependencies for {@link createNip46Bunker}. */
export interface BunkerDeps {
  /** The Nostr-on-the-wire port the bunker subscribes and publishes on. */
  readonly transport: Nip46Transport
  /** The signer that actually approves requests (a NIP-07, local, or other `Signer`). */
  readonly signer: Signer
  /** Clock returning Unix seconds; injectable for tests. Defaults to the core `now`. */
  readonly now?: () => number
}

/** The signer-side (bunker) role: subscribes to incoming requests, queues `sign_event`s for approval, and answers over the transport. */
export interface Nip46Bunker {
  /** Begins serving as a remote signer for `userPubkey` on `relayUrls`, gated by `secret`. A no-op if `relayUrls` is empty or `secret` is empty. */
  readonly start: (userPubkey: PublicKey, relayUrls: ReadonlyArray<RelayUrl>, secret: string) => void
  /** Tears down the subscription and clears all session state. */
  readonly stop: () => void
  /** The `bunker://...` URL to paste into another device, or `null` before {@link Nip46Bunker.start}. */
  readonly getBunkerUrl: () => string | null
  /** The current approval queue, ordered most-recently-received first. */
  readonly getPending: () => ReadonlyArray<PendingSignRequest>
  /** Signs and answers the queued request with the given id; a no-op for an unknown id. */
  readonly approve: (id: string) => Promise<void>
  /** Declines the queued request with the given id, replying `user rejected`; a no-op for an unknown id. */
  readonly reject: (id: string) => Promise<void>
  /** Registers a listener fired whenever the queue changes; returns an unsubscribe function. */
  readonly onUpdate: (listener: () => void) => () => void
}

const SEEN_EVENT_LIMIT = 10_000
const CLIENT_CIPHER_LIMIT = 10_000

interface BoundedKeyed {
  readonly size: number
  readonly keys: () => IterableIterator<string>
  readonly delete: (key: string) => boolean
}

const evictOldest = (tracked: BoundedKeyed, limit: number): void => {
  if (tracked.size <= limit) return
  const oldest = tracked.keys().next().value
  if (oldest !== undefined) tracked.delete(oldest)
}

const parseUnsignedEventInput = (value: unknown): UnsignedEventInput | null => {
  if (!isRecord(value)) return null
  if (typeof value.kind !== "number") return null
  if (value.created_at !== undefined && typeof value.created_at !== "number") return null
  if (value.content !== undefined && typeof value.content !== "string") return null
  const tags = value.tags
  if (tags !== undefined && (!Array.isArray(tags) || !tags.every(isValidTag))) return null
  return { kind: value.kind, created_at: value.created_at, content: value.content, tags }
}

/**
 * Construct a {@link Nip46Bunker} — a remote signer that lets a logged-in session sign for another device.
 * It subscribes for kind 24133 requests p-tagged to the user, authenticates clients by the pairing secret
 * (`connect`), answers `ping` / `get_public_key` / `nip04_*` / `nip44_*` directly, and queues `sign_event`
 * requests for the host to {@link Nip46Bunker.approve} or {@link Nip46Bunker.reject}.
 */
export const createNip46Bunker = ({ transport, signer, now = defaultNow }: BunkerDeps): Nip46Bunker => {
  const pending = new Map<string, PendingSignRequest>()
  const seenEventIds = new Set<string>()
  const authenticatedClients = new Set<string>()
  const clientEnvelopeCipher = new Map<string, EnvelopeCipher>()
  const listeners = new Set<() => void>()

  let userPubkey: PublicKey | null = null
  let relays: ReadonlyArray<RelayUrl> = []
  let secret: string | null = null
  let subscription: Nip46Subscription | null = null

  const notify = (): void => {
    for (const listener of listeners) {
      try {
        listener()
      } catch (err) {
        reportUnhandledError(err)
      }
    }
  }

  const markSeen = (id: string): boolean => {
    if (seenEventIds.has(id)) return false
    seenEventIds.add(id)
    evictOldest(seenEventIds, SEEN_EVENT_LIMIT)
    return true
  }

  const sendResponse = async (
    clientPubkey: PublicKey,
    payload: Nip46Response,
  ): Promise<void> => {
    if (relays.length === 0) return
    const cipher = clientEnvelopeCipher.get(clientPubkey) ?? "nip44"
    const sent = await sendEnvelope({ signer, transport, relays, peerPubkey: clientPubkey, payload, cipher, now })
    if (!sent.success) {
      reportUnhandledError(
        new Error(`NIP-46 response encryption failed (${cipher}): ${sent.error.tag} — ${sent.error.message}`),
      )
    }
  }

  const isAuthenticated = (clientPubkey: PublicKey): boolean =>
    secret !== null && authenticatedClients.has(clientPubkey)

  const queueSignRequest = async (clientPubkey: PublicKey, request: Nip46Request): Promise<void> => {
    const rawJson = request.params[0]
    if (!rawJson) {
      await sendResponse(clientPubkey, { id: request.id, error: "missing event" })
      return
    }
    const eventToSign = parseUnsignedEventInput(tryParseJson(rawJson))
    if (!eventToSign) {
      await sendResponse(clientPubkey, { id: request.id, error: "invalid event" })
      return
    }
    pending.set(request.id, { id: request.id, clientPubkey, receivedAt: now(), eventToSign })
    notify()
  }

  const dispatch = async (clientPubkey: PublicKey, request: Nip46Request): Promise<void> => {
    if (request.method === "connect") {
      if (request.params[0] !== userPubkey) {
        return sendResponse(clientPubkey, { id: request.id, error: "invalid signer" })
      }
      const providedSecret = request.params[1] ?? ""
      if (secret === null || !constantTimeEqual(providedSecret, secret)) {
        return sendResponse(clientPubkey, { id: request.id, error: "invalid secret" })
      }
      authenticatedClients.add(clientPubkey)
      return sendResponse(clientPubkey, { id: request.id, result: "ack" })
    }
    if (request.method === "ping") {
      return sendResponse(clientPubkey, { id: request.id, result: "pong" })
    }
    if (!isAuthenticated(clientPubkey)) {
      return sendResponse(clientPubkey, { id: request.id, error: "not connected" })
    }
    if (request.method === "get_public_key") {
      return sendResponse(
        clientPubkey,
        userPubkey === null ? { id: request.id, error: "not connected" } : { id: request.id, result: userPubkey },
      )
    }
    const cryptoMethod = signerCryptoMethodFor(request.method)
    if (cryptoMethod) {
      const [targetPubkey, payload] = request.params
      if (!targetPubkey || payload === undefined || !isValidPublicKey(targetPubkey)) {
        return sendResponse(clientPubkey, { id: request.id, error: "invalid params" })
      }
      const result = await signer[cryptoMethod](targetPubkey, payload)
      return sendResponse(
        clientPubkey,
        result.success ? { id: request.id, result: result.value } : { id: request.id, error: "encryption failed" },
      )
    }
    if (request.method === "sign_event") {
      return queueSignRequest(clientPubkey, request)
    }
    return sendResponse(clientPubkey, { id: request.id, error: `unsupported method: ${request.method}` })
  }

  const handleEvent = async (event: NostrEvent): Promise<void> => {
    if (!markSeen(event.id)) return
    const decoded = await decryptEnvelopeJson({
      signer,
      peerPubkey: event.pubkey,
      ciphertext: event.content,
      preferredCipher: clientEnvelopeCipher.get(event.pubkey) ?? "nip44",
    })
    if (!decoded) return
    clientEnvelopeCipher.set(event.pubkey, decoded.cipher)
    evictOldest(clientEnvelopeCipher, CLIENT_CIPHER_LIMIT)
    const request = parseRequest(decoded.value)
    if (!request) return
    await dispatch(event.pubkey, request)
  }

  const stop = (): void => {
    if (subscription) {
      subscription.abort()
      subscription = null
    }
    userPubkey = null
    secret = null
    relays = []
    pending.clear()
    seenEventIds.clear()
    authenticatedClients.clear()
    clientEnvelopeCipher.clear()
    notify()
  }

  const start = (pubkey: PublicKey, relayUrls: ReadonlyArray<RelayUrl>, bunkerSecret: string): void => {
    stop()
    if (relayUrls.length === 0 || bunkerSecret.length === 0) return
    userPubkey = pubkey
    relays = [...relayUrls]
    secret = bunkerSecret
    subscription = transport.subscribe({
      filter: { kinds: [KIND_NOSTR_CONNECT], "#p": [pubkey], since: now() - CLOCK_SKEW_TOLERANCE_SECONDS },
      relays,
      onEvent: (event) => {
        handleEvent(event).catch(reportUnhandledError)
      },
    })
  }

  const getBunkerUrl = (): string | null => {
    if (!userPubkey || relays.length === 0 || !secret) return null
    return formatBunkerUrl({ remoteSignerPubkey: userPubkey, relays, secret })
  }

  const getPending = (): ReadonlyArray<PendingSignRequest> =>
    [...pending.values()].sort((a, b) => b.receivedAt - a.receivedAt)

  const approve = async (id: string): Promise<void> => {
    const request = pending.get(id)
    if (!request) return
    pending.delete(id)
    notify()
    try {
      const unsigned: UnsignedEvent = {
        kind: request.eventToSign.kind,
        created_at: request.eventToSign.created_at ?? now(),
        tags: request.eventToSign.tags ?? [],
        content: request.eventToSign.content ?? "",
      }
      const signed = await signer.signEvent(unsigned)
      await sendResponse(request.clientPubkey, { id: request.id, result: JSON.stringify(signed) })
    } catch (err) {
      reportUnhandledError(err)
      await sendResponse(request.clientPubkey, { id: request.id, error: "signing failed" })
    }
  }

  const reject = async (id: string): Promise<void> => {
    const request = pending.get(id)
    if (!request) return
    pending.delete(id)
    notify()
    await sendResponse(request.clientPubkey, { id: request.id, error: "user rejected" })
  }

  const onUpdate = (listener: () => void): () => void => {
    listeners.add(listener)
    return (): void => {
      listeners.delete(listener)
    }
  }

  return Object.freeze({ start, stop, getBunkerUrl, getPending, approve, reject, onUpdate })
}
