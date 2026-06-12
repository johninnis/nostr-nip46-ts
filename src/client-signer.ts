import type {
  LocalSignerTools,
  NostrEvent,
  PublicKey,
  RelayUrl,
  Result,
  Signer,
  UnsignedEvent,
} from "@innis/nostr-core"
import {
  assertPubkeyMatches,
  createLocalSigner,
  failure,
  KIND_NOSTR_CONNECT,
  now as defaultNow,
  ok,
  parseNostrEvent,
  reportUnhandledError,
  SignerError,
  SigningError,
  tryParseJson,
  tryParsePublicKey,
  verifyEventSignature as defaultVerifyEventSignature,
} from "@innis/nostr-core"
import type { EnvelopeCipher } from "./protocol.ts"
import {
  CLOCK_SKEW_TOLERANCE_SECONDS,
  decryptEnvelopeJson,
  type Nip46CryptoMethod,
  type Nip46Request,
  parseResponse,
  sendEnvelope,
} from "./protocol.ts"
import type { Nip46Subscription, Nip46Transport } from "./transport.ts"

class Nip46RequestError extends SigningError {
  readonly transportFailure: boolean
  constructor(message: string, transportFailure: boolean) {
    super(message)
    this.transportFailure = transportFailure
  }
}

/** Dependencies for {@link createNip46ClientSigner}. */
export interface Nip46ClientSignerDeps {
  /** Pure-crypto primitives from `@innis/nostr-core` used to sign and encrypt request envelopes with the client key. */
  readonly tools: LocalSignerTools
  /** The Nostr-on-the-wire port the client publishes requests and subscribes for responses on. */
  readonly transport: Nip46Transport
  /** The per-session ephemeral secret key the client signs request envelopes with — never the user's key. */
  readonly clientSecretKey: Uint8Array
  /** The remote signer's public key, taken from the `bunker://` URL. */
  readonly remoteSignerPubkey: PublicKey
  /** Every relay the `bunker://` URL advertised; requests broadcast to all, responses awaited across all. */
  readonly relayUrls: ReadonlyArray<RelayUrl>
  /** The initial pairing secret from the `bunker://` URL, or `null` if none. */
  readonly secret: string | null
  /** A previously known user pubkey (e.g. a restored session); when set, {@link Nip46ClientSigner.connect} skips the handshake. */
  readonly initialUserPubkey?: PublicKey | null
  /** Per-request timeout in milliseconds. Defaults to 300000 (5 minutes). */
  readonly timeoutMs?: number
  /** Clock returning Unix seconds; injectable for tests. Defaults to the core `now`. */
  readonly now?: () => number
  /** Factory for unique request ids. Defaults to `crypto.randomUUID()`. */
  readonly generateRequestId?: () => string
  /** Verifier for the Schnorr signature of bunker-signed events. Defaults to the core `verifyEventSignature`. */
  readonly verifyEventSignature?: (event: NostrEvent) => Promise<boolean>
  /** Fired before {@link Nip46ClientSigner.signEvent} throws when a signed event's pubkey differs from the known user pubkey. */
  readonly onPubkeyMismatch?: (expected: PublicKey, actual: PublicKey) => void
  /** Fired when the bunker answers with an `auth_url` challenge so the host can open it; the request stays pending for the real reply. */
  readonly onAuthChallenge?: (url: string) => void
}

/** A NIP-46 client that implements the core `Signer` interface, so app code cannot tell a remote bunker from a local key. */
export interface Nip46ClientSigner extends Signer {
  /** Runs the `connect` handshake (unless `initialUserPubkey` was supplied) and resolves the user pubkey. Must succeed before any signing call. */
  readonly connect: () => Promise<void>
  /** Rejects all in-flight requests with a disconnected error and tears down the subscription. */
  readonly disconnect: () => void
  /** The ephemeral client public key derived from `clientSecretKey`. */
  readonly getClientPubkey: () => PublicKey
}

interface PendingRequest {
  readonly resolve: (result: string) => void
  readonly reject: (error: Error) => void
  readonly timer: ReturnType<typeof setTimeout>
}

/**
 * Construct a {@link Nip46ClientSigner}. Each `signEvent` / `nip04*` / `nip44*` call is JSON-encoded, NIP-44
 * encrypted to `remoteSignerPubkey`, signed with the ephemeral client key, and published as a kind 24133 event
 * to every relay; the matching response is awaited on one subscription spanning all relays. `signEvent`
 * additionally checks the returned pubkey against the user pubkey ({@link Nip46ClientSignerDeps.onPubkeyMismatch})
 * and verifies the event signature before resolving.
 */
export const createNip46ClientSigner = ({
  tools,
  transport,
  clientSecretKey,
  remoteSignerPubkey,
  relayUrls,
  secret,
  initialUserPubkey = null,
  timeoutMs = 300_000,
  now = defaultNow,
  generateRequestId = () => globalThis.crypto.randomUUID(),
  verifyEventSignature = defaultVerifyEventSignature,
  onPubkeyMismatch,
  onAuthChallenge,
}: Nip46ClientSignerDeps): Nip46ClientSigner => {
  const clientPubkey = tools.getPublicKey(clientSecretKey)
  const envelopeSigner = createLocalSigner(clientSecretKey, tools)
  const pending = new Map<string, PendingRequest>()
  let userPubkey: PublicKey | null = initialUserPubkey
  // Cipher the bunker last spoke; requests and first decrypt attempts follow it so a NIP-04 peer
  // does not cost a failed NIP-44 attempt on every envelope. Mirrors the bunker's per-client cache.
  let peerCipher: EnvelopeCipher = "nip44"
  let subscription: Nip46Subscription | null = null

  const handleResponse = async (event: NostrEvent): Promise<void> => {
    if (event.pubkey !== remoteSignerPubkey) return
    const decoded = await decryptEnvelopeJson({
      signer: envelopeSigner,
      peerPubkey: event.pubkey,
      ciphertext: event.content,
      preferredCipher: peerCipher,
    })
    if (!decoded) return
    peerCipher = decoded.cipher
    const response = parseResponse(decoded.value)
    if (!response) return
    const request = pending.get(response.id)
    if (!request) return
    if (response.result === "auth_url") {
      const url = response.error ?? ""
      if (onAuthChallenge) {
        onAuthChallenge(url)
        return
      }
      pending.delete(response.id)
      clearTimeout(request.timer)
      request.reject(new SigningError(`bunker requires authentication: ${url}`))
      return
    }
    pending.delete(response.id)
    clearTimeout(request.timer)
    if (response.error !== undefined) {
      request.reject(new Nip46RequestError(response.error, false))
      return
    }
    request.resolve(response.result ?? "")
  }

  const ensureSubscription = (): void => {
    if (subscription) return
    subscription = transport.subscribe({
      filter: {
        kinds: [KIND_NOSTR_CONNECT],
        authors: [remoteSignerPubkey],
        "#p": [clientPubkey],
        since: now() - CLOCK_SKEW_TOLERANCE_SECONDS,
      },
      relays: relayUrls,
      onEvent: (event) => {
        handleResponse(event).catch(reportUnhandledError)
      },
    })
  }

  const sendRequest = (method: string, params: ReadonlyArray<string>): Promise<string> => {
    ensureSubscription()
    return new Promise<string>((resolve, reject) => {
      const id = generateRequestId()
      const timer = setTimeout(() => {
        pending.delete(id)
        reject(new Nip46RequestError("bunker request timed out", true))
      }, timeoutMs)
      pending.set(id, { resolve, reject, timer })

      const failPending = (error: Error): void => {
        if (!pending.delete(id)) return
        clearTimeout(timer)
        reject(error)
      }
      ;(async () => {
        const payload: Nip46Request = { id, method, params }
        const sent = await sendEnvelope({
          signer: envelopeSigner,
          transport,
          relays: relayUrls,
          peerPubkey: remoteSignerPubkey,
          payload,
          cipher: peerCipher,
          now,
        })
        if (!sent.success) {
          failPending(new SigningError(`failed to encrypt NIP-46 request: ${sent.error.message}`, sent.error))
        }
      })().catch((err: unknown) => {
        failPending(err instanceof Error ? err : new SigningError(String(err)))
      })
    })
  }

  const toUserPubkey = (raw: string): PublicKey => {
    const parsed = tryParsePublicKey(raw)
    if (parsed === null) throw new SigningError("bunker returned invalid public key")
    return parsed
  }

  const connect = async (): Promise<void> => {
    if (userPubkey) {
      ensureSubscription()
      return
    }
    const params: ReadonlyArray<string> = secret === null ? [remoteSignerPubkey] : [remoteSignerPubkey, secret]
    await sendRequest("connect", params)
    await getPublicKey()
  }

  const disconnect = (): void => {
    if (subscription) {
      subscription.abort()
      subscription = null
    }
    for (const { reject, timer } of pending.values()) {
      clearTimeout(timer)
      reject(new Nip46RequestError("bunker disconnected", true))
    }
    pending.clear()
    userPubkey = null
  }

  const getPublicKey = async (): Promise<PublicKey> => {
    if (userPubkey) return userPubkey
    userPubkey = toUserPubkey(await sendRequest("get_public_key", []))
    return userPubkey
  }

  const signEvent = async (event: UnsignedEvent): Promise<NostrEvent> => {
    if (userPubkey === null) {
      throw new SigningError("bunker not connected — call connect() before signEvent")
    }
    const raw = await sendRequest("sign_event", [JSON.stringify(event)])
    const signed = parseNostrEvent(tryParseJson(raw))
    if (!signed) throw new SigningError("bunker returned invalid sign_event response")
    assertPubkeyMatches(userPubkey, signed.pubkey, onPubkeyMismatch)
    if (!(await verifyEventSignature(signed))) {
      throw new SigningError("bunker returned an event with an invalid signature")
    }
    return signed
  }

  const isEncrypt = (method: Nip46CryptoMethod): boolean => method.endsWith("_encrypt")

  const callRemote = async (
    method: Nip46CryptoMethod,
    peerPubkey: PublicKey,
    payload: string,
  ): Promise<Result<string, SignerError>> => {
    try {
      return ok(await sendRequest(method, [peerPubkey, payload]))
    } catch (err) {
      if (err instanceof Nip46RequestError && err.transportFailure) {
        return failure(new SignerError("disconnected", err.message, err))
      }
      const tag = isEncrypt(method) ? "encrypt-failed" : "decrypt-failed"
      return failure(new SignerError(tag, err instanceof Error ? err.message : String(err), err))
    }
  }

  const nip44Encrypt = (peerPubkey: PublicKey, plaintext: string): Promise<Result<string, SignerError>> =>
    callRemote("nip44_encrypt", peerPubkey, plaintext)

  const nip44Decrypt = (peerPubkey: PublicKey, ciphertext: string): Promise<Result<string, SignerError>> =>
    callRemote("nip44_decrypt", peerPubkey, ciphertext)

  const nip04Encrypt = (peerPubkey: PublicKey, plaintext: string): Promise<Result<string, SignerError>> =>
    callRemote("nip04_encrypt", peerPubkey, plaintext)

  const nip04Decrypt = (peerPubkey: PublicKey, ciphertext: string): Promise<Result<string, SignerError>> =>
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
    getClientPubkey: () => clientPubkey,
  })
}
