import type { JsonCryptoError, PublicKey, RelayUrl, Result, Signer, UnsignedEvent } from "@innis/nostr-core"
import {
  decryptJson,
  encryptJson,
  failure,
  isRecord,
  KIND_NOSTR_CONNECT,
  nip04DecryptJson,
  nip04EncryptJson,
  ok,
  TaggedError,
} from "@innis/nostr-core"
import type { Nip46Transport } from "./transport.ts"

/** Discriminator for `Nip46SendError.tag` — the envelope could not be encrypted, or no relay accepted it. */
export type Nip46SendErrorTag = "encrypt-failed" | "delivery-failed"

/**
 * Returned by `sendEnvelope` when a NIP-46 envelope never reached the peer. `cause` carries the
 * underlying `JsonCryptoError` for `encrypt-failed`; `delivery-failed` has no upstream error —
 * it means every targeted relay rejected the publish, or there were no relays to try.
 */
export class Nip46SendError extends TaggedError<Nip46SendErrorTag, JsonCryptoError> {
  constructor(tag: Nip46SendErrorTag, message: string, cause?: JsonCryptoError) {
    super(tag, message, cause)
  }
}

export interface Nip46Request {
  readonly id: string
  readonly method: string
  readonly params: ReadonlyArray<string>
}

export interface Nip46Response {
  readonly id: string
  readonly result?: string
  readonly error?: string
}

export const parseRequest = (value: unknown): Nip46Request | null => {
  if (!isRecord(value) || typeof value.id !== "string" || typeof value.method !== "string") return null
  const rawParams = value.params
  if (rawParams === undefined) return { id: value.id, method: value.method, params: [] }
  if (!Array.isArray(rawParams)) return null
  // Some clients send `sign_event`'s event as a raw object rather than the spec's JSON string;
  // normalise any non-string param back to its JSON form so the one downstream path handles both.
  const params = rawParams.map((param): string => typeof param === "string" ? param : JSON.stringify(param))
  return { id: value.id, method: value.method, params }
}

export const parseResponse = (value: unknown): Nip46Response | null => {
  if (!isRecord(value)) return null
  if (typeof value.id !== "string") return null
  if (value.result !== undefined && typeof value.result !== "string") return null
  if (value.error !== undefined && typeof value.error !== "string") return null
  return { id: value.id, result: value.result, error: value.error }
}

export type EnvelopeCipher = "nip04" | "nip44"

export const CLOCK_SKEW_TOLERANCE_SECONDS = 60

export type Nip46CryptoMethod = "nip04_encrypt" | "nip04_decrypt" | "nip44_encrypt" | "nip44_decrypt"

type SignerCryptoMethod = "nip04Encrypt" | "nip04Decrypt" | "nip44Encrypt" | "nip44Decrypt"

const SIGNER_CRYPTO_METHOD: Readonly<Record<Nip46CryptoMethod, SignerCryptoMethod>> = {
  nip04_encrypt: "nip04Encrypt",
  nip04_decrypt: "nip04Decrypt",
  nip44_encrypt: "nip44Encrypt",
  nip44_decrypt: "nip44Decrypt",
}

const isNip46CryptoMethod = (method: string): method is Nip46CryptoMethod => Object.hasOwn(SIGNER_CRYPTO_METHOD, method)

export const signerCryptoMethodFor = (method: string): SignerCryptoMethod | undefined =>
  isNip46CryptoMethod(method) ? SIGNER_CRYPTO_METHOD[method] : undefined

interface EncryptEnvelopeParams {
  readonly signer: Signer
  readonly peerPubkey: PublicKey
  readonly payload: unknown
  readonly cipher?: EnvelopeCipher
}

interface DecryptEnvelopeParams {
  readonly signer: Signer
  readonly peerPubkey: PublicKey
  readonly ciphertext: string
  /** Cipher to try first (default `"nip44"`); the other is attempted as a fallback. */
  readonly preferredCipher?: EnvelopeCipher
}

const encryptEnvelopeJson = (
  { signer, peerPubkey, payload, cipher = "nip44" }: EncryptEnvelopeParams,
): Promise<Result<string, JsonCryptoError>> =>
  cipher === "nip04" ? nip04EncryptJson(signer, peerPubkey, payload) : encryptJson(signer, peerPubkey, payload)

export const decryptEnvelopeJson = async (
  { signer, peerPubkey, ciphertext, preferredCipher = "nip44" }: DecryptEnvelopeParams,
): Promise<{ value: unknown; cipher: EnvelopeCipher } | null> => {
  const attempt = (cipher: EnvelopeCipher): Promise<Result<unknown, JsonCryptoError>> =>
    cipher === "nip04" ? nip04DecryptJson(signer, peerPubkey, ciphertext) : decryptJson(signer, peerPubkey, ciphertext)
  const fallbackCipher: EnvelopeCipher = preferredCipher === "nip44" ? "nip04" : "nip44"
  const first = await attempt(preferredCipher)
  if (first.success) return { value: first.value, cipher: preferredCipher }
  const second = await attempt(fallbackCipher)
  if (second.success) return { value: second.value, cipher: fallbackCipher }
  return null
}

const buildEnvelopeEvent = (peerPubkey: PublicKey, content: string, createdAt: number): UnsignedEvent => ({
  kind: KIND_NOSTR_CONNECT,
  created_at: createdAt,
  tags: [["p", peerPubkey]],
  content,
})

interface SendEnvelopeParams {
  readonly signer: Signer
  readonly transport: Nip46Transport
  readonly relays: ReadonlyArray<RelayUrl>
  readonly peerPubkey: PublicKey
  readonly payload: unknown
  readonly cipher?: EnvelopeCipher
  readonly now: () => number
}

export const sendEnvelope = async (
  { signer, transport, relays, peerPubkey, payload, cipher, now }: SendEnvelopeParams,
): Promise<Result<void, Nip46SendError>> => {
  const ciphertext = await encryptEnvelopeJson({ signer, peerPubkey, payload, cipher })
  if (!ciphertext.success) {
    return failure(
      new Nip46SendError(
        "encrypt-failed",
        `failed to encrypt NIP-46 envelope (${ciphertext.error.tag}): ${ciphertext.error.message}`,
        ciphertext.error,
      ),
    )
  }
  if (relays.length === 0) {
    return failure(new Nip46SendError("delivery-failed", "no relay to publish the NIP-46 envelope to"))
  }
  const signed = await signer.signEvent(buildEnvelopeEvent(peerPubkey, ciphertext.value, now()))
  const outcomes = await Promise.allSettled(relays.map((relay) => transport.publish(relay, signed)))
  if (outcomes.some((outcome) => outcome.status === "fulfilled" && outcome.value.ok)) return ok(undefined)
  return failure(
    new Nip46SendError("delivery-failed", `no relay accepted the NIP-46 envelope (tried ${relays.length})`),
  )
}
