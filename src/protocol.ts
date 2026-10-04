import type { CipherScheme, PublicKey, RelayUrl, Result, Signer, SignerFailure, UnsignedEvent } from "@innis/nostr-core"
import { cipherSchemeOf, createJsonCipher, failure, isRecord, KIND_NOSTR_CONNECT, ok } from "@innis/nostr-core"
import type { Nip46Transport } from "./transport.ts"

/**
 * Returned by `sendEnvelope` when a NIP-46 envelope never reached the peer: `encrypt-failed` when it could not be
 * encrypted, `sign-failed` when the signer did not sign it, `delivery-failed` when every targeted relay refused the
 * publish or there were no relays to try. A transport whose `publish` rejects is broken rather than refused, and that
 * rejection propagates instead. `message` describes it; the client signer passes it on as the failed request's reason.
 */
export interface Nip46SendFailure {
  readonly type: "encrypt-failed" | "sign-failed" | "delivery-failed"
  readonly message: string
}

/** Every method NIP-46 defines, as written on the wire. */
export type Nip46Method =
  | "connect"
  | "ping"
  | "get_public_key"
  | "switch_relays"
  | "logout"
  | "sign_event"
  | Nip46CryptoMethod

export interface Nip46Request {
  readonly id: string
  readonly method: string
  readonly params: ReadonlyArray<string>
}

export interface Nip46Response {
  readonly id: string
  readonly result?: string | undefined
  readonly error?: string | undefined
}

const isNonEmptyString = (value: unknown): value is string => typeof value === "string" && value.length > 0

const isOptionalString = (value: unknown): value is string | null | undefined =>
  value === undefined || value === null || typeof value === "string"

export const parseRequest = (value: Readonly<Record<string, unknown>>): Nip46Request | null => {
  if (!isNonEmptyString(value.id) || !isNonEmptyString(value.method)) return null
  // Deliberate: an absent params member reads as an empty list, an explicit null is refused — see ADR-0016
  const rawParams = value.params === undefined ? [] : value.params
  if (!Array.isArray(rawParams)) return null
  // Deliberate: a non-string param is normalised to its JSON form, for clients that send sign_event's event as an object — see ADR-0016
  const params = rawParams.map((param): string => typeof param === "string" ? param : JSON.stringify(param))
  return { id: value.id, method: value.method, params }
}

export const parseResponse = (value: Readonly<Record<string, unknown>>): Nip46Response | null => {
  if (!isNonEmptyString(value.id)) return null
  const { result, error } = value
  if (!isOptionalString(result) || !isOptionalString(error)) return null
  return { id: value.id, result: result ?? undefined, error: error ?? undefined }
}

export const CLOCK_SKEW_TOLERANCE_SECONDS = 60

/** The four NIP-46 methods that encrypt or decrypt a payload for a third party as the user. */
export type Nip46CryptoMethod = "nip04_encrypt" | "nip04_decrypt" | "nip44_encrypt" | "nip44_decrypt"

type SignerCryptoMethod = "nip04Encrypt" | "nip04Decrypt" | "nip44Encrypt" | "nip44Decrypt"

const SIGNER_CRYPTO_METHOD: Readonly<Record<Nip46CryptoMethod, SignerCryptoMethod>> = {
  nip04_encrypt: "nip04Encrypt",
  nip04_decrypt: "nip04Decrypt",
  nip44_encrypt: "nip44Encrypt",
  nip44_decrypt: "nip44Decrypt",
}

export const isNip46CryptoMethod = (method: string): method is Nip46CryptoMethod =>
  Object.hasOwn(SIGNER_CRYPTO_METHOD, method)

const NIP46_METHODS: Readonly<Record<Nip46Method, true>> = {
  connect: true,
  ping: true,
  get_public_key: true,
  switch_relays: true,
  logout: true,
  sign_event: true,
  nip04_encrypt: true,
  nip04_decrypt: true,
  nip44_encrypt: true,
  nip44_decrypt: true,
}

export const isNip46Method = (method: string): method is Nip46Method => Object.hasOwn(NIP46_METHODS, method)

export const signerCryptoMethodOf = (method: Nip46CryptoMethod): SignerCryptoMethod => SIGNER_CRYPTO_METHOD[method]

export const isEncryptMethod = (method: Nip46CryptoMethod): boolean => method.endsWith("_encrypt")

interface EncryptEnvelopeParams {
  readonly signer: Signer
  readonly peerPubkey: PublicKey
  readonly payload: Nip46Request | Nip46Response
  readonly cipher?: CipherScheme | undefined
}

interface DecryptEnvelopeParams {
  readonly signer: Signer
  readonly peerPubkey: PublicKey
  readonly ciphertext: string
}

const encryptEnvelopeJson = (
  { signer, peerPubkey, payload, cipher = "nip44" }: EncryptEnvelopeParams,
): Promise<Result<string, SignerFailure>> => createJsonCipher(signer, cipher).encrypt(peerPubkey, payload)

const encryptFailureMessage = (signerFailure: SignerFailure): string =>
  `failed to encrypt NIP-46 envelope (${signerFailure.type}): ${signerFailure.message}`

/**
 * Decrypt a NIP-46 envelope with the cipher its payload is written in — NIP-04 carries an `?iv=` suffix, NIP-44 does
 * not — and keep it only when it holds a JSON object, the one shape a request or a response can take.
 */
export const decryptEnvelopeJson = async (
  { signer, peerPubkey, ciphertext }: DecryptEnvelopeParams,
): Promise<{ value: Record<string, unknown>; cipher: CipherScheme } | null> => {
  const cipher = cipherSchemeOf(ciphertext)
  const decrypted = await createJsonCipher(signer, cipher).decrypt(peerPubkey, ciphertext)
  return decrypted.success && isRecord(decrypted.value) ? { value: decrypted.value, cipher } : null
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
  readonly payload: Nip46Request | Nip46Response
  readonly cipher?: CipherScheme | undefined
  readonly now: () => number
}

export const sendEnvelope = async (
  { signer, transport, relays, peerPubkey, payload, cipher, now }: SendEnvelopeParams,
): Promise<Result<void, Nip46SendFailure>> => {
  const ciphertext = await encryptEnvelopeJson({ signer, peerPubkey, payload, cipher })
  if (!ciphertext.success) {
    return failure({ type: "encrypt-failed", message: encryptFailureMessage(ciphertext.error) })
  }
  if (relays.length === 0) {
    return failure({ type: "delivery-failed", message: "no relay to publish the NIP-46 envelope to" })
  }
  const signed = await signer.signEvent(buildEnvelopeEvent(peerPubkey, ciphertext.value, now()))
  if (!signed.success) {
    return failure({
      type: "sign-failed",
      message: `failed to sign NIP-46 envelope (${signed.error.type}): ${signed.error.message}`,
    })
  }
  // Deliberate: a relay's refusal is a result, but a publish that rejects is a transport fault and propagates — see ADR-0005
  const outcomes = await Promise.all(relays.map((relay) => transport.publish(relay, signed.value)))
  if (outcomes.some((outcome) => outcome.ok)) return ok(undefined)
  return failure({
    type: "delivery-failed",
    message: `no relay accepted the NIP-46 envelope (tried ${relays.length})`,
  })
}
