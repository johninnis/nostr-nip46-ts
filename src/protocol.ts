import type { JsonCryptoError, PublicKey, RelayUrl, Result, Signer, UnsignedEvent } from "@innis/nostr-core"
import {
  decryptJson,
  encryptJson,
  isRecord,
  KIND_NOSTR_CONNECT,
  nip04DecryptJson,
  nip04EncryptJson,
  ok,
  reportUnhandledError,
} from "@innis/nostr-core"
import type { Nip46Transport } from "./transport.ts"

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
  if (!Array.isArray(rawParams) || !rawParams.every((p): p is string => typeof p === "string")) return null
  return { id: value.id, method: value.method, params: rawParams }
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
}

const encryptEnvelopeJson = (
  { signer, peerPubkey, payload, cipher = "nip44" }: EncryptEnvelopeParams,
): Promise<Result<string, JsonCryptoError>> =>
  cipher === "nip04" ? nip04EncryptJson(signer, peerPubkey, payload) : encryptJson(signer, peerPubkey, payload)

export const decryptEnvelopeJson = async (
  { signer, peerPubkey, ciphertext }: DecryptEnvelopeParams,
): Promise<{ value: unknown; cipher: EnvelopeCipher } | null> => {
  const nip44 = await decryptJson(signer, peerPubkey, ciphertext)
  if (nip44.success) return { value: nip44.value, cipher: "nip44" }
  const nip04 = await nip04DecryptJson(signer, peerPubkey, ciphertext)
  if (nip04.success) return { value: nip04.value, cipher: "nip04" }
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
): Promise<Result<void, JsonCryptoError>> => {
  const ciphertext = await encryptEnvelopeJson({ signer, peerPubkey, payload, cipher })
  if (!ciphertext.success) return ciphertext
  const signed = await signer.signEvent(buildEnvelopeEvent(peerPubkey, ciphertext.value, now()))
  for (const relay of relays) transport.publish(relay, signed).catch(reportUnhandledError)
  return ok(undefined)
}
