import type { EventId, PublicKey, Signer, Tag } from "@innis/nostr-core"
import {
  isOk,
  isRecord,
  isValidKind,
  isValidTagsArray,
  parseJson,
  parsePublicKey,
  serialiseEvent,
} from "@innis/nostr-core"
import type { Nip46Permission } from "./permission.ts"
import { isEncryptMethod, type Nip46CryptoMethod, type Nip46Response, signerCryptoMethodOf } from "./protocol.ts"

export type { Nip46Permission } from "./permission.ts"

/** A `sign_event` request body as received from a client — the fields the bunker will sign, with optional parts defaulted at approval time. */
export interface UnsignedEventInput {
  /** The event kind the client wants signed. */
  readonly kind: number
  /** The event timestamp; defaults to the approval-time clock when omitted. */
  readonly created_at?: number | undefined
  /** The event tags; defaults to an empty list when omitted. */
  readonly tags?: ReadonlyArray<Tag> | undefined
  /** The event content; defaults to an empty string when omitted. */
  readonly content?: string | undefined
}

/** A `get_public_key` request: the client asks which user the bunker signs as. */
export interface GetPublicKeyDetail {
  /** The NIP-46 method. */
  readonly method: "get_public_key"
}

/** A `sign_event` request: the client asks for this event to be signed as the user. */
export interface SignEventDetail {
  /** The NIP-46 method. */
  readonly method: "sign_event"
  /** The event the client is asking to have signed. */
  readonly eventToSign: UnsignedEventInput
}

/** A `nip04_*` / `nip44_*` request: the client asks for a payload to be encrypted to, or decrypted from, a third party. */
export interface CipherDetail {
  /** The NIP-46 method. */
  readonly method: Nip46CryptoMethod
  /** The third party the payload is encrypted to or was encrypted by. */
  readonly counterparty: PublicKey
  /** The plaintext to encrypt or the ciphertext to decrypt. */
  readonly payload: string
}

/** What a queued request asks the bunker to do, discriminated by its NIP-46 `method`. */
export type PendingRequestDetail = GetPublicKeyDetail | SignEventDetail | CipherDetail

/** A request the host's authoriser did not grant, queued for the host to approve or reject. */
export interface PendingRequest {
  /** The id of the kind 24133 event that carried the request: unique across every client, and what `approve` and `reject` take. */
  readonly id: EventId
  /** The NIP-46 request id the client chose, echoed in the response so the client can correlate it. */
  readonly requestId: string
  /** The public key of the client that sent the request. */
  readonly clientPubkey: PublicKey
  /** When the request was received, from the injected clock — used to order the queue newest-first. */
  readonly receivedAt: number
  /** What the request asks for. */
  readonly detail: PendingRequestDetail
}

export const USER_REJECTED = "user rejected"

export const permissionFor = (detail: PendingRequestDetail): Nip46Permission =>
  detail.method === "sign_event" ? `sign_event:${detail.eventToSign.kind}` : detail.method

const isTimestamp = (value: unknown): value is number => Number.isSafeInteger(value) && Number(value) >= 0

const parseUnsignedEventInput = (value: unknown): UnsignedEventInput | null => {
  if (!isRecord(value) || !isValidKind(value.kind)) return null
  const { created_at, tags, content } = value
  if (created_at !== undefined && !isTimestamp(created_at)) return null
  if (tags !== undefined && !isValidTagsArray(tags)) return null
  if (content !== undefined && typeof content !== "string") return null
  return { kind: value.kind, created_at, tags, content }
}

export const parseSignEventDetail = (rawEvent: string | undefined): SignEventDetail | null => {
  const json = parseJson(rawEvent ?? "")
  const eventToSign = isOk(json) ? parseUnsignedEventInput(json.value) : null
  return eventToSign === null ? null : { method: "sign_event", eventToSign }
}

export const parseCipherDetail = (
  method: Nip46CryptoMethod,
  params: ReadonlyArray<string>,
): CipherDetail | null => {
  const [rawCounterparty = "", payload] = params
  const counterparty = parsePublicKey(rawCounterparty)
  return counterparty === null || payload === undefined ? null : { method, counterparty, payload }
}

export interface AnswerContext {
  readonly signer: Signer
  readonly userPubkey: PublicKey
  readonly now: () => number
}

const answerSignEvent = async (
  { eventToSign }: SignEventDetail,
  id: string,
  { signer, now }: AnswerContext,
): Promise<Nip46Response> => {
  const signed = await signer.signEvent({
    kind: eventToSign.kind,
    created_at: eventToSign.created_at ?? now(),
    tags: eventToSign.tags ?? [],
    content: eventToSign.content ?? "",
  })
  if (signed.success) return { id, result: serialiseEvent(signed.value) }
  return { id, error: signed.error.type === "rejected" ? USER_REJECTED : "signing failed" }
}

const answerCipher = async (
  { method, counterparty, payload }: CipherDetail,
  id: string,
  { signer }: AnswerContext,
): Promise<Nip46Response> => {
  const answered = await signer[signerCryptoMethodOf(method)](counterparty, payload)
  if (answered.success) return { id, result: answered.value }
  if (answered.error.type === "rejected") return { id, error: USER_REJECTED }
  return { id, error: isEncryptMethod(method) ? "encryption failed" : "decryption failed" }
}

export const answerDetail = (
  detail: PendingRequestDetail,
  id: string,
  context: AnswerContext,
): Promise<Nip46Response> => {
  switch (detail.method) {
    case "get_public_key":
      return Promise.resolve({ id, result: context.userPubkey })
    case "sign_event":
      return answerSignEvent(detail, id, context)
    default:
      return answerCipher(detail, id, context)
  }
}
