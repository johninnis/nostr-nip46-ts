import type { PublicKey, RelayUrl } from "@innis/nostr-core"
import { type Nip46Permission, parsePermissionList } from "./permission.ts"
import { formatPairingUri, parsePairingUri, relayParams } from "./pairing-uri.ts"

/**
 * A client application's description of itself — NIP-46's client metadata, carried in a `nostrconnect://` URL or as
 * the `optional_client_metadata` of a `connect` request. It is unauthenticated: a remote signer shows it and never
 * authorises anything by it.
 */
export interface Nip46ClientMetadata {
  /** The client application's name, or `null`. */
  readonly name: string | null
  /** The client application's canonical URL, or `null`. */
  readonly url: string | null
  /** A small image representing the client application, or `null`. */
  readonly image: string | null
}

/**
 * The parsed contents of a `nostrconnect://` URL — the token a client mints for a client-initiated pairing. The
 * `perms`, `name`, `url` and `image` fields are the client's own, unauthenticated description of itself: a bunker
 * shows them to its user and never treats them as a grant.
 */
export interface NostrConnectUrl extends Nip46ClientMetadata {
  /** The client's public key, the URL's origin; the bunker answers it here. */
  readonly clientPubkey: PublicKey
  /** The relays the client listens on for the remote signer's responses. */
  readonly relays: ReadonlyArray<RelayUrl>
  /** The secret the remote signer returns as the `result` of its `connect` response, proving the pairing to the client. */
  readonly secret: string
  /** The permissions the client asks for; unrecognised entries are dropped when parsing. */
  readonly perms: ReadonlyArray<Nip46Permission>
}

const SCHEME = "nostrconnect://"

export const clientMetadataEntries = (metadata: Nip46ClientMetadata): ReadonlyArray<[string, string]> =>
  (["name", "url", "image"] as const).flatMap((key) => {
    const value = metadata[key]
    return value === null ? [] : [[key, value]]
  })

const nonEmpty = (value: string | null): string | null => {
  const trimmed = value?.trim() ?? ""
  return trimmed.length > 0 ? trimmed : null
}

/**
 * Parse `nostrconnect://<client-pubkey>?relay=...&secret=...&perms=...&name=...&url=...&image=...` into a
 * {@link NostrConnectUrl}. Returns `null` for any malformed input: wrong scheme, invalid pubkey, no valid relay, or
 * no secret — NIP-46 requires both a relay and a secret. Relay URLs are canonicalised and invalid ones dropped, as in
 * `parseBunkerUrl`. Inverse of {@link formatNostrConnectUrl}.
 */
export const parseNostrConnectUrl = (raw: string): NostrConnectUrl | null => {
  const uri = parsePairingUri(raw, SCHEME)
  const secret = uri?.params.get("secret") ?? ""
  if (uri === null || secret.length === 0) return null
  return {
    clientPubkey: uri.pubkey,
    relays: uri.relays,
    secret,
    perms: parsePermissionList(uri.params.get("perms") ?? ""),
    name: nonEmpty(uri.params.get("name")),
    url: nonEmpty(uri.params.get("url")),
    image: nonEmpty(uri.params.get("image")),
  }
}

/**
 * Render a {@link NostrConnectUrl} as the `nostrconnect://` string a client shows its user to paste into a remote
 * signer: one `relay=` per relay, the secret, `perms` comma-separated when any are asked for, and each piece of
 * metadata that is present. Inverse of {@link parseNostrConnectUrl}.
 */
export const formatNostrConnectUrl = (url: NostrConnectUrl): string => {
  const params = relayParams(url.relays)
  params.append("secret", url.secret)
  if (url.perms.length > 0) params.append("perms", url.perms.join(","))
  for (const [key, value] of clientMetadataEntries(url)) params.append(key, value)
  return formatPairingUri(SCHEME, url.clientPubkey, params)
}
