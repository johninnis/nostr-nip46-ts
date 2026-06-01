import type { PublicKey, RelayUrl } from "@innis/nostr-core"
import { normaliseRelayUrl, tryParsePublicKey } from "@innis/nostr-core"

/** The parsed contents of a `bunker://` URL — the connection coordinates a client needs to reach a remote signer. */
export interface BunkerUrl {
  /** The remote signer's public key (the identity the bunker signs as). */
  readonly remoteSignerPubkey: PublicKey
  /** The relays the client should publish requests to and subscribe for responses on. */
  readonly relays: ReadonlyArray<RelayUrl>
  /** The one-shot pairing secret, or `null` when the URL carries none. */
  readonly secret: string | null
}

const PREFIX = "bunker://"

/**
 * Parse `bunker://<remoteSignerPubkey>?relay=wss://...&relay=wss://...&secret=...` into a {@link BunkerUrl}.
 * Returns `null` for any malformed input: wrong scheme, invalid pubkey, or no valid relay. Relay URLs are
 * normalised via `@innis/nostr-core`'s `normaliseRelayUrl`; individually invalid relays are dropped, but a
 * URL with zero surviving relays is rejected. Inverse of {@link formatBunkerUrl}.
 */
export const parseBunkerUrl = (raw: string): BunkerUrl | null => {
  const trimmed = raw.trim()
  if (!trimmed.startsWith(PREFIX)) return null

  const rest = trimmed.slice(PREFIX.length)
  const queryIndex = rest.indexOf("?")
  const pubkeyPart = queryIndex >= 0 ? rest.slice(0, queryIndex) : rest
  const queryPart = queryIndex >= 0 ? rest.slice(queryIndex + 1) : ""

  const remoteSignerPubkey = tryParsePublicKey(pubkeyPart)
  if (remoteSignerPubkey === null) return null

  const params = new URLSearchParams(queryPart)
  const validRelays: Array<RelayUrl> = []
  for (const candidate of params.getAll("relay")) {
    const normalised = normaliseRelayUrl(candidate)
    if (normalised !== null) validRelays.push(normalised)
  }
  if (validRelays.length === 0) return null

  const secretRaw = params.get("secret")
  const secret = secretRaw !== null && secretRaw.length > 0 ? secretRaw : null

  return {
    remoteSignerPubkey,
    relays: validRelays,
    secret,
  }
}

/**
 * Render a {@link BunkerUrl} back into its `bunker://` string form, one `relay=` parameter per relay and the
 * `secret` parameter omitted when `secret` is `null`. The single owner of the on-wire URL format, so parse and
 * format can never drift. Inverse of {@link parseBunkerUrl}.
 */
export const formatBunkerUrl = ({ remoteSignerPubkey, relays, secret }: BunkerUrl): string => {
  const params = new URLSearchParams()
  for (const relay of relays) params.append("relay", relay)
  if (secret !== null) params.append("secret", secret)
  const query = params.toString()
  return query.length > 0 ? `${PREFIX}${remoteSignerPubkey}?${query}` : `${PREFIX}${remoteSignerPubkey}`
}
