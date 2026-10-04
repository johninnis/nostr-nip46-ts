import type { PublicKey, RelayUrl } from "@innis/nostr-core"
import { formatPairingUri, parsePairingUri, relayParams } from "./pairing-uri.ts"

/** The parsed contents of a `bunker://` URL — the connection coordinates a client needs to reach a remote signer. */
export interface BunkerUrl {
  /** The remote signer's public key (the identity the bunker signs as). */
  readonly remoteSignerPubkey: PublicKey
  /** The relays the client should publish requests to and subscribe for responses on. */
  readonly relays: ReadonlyArray<RelayUrl>
  /** The one-shot pairing secret, or `null` when the URL carries none. */
  readonly secret: string | null
}

const SCHEME = "bunker://"

/**
 * Parse `bunker://<remoteSignerPubkey>?relay=wss://...&relay=wss://...&secret=...` into a {@link BunkerUrl}.
 * The pubkey must be NIP-01 lowercase hex and the secret is kept exactly. Returns `null` for any malformed input: wrong
 * scheme, invalid pubkey, or no valid relay. Relay URLs are canonicalised via `@innis/nostr-core`'s `parseRelayUrl`; individually invalid relays are dropped, but a
 * URL with zero surviving relays is rejected. Inverse of {@link formatBunkerUrl}.
 */
export const parseBunkerUrl = (raw: string): BunkerUrl | null => {
  const uri = parsePairingUri(raw, SCHEME)
  if (uri === null) return null
  const secret = uri.params.get("secret")
  return {
    remoteSignerPubkey: uri.pubkey,
    relays: uri.relays,
    secret: secret !== null && secret.length > 0 ? secret : null,
  }
}

/**
 * Render a {@link BunkerUrl} back into its `bunker://` string form, one `relay=` parameter per relay and the
 * `secret` parameter omitted when `secret` is `null`. The single owner of the on-wire URL format, so parse and
 * format can never drift. Inverse of {@link parseBunkerUrl}.
 */
export const formatBunkerUrl = ({ remoteSignerPubkey, relays, secret }: BunkerUrl): string => {
  const params = relayParams(relays)
  if (secret !== null) params.append("secret", secret)
  return formatPairingUri(SCHEME, remoteSignerPubkey, params)
}
