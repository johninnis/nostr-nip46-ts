import type { PublicKey, RelayUrl } from "@innis/nostr-core"
import { parsePublicKey, parseRelayUrl } from "@innis/nostr-core"

export interface PairingUri {
  readonly pubkey: PublicKey
  readonly relays: ReadonlyArray<RelayUrl>
  readonly params: URLSearchParams
}

export const parsePairingUri = (raw: string, scheme: string): PairingUri | null => {
  const trimmed = raw.trim()
  if (!trimmed.startsWith(scheme)) return null

  const rest = trimmed.slice(scheme.length)
  const queryIndex = rest.indexOf("?")
  const origin = queryIndex >= 0 ? rest.slice(0, queryIndex) : rest
  const params = new URLSearchParams(queryIndex >= 0 ? rest.slice(queryIndex + 1) : "")

  const pubkey = parsePublicKey(origin)
  const relays = params.getAll("relay").map(parseRelayUrl).filter((relay) => relay !== null)
  return pubkey === null || relays.length === 0 ? null : { pubkey, relays, params }
}

// Deliberate: pairing URIs are written percent-encoded (RFC 3986), never form-encoded — a strict parser decodes %20 but reads + as a literal plus — see ADR-0019
const encodeQueryComponent = (value: string): string =>
  encodeURIComponent(value).replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`)

export const formatPairingUri = (scheme: string, pubkey: PublicKey, params: URLSearchParams): string => {
  const query = [...params].map(([key, value]) => `${encodeQueryComponent(key)}=${encodeQueryComponent(value)}`).join(
    "&",
  )
  return query.length > 0 ? `${scheme}${pubkey}?${query}` : `${scheme}${pubkey}`
}

export const relayParams = (relays: ReadonlyArray<RelayUrl>): URLSearchParams =>
  new URLSearchParams(relays.map((relay) => ["relay", relay]))
