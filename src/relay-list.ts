import type { RelayUrl } from "@innis/nostr-core"
import { isOk, parseJson, parseRelayUrl } from "@innis/nostr-core"

export const parseRelayList = (raw: string): ReadonlyArray<RelayUrl> | null => {
  const json = parseJson(raw)
  if (!isOk(json) || !Array.isArray(json.value)) return null
  const relays = json.value.map((entry: unknown) => typeof entry === "string" ? parseRelayUrl(entry) : null)
    .filter((relay) => relay !== null)
  return relays.length > 0 ? [...new Set(relays)] : null
}

export const sameRelays = (a: ReadonlyArray<RelayUrl>, b: ReadonlyArray<RelayUrl>): boolean =>
  a.length === b.length && a.every((relay) => b.includes(relay))
