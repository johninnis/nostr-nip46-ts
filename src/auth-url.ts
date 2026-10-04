// Deliberate: http(s) with a host only, stricter than the NIP's bare "URL" — the host opens it — see ADR-0009
const WEB_PROTOCOLS: ReadonlySet<string> = new Set(["http:", "https:"])

export const parseAuthUrl = (raw: string): string | null => {
  if (!URL.canParse(raw)) return null
  const url = new URL(raw)
  return WEB_PROTOCOLS.has(url.protocol) && url.hostname.length > 0 ? url.href : null
}
