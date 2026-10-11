// Deliberate: judged on the string itself, never through a URL parser that would repair it, so it is handed over as received — see ADR-0009
const WEB_SCHEME_AND_HOST = /^https?:\/\/[^/?#@:]+(?::[0-9]+)?(?:[/?#]|$)/i
const WHITESPACE_CONTROL_OR_BACKSLASH = /[\p{White_Space}\p{Cc}\\]/u

export const isWebUrl = (raw: string): boolean =>
  WEB_SCHEME_AND_HOST.test(raw) && !WHITESPACE_CONTROL_OR_BACKSLASH.test(raw)
