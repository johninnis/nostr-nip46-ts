# 0009. An `auth_url` challenge is surfaced only as a web URL

## Status

Accepted

## Context

A bunker that needs the user to authorise out of band answers with `result: "auth_url"` and a URL in `error`, and the client is expected to "display (in a popup or new tab) the URL". The specification calls it only a URL. It is counterparty-supplied input: a malicious or compromised bunker can send `javascript:`, `data:` or `file:` URLs, and a host that opens what it is handed runs them in the user's browser. Leaving the check to each host is how one of them forgets it, invisibly until it is exploited.

URL parsers disagree on the edges. The WHATWG parser repairs what it is given: `https:example.com` and `https:\\evil.com` parse as `https` URLs with a host, and its `href` is not the string the bunker sent. Parsers on other platforms accept or refuse different strings, and some platforms have none, so "a URL the parser accepts" names a different set of strings in each NIP-46 port. A rule stated on the string itself can be applied identically everywhere, and a string that passes it needs no rewriting.

A challenge that fails the check could be dropped like a malformed response, but it is not one: a response that cannot be decrypted names no request, while a challenge carries the id of the request it answers. Dropping it leaves that request waiting for a reply that comes only after an authentication nobody was shown, so it times out and hides the reason.

## Decision

- The client takes an `auth_url` challenge's URL to be a web URL only when the string itself passes this check: it starts with `http://` or `https://`, the scheme compared without regard to case; the host that follows, up to the first `/`, `?`, `#` or the end, is non-empty, contains no `@`, and contains no `:` except one introducing a port of one or more ASCII digits at its end; and the whole string contains no whitespace or control character (the Unicode `White_Space` property and category `Cc`) and no `\`.
- A web URL is handed over exactly as received, to `onAuthChallenge` or in the failure ADR-0010 writes when there is none.
- A challenge whose URL fails the check, or carries none, fails the request it answers at once, in the method's own failure mode, with the message `bunker sent an authentication URL that is not a web URL`, which does not carry the URL. `onAuthChallenge` is not called, whether or not it is supplied. The failure is the client's own and is never read as a decline.

## Consequences

- A host can never receive a non-web URL through a challenge, in `onAuthChallenge` or in a failure message, and what it opens is byte for byte what the bunker sent.
- A request answered by an unusable challenge fails when the challenge arrives, not at its timeout.
- `https:example.com`, `https:\\evil.com`, `https://user@host/`, a host containing a space, a `:` with no port and a bracketed IPv6 host are refused, not repaired. A host that is not ASCII, such as an internationalised domain name, passes unchanged: the check does not judge what a host name may spell.
- The check names whitespace, control characters and a decimal port, and nothing more: a format character such as U+202E or U+FEFF passes, and so does a port of any length or with leading zeros. Refusing them would be a change to this record, made in every port together.
- No URL parser is involved, so the check is the same wherever it runs.
- Custom-scheme deep links are unsupported on purpose; allowing one needs a superseding record.
- A reader may see the allowlist as needless strictness over the specification's bare "URL", or reach for a URL parser to "simplify" it. The check carries a fence pointing here. Both ports drive their tests from one vector file, `tests/auth-url-vectors.json` — each challenge's `error`, or none, with the URL handed to the host or none — asserting through the client, with a listener and without, that each accepted URL reaches the host unchanged and each refused one fails its request without reaching it.
- An earlier version of this record judged the URL with the WHATWG parser, handed over its normalised `href`, and dropped a failing challenge, leaving its request to time out.
- Shared decision: nostr-adrs ADR-0054.
