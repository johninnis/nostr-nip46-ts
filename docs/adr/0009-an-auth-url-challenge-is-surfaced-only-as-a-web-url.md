# 0009. An `auth_url` challenge is surfaced only as a web URL

## Status

Accepted

## Context

A bunker that needs the user to authorise out of band answers with `result: "auth_url"` and a URL in `error`, and the client is expected to "display (in a popup or new tab) the URL". The specification calls it only a URL. It is counterparty-supplied input: a malicious or compromised bunker can send `javascript:`, `data:` or `file:` URLs, and a host that opens what it is handed runs them in the user's browser. Leaving the check to each host is how one of them forgets it, invisibly until it is exploited.

## Decision

The client passes `onAuthChallenge` only an absolute `http:` or `https:` URL with a non-empty host, as parsed by the WHATWG URL parser, and passes the parser's normalised `href` rather than the raw string, so the host opens exactly what was checked. Anything else is treated as a malformed response: the challenge is dropped, the host is not notified, and the request stays pending until the real reply or its timeout.

## Consequences

- A host can never receive a non-web URL through a challenge.
- The URL the host receives may differ in form from the one the bunker sent (a lower-cased scheme and host, surrounding whitespace removed); it is the same address.
- Custom-scheme deep links are unsupported on purpose; allowing one needs a superseding record.
- A reader may see the allowlist as needless strictness over the specification's bare "URL". The allowlist carries a fence pointing here, and tests drive `javascript:`, `data:` and `file:` challenges and assert the host is never called.
