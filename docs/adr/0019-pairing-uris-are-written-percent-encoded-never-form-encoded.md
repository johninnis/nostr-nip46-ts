# 0019. Pairing URIs are written percent-encoded, never form-encoded

## Status

Accepted

## Context

`bunker://` and `nostrconnect://` URIs carry their relays, secret and metadata in a query string. JavaScript's `URLSearchParams.toString()` renders a space as `+` — the `application/x-www-form-urlencoded` convention — while RFC 3986 percent-encoding renders it `%20`. The NIP-46 text shows `name=My+Client` in its example, so both forms circulate.

The two forms are not interchangeable on the reading side. A form-aware parser (`URLSearchParams`, PHP's `urldecode`) decodes both. A strict RFC 3986 parser decodes `%20` and reads `+` as a literal plus sign — a client name arrives as `My+Client`. The writer cannot know which parser a signer will use.

## Decision

Pairing URIs are written percent-encoded: every query name and value is encoded with `encodeURIComponent`, tightened to escape `!`, `'`, `(`, `)` and `*` as well, so the output is byte-identical to what a strict RFC 3986 encoder (PHP's `rawurlencode`) produces. Reading is unchanged and stays form-tolerant: both `%20` and `+` decode to a space, so URIs minted by either convention still parse.

## Consequences

- A URI written by this library decodes correctly under every parser, strict or form-aware.
- Both NIP-46 ports write the same bytes for the same URL.
- A reader may be tempted to "simplify" the encoder back to `URLSearchParams.toString()`; a fence at `formatPairingUri` points here, and a test pins that a secret with spaces is written with `%20`.
- Shared decision: nostr-adrs ADR-0114.
