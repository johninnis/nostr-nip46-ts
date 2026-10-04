# 0016. Wire forms outside the specification are tolerated where deployed clients send them

## Status

Accepted

## Context

NIP-46 defines `params` as "a positional array of string parameters", `sign_event`'s first parameter as a JSON-stringified event, and `connect`'s first parameter as the remote signer's public key. Some deployed clients send `sign_event`'s event as a raw JSON object rather than a string, and some send `connect` with an empty signer key and rely on the secret. Rejecting either shuts those clients out, with an error they do not act on.

## Decision

- A request parameter that is not a string is replaced by its JSON form before dispatch, so a `sign_event` whose event arrives as an object is handled exactly like one whose event arrives as a string.
- A `connect` whose first parameter is empty is accepted on its secret alone: the request is already bound to this signer by its `p` tag. A `connect` naming a different, non-empty key is answered `invalid signer`.
- A request with no `params` member is read as having an empty parameter list, as JSON-RPC permits. An explicit `null` is not an empty list: it is refused like any other non-array.
- Everything else the bunker receives must match the specification.

## Consequences

- Those clients pair and sign; nothing the bunker sends changes.
- The tolerance is narrow on purpose. Adding another needs its own evidence of a deployed client, and a record.
- Shared decision: nostr-adrs ADR-0116.
