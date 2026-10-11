# 0016. Wire forms outside the specification are tolerated where deployed clients send them

## Status

Accepted

## Context

NIP-46 defines `params` as "a positional array of string parameters", `sign_event`'s first parameter as a JSON-stringified event, and `connect`'s first parameter as the remote signer's public key. Some deployed clients send `sign_event`'s event as a raw JSON object rather than a string, some send `connect` with an empty signer key and rely on the secret, and some omit `params` for a parameterless call, as JSON-RPC permits. Rejecting any of these shuts those clients out, with an error they do not act on.

Meeting the first by encoding every parameter that is not a string, whatever the method and position, accepts far more than any deployed client sends: a number where a public key belongs becomes the string `7`, an array becomes its encoding, and each then travels on as if the client had sent a string. Every malformed parameter would become a supported one.

## Decision

- A `sign_event` whose first parameter is a JSON object, rather than a string holding one, has it replaced by its JSON encoding before dispatch, so it is handled exactly like one whose event arrives as a string. A JSON array, number, boolean or `null` in that place is not an event. Any other parameter that is not a string, of any method and in any position, makes the request malformed: it is dropped without a reply, as every request that does not parse is.
- A `connect` whose first parameter is empty is accepted on its secret alone: the request is already bound to this signer by its `p` tag and by a signature-verified, decryptable envelope (ADR-0021). A `connect` naming a different, non-empty key is answered `invalid signer`.
- A request with no `params` member is read as having an empty parameter list, as JSON-RPC permits. An explicit `null` is not an empty list: it is refused like any other non-array.
- Everything else the bunker receives must match the specification.

## Consequences

- Those clients pair and sign; nothing the bunker sends changes.
- A request carrying a non-string parameter anywhere else gets no reply, exactly as one with an empty id or a non-array `params` gets none, and its client times out.
- The tolerance is narrow on purpose. Adding another needs its own evidence of a deployed client, and a record.
- `parseRequest` carries fences pointing here. Tests drive a `sign_event` whose event is an array, a number or `null`, one whose second parameter is a number, and a `ping` carrying an object, and assert each is dropped unanswered and unqueued.
- An earlier version of this record replaced every non-string parameter of every method by its JSON encoding.
- Shared decision: nostr-adrs ADR-0116.
