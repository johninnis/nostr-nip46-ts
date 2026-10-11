# 0002. The client verifies the event a bunker signed for it

## Status

Accepted

## Context

A remote signer returns the signed event for a `sign_event` request, and trusting it as returned looks reasonable: the client asked for it. But which key signs is decided by software outside the client — the user may have switched accounts in the bunker — and a bunker can return anything. An event signed by another key would be published under the user's apparent identity; one with a broken signature would be refused later by every relay, far from the call that produced it.

And a valid signature by the right key proves only who signed, not what was signed: a bunker that changes the kind, the content, the tags or the timestamp returns an event the caller never asked for, correctly signed, and the caller publishes it.

## Decision

- `signEvent` refuses a returned event whose `pubkey` is not the connected user's, returning `pubkey-mismatch` and calling `onPubkeyMismatch`.
- It then refuses one whose `kind`, `content`, `created_at` or `tags` differ from the template it sent — the output of `buildUnsignedEvent`, so an addressable kind carries the `["d", ""]` the client added — returning `sign-failed` with the message `Signer returned an event that differs from the template it was asked to sign`. Tags are compared in order, each element by element; `id`, `pubkey` and `sig` are the only fields a bunker adds. The comparison is `@innis/nostr-core`'s `checkSignedMatchesTemplate`, the one rule every adapter for an outside signer applies.
- It then refuses one whose id or signature does not verify, returning `sign-failed`. The check is injectable (`verifyEventSignature`) and defaults to `@innis/nostr-core`'s.
- The client exposes no public raw request method through which `sign_event` could be sent without these checks.

## Consequences

- A caller holding a signed event from the client can publish it: it is the event the caller asked for, signed by the user's key.
- An account switch in the bunker surfaces as a mismatch the host can act on — typically by logging out — rather than as a silently foreign event.
- A bunker that rewrites the event, adds a tag of its own or re-stamps its time fails the call, however well it signed.
- The order is fixed: an account switch is reported as one even when the content also differs, and a rewritten event is reported as rewritten before its signature is checked.
- A host that needs a NIP-46 method with no typed wrapper has no public entry point; that is the cost of not shipping a general method-caller that could bypass these checks.
- The comparison carries a fence pointing here. Tests change each field and the tags in each way and assert the refusal, accept an addressable event carrying the `d` tag the client added, and pin the order of the three checks.
- An earlier version of this record checked only the author and the signature.
- Shared decision: nostr-adrs ADR-0049.
