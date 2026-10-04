# 0002. The client verifies the event a bunker signed for it

## Status

Accepted

## Context

A remote signer returns the signed event for a `sign_event` request, and trusting it as returned looks reasonable: the client asked for it. But which key signs is decided by software outside the client — the user may have switched accounts in the bunker — and a bunker can return anything. An event signed by another key would be published under the user's apparent identity; one with a broken signature would be refused later by every relay, far from the call that produced it.

## Decision

`signEvent` refuses a returned event whose `pubkey` is not the connected user's, returning `pubkey-mismatch` and calling `onPubkeyMismatch`, and refuses one whose signature does not verify, returning `sign-failed`. The signature check is injectable (`verifyEventSignature`) and defaults to `@innis/nostr-core`'s. The client exposes no public raw request method through which `sign_event` could be sent without these checks.

## Consequences

- A caller holding a signed event from the client can publish it.
- An account switch in the bunker surfaces as a mismatch the host can act on — typically by logging out — rather than as a silently foreign event.
- A host that needs a NIP-46 method with no typed wrapper has no public entry point; that is the cost of not shipping a general method-caller that could bypass these checks.
