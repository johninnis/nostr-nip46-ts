# 0006. Redelivered events are deduplicated by event id, on both sides

## Status

Accepted

## Context

The bunker and the client each listen on several relays, so one event routinely arrives once per relay. For a correlated response that is harmless: completing a pending request is idempotent, and a second completion finds nothing to settle. For everything else it is not. The bunker would queue or answer one request several times, and the client would hand one `auth_url` challenge to the host once per relay, opening the same authorisation page again and again.

## Decision

The bunker and the client each keep a set of event ids they have seen, bounded at 10,000 and evicting the oldest first, and drop an event already seen before decrypting it. The client first drops an event whose author is not the remote signer, so events it would ignore anyway cannot evict ids from the set. Completing a pending request stays idempotent, because a response can still arrive after its request timed out, or after its id was evicted.

## Consequences

- An `auth_url` challenge reaches the host once per challenge event, however many relays deliver it. A bunker that deliberately re-issues a challenge publishes a new event with a new id, and that reaches the host again.
- Redelivered ciphertext is not decrypted repeatedly.
- Eviction can in principle forget an id seen long ago; at ten thousand entries the redelivery window has closed, so the risk is theoretical.
- The client's check carries a fence pointing here, backed by a test that delivers one challenge event twice and asserts one notification.
