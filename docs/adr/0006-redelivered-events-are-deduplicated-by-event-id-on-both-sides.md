# 0006. Redelivered events are deduplicated by event id, on both sides

## Status

Accepted

## Context

The bunker and the client each listen on several relays, so one event routinely arrives once per relay. For a correlated response that is harmless: completing a pending request is idempotent, and a second completion finds nothing to settle. For everything else it is not. The bunker would queue or answer one request several times, and the client would hand one `auth_url` challenge to the host once per relay, opening the same authorisation page again and again.

A set of seen event ids handles that redelivery, and only that. It is bounded, so it forgets: an id evicted after ten thousand newer events, or forgotten at a restart, is accepted again. That is harmless for redelivery, whose window closes in seconds, but it means the set is not replay protection: a captured request republished once its id has left the set would be executed again.

Both roles subscribe from a minute before now, so an honest relay never delivers an old event at subscription time. A relay that ignores `since`, or applies it only to stored events and forwards every new arrival, delivers a republished old request as if it were current. NIP-46 says nothing about an envelope's age, but its requests are short-lived: a client whose request has gone unanswered for minutes has timed out and given up, so an old request has no one waiting for it.

## Decision

- The bunker and the client each keep a set of event ids they have seen, bounded at 10,000 and evicting the oldest first, and drop an event already seen before decrypting it.
- Each drops, without a reply and before decrypting, an envelope whose `created_at` is more than ten minutes (600 seconds) before or after its own clock, the injected `now`. An envelope exactly ten minutes off is within the window.
- The inbound gates run in one order in both roles (ADR-0021): the author, where the role awaits one; the signature; the window; the seen-set; then decryption. The client drops an event from any author but the remote signer first, so events it would ignore anyway cannot evict ids from the set. The window is judged after the signature, so it judges the timestamp the author signed, and before the seen-set, so a stale envelope is never remembered: it cannot evict the id of a live one, and an envelope from the future is judged again when it is redelivered within the window.
- Completing a pending request stays idempotent, because a response can still arrive after its request timed out, or after its id was evicted.

## Consequences

- An `auth_url` challenge reaches the host once per challenge event, however many relays deliver it. A bunker that deliberately re-issues a challenge publishes a new event with a new id, and that reaches the host again.
- Redelivered ciphertext is not decrypted repeatedly.
- An envelope replayed more than ten minutes after it was signed is dropped whatever the relay does; one replayed within ten minutes is caught by the seen-set, unless ten thousand newer events arrived in that time.
- Ten minutes absorbs the skew of an unsynchronised phone and a slow relay; a peer whose clock is further off cannot exchange messages at all, and must fix its clock.
- Do not read the seen-set as replay protection, and do not grow it to make it one: the window is what bounds a replay.
- Both checks carry fences pointing here. Tests deliver one challenge event twice and assert one notification, deliver envelopes just inside and just outside the window on either side, verify the signature of a stale envelope before it is dropped, and redeliver a once-stale envelope within the window and assert it is handled.
- An earlier version of this record deduplicated by id alone and judged no envelope's age, taking eviction from the seen-set to be harmless.
- Shared decision: nostr-adrs ADR-0050.
