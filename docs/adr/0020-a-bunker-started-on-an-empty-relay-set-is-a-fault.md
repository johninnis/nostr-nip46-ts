# 0020. A bunker started on an empty relay set is a fault

## Status

Accepted

## Context

`start` takes the relays the bunker listens and answers on. A bunker started on an empty relay set subscribes nowhere and publishes nowhere: no client can ever reach it, and nothing the host does afterwards — issuing secrets, minting a `bunker://` URL — can work. The URL it advertises would name relays it is not listening on, or none at all.

The previous behaviour was a silent no-op: `start` returned, the bunker sat stopped, and the host discovered the misconfiguration only when no client could connect. An unreachable bunker is not an anticipated outcome to report; it is a caller's bug. The relay set is the host's own configuration, not input from a peer, so no caller has a sensible way to handle an empty one at run time: a returned failure would only be ignored or rethrown, while a thrown argument error stops the misconfigured start where it was made.

## Decision

`start` throws `InvalidArgumentError` when the relay set is empty, before it does anything else. A bunker already running when the bad start is made keeps running, untouched: the faulty call stops nothing, subscribes nothing and changes no secret.

An empty secret is a different case and is not a fault: a started bunker whose secret the host has not supplied yet is a coherent state. `start` with an empty secret starts the bunker with no current secret — it serves its paired clients, can restore them with `restorePairing` and be issued a secret with `issueSecret`, and simply cannot be newly connected until then.

## Consequences

- The misconfiguration surfaces at the call that caused it, not as a client that mysteriously times out.
- A host that restarts a running bunker with a bad relay set loses nothing: its paired clients are still served on the old relays.
- Both NIP-46 ports fail fast here: the PHP bunker throws `InvalidArgumentException` on the same call.
- The check before the stop carries a fence pointing here. Tests pin the throw, that a running bunker still answers and still advertises its URL after a bad start, and that a bunker started with an empty secret serves a restored client, can be issued a secret, and connects no client.
- Shared decision: nostr-adrs ADR-0113.
