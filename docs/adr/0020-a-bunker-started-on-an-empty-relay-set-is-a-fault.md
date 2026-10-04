# 0020. A bunker started on an empty relay set is a fault

## Status

Accepted

## Context

`start` takes the relays the bunker listens and answers on. A bunker started on an empty relay set subscribes nowhere and publishes nowhere: no client can ever reach it, and nothing the host does afterwards — issuing secrets, minting a `bunker://` URL — can work. The URL it advertises would name relays it is not listening on, or none at all.

The previous behaviour was a silent no-op: `start` returned, the bunker sat stopped, and the host discovered the misconfiguration only when no client could connect. An unreachable bunker is not an anticipated outcome to report; it is a caller's bug, and the conventions route a programmer error on a trusted value to a thrown argument error.

## Decision

`start` throws `InvalidArgumentError` when the relay set is empty. An empty secret remains a no-op: a started bunker whose secret the host has not supplied yet is a coherent state — it serves its paired clients and simply cannot be newly connected until `issueSecret`.

## Consequences

- The misconfiguration surfaces at the call that caused it, not as a client that mysteriously times out.
- Both NIP-46 ports fail fast here: the PHP bunker throws `InvalidArgumentException` on the same call.
- A test pins the throw.
- Shared decision: nostr-adrs ADR-0113.
