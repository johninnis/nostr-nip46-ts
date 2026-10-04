# 0007. The bunker's state is bounded, and a full queue refuses rather than evicts

## Status

Accepted

## Context

The bunker accumulates state per peer while it runs: event ids seen, clients connected, the cipher each client speaks, the relays each paired client listens on, and requests waiting for the host's decision. Any peer can create more of it by generating keys and sending requests, so unbounded state is a memory-exhaustion vector for a process meant to run for as long as the user is signed in. Bounding everything by evicting the oldest entry is the uniform answer, and it is wrong for exactly one of them: evicting a waiting request drops it silently, and its client hangs until it times out.

## Decision

- The seen-id set (ADR-0006), the connected clients, the per-client ciphers and the per-client relays are each bounded at 10,000 entries, evicting the oldest first. An evicted client must connect again, exactly as after a restart; an evicted relay set means that client is answered on the bunker's own relays only.
- The queue of requests awaiting a decision is never evicted from. At 1,000 requests a new one is answered with the error `too many pending requests`.
- All of it belongs to one session, created by `start` and discarded by `stop`. The record of used `connect` secrets is the one exception: it belongs to the bunker and outlives the session (ADR-0017).

## Consequences

- The bunker's memory is bounded whatever its peers do.
- A client whose request cannot be queued is told so at once rather than timing out; the host drains the queue by deciding requests.
- A reader tempted to make the queue evict like the maps do would reintroduce the silent hang. The queue carries a fence pointing here, and a test fills it and asserts the refusal.
