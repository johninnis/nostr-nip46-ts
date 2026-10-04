# 0017. A used `connect` secret is remembered beyond the session, in a bounded set

## Status

Accepted

## Context

NIP-46 says a `bunker://` secret "can be used for single successfully established connection only, _remote-signer_ SHOULD ignore new attempts to establish connection with old secret". The bunker must therefore remember which secrets have been used. Two questions follow that the specification does not answer.

Where the record lives. Session state is discarded by `stop` (ADR-0007), and a host restarts the bunker whenever its relays change, typically passing the same stored secret to `start` again. A record kept in the session would forget the secret on every restart and accept it once more.

How it is bounded. Every other piece of per-peer state is bounded and evicts its oldest entry (ADR-0007). Evicting a used secret looks as if it would let that secret connect again, which is exactly what the record exists to prevent.

And what to do when the client that used a secret presents it again. Its `connect` reply can be lost on the relays, and a client that retries is not a new attempt to establish a connection: ignoring it leaves the client that legitimately paired hanging until its timeout.

## Decision

- The record of used secrets belongs to the bunker, not the session: it survives `stop` and `start`. `start` with a used secret serves, but has no secret to offer until the host calls `issueSecret`.
- It maps each used secret to the client that used it, bounded at 10,000 entries, evicting the oldest first. Acceptance never consults the record: only the one current secret is accepted, and it stops being current the moment it is used. Eviction therefore changes only how an old secret is refused — `invalid secret` instead of silence — and never admits it.
- A `connect` presenting a used secret is ignored, with no reply, unless it comes from the client that used it while that client is still connected, which is answered `ack` again. After `logout` or eviction that client is a stranger to the secret too.
- Using the secret fires `onSecretUsed(secret, clientPubkey)` and `onUpdate`; `getBunkerUrl` returns `null` until `issueSecret` supplies a fresh one, which must be non-empty and not already on record.

## Consequences

- A secret connects exactly one client, however often the host restarts the bunker within one process.
- The record forgets nothing across a process restart. The host is told when a secret is used so it can replace its stored secret and persist the paired client for `restorePairing`; a host that ignores `onSecretUsed` will hand a used secret to `start` after a reload.
- A client whose `connect` reply was lost can retry and still pair.
- `issueSecret` may accept a secret evicted from the record; at ten thousand issued secrets that is theoretical, and such a secret still connects only once.
- A reader will expect the record to be session state, or to see eviction as a hole. Its declaration carries a fence pointing here, and tests restart the bunker with a used secret and assert it stays used.
