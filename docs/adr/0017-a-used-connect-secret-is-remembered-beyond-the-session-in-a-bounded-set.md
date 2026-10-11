# 0017. A used `connect` secret is remembered beyond the session, in a bounded set

## Status

Accepted

## Context

NIP-46 says a `bunker://` secret "can be used for single successfully established connection only, _remote-signer_ SHOULD ignore new attempts to establish connection with old secret". The bunker must therefore remember which secrets have been used, and several questions follow that the specification does not answer.

Where the record lives. Session state is discarded by `stop` (ADR-0007), and a host restarts the bunker whenever its relays change, typically passing the same stored secret to `start` again. A record kept in the session would forget the secret on every restart and accept it once more.

How it is bounded. Every other piece of per-peer state is bounded and evicts its oldest entry (ADR-0007). Evicting a used secret looks as if it would let that secret connect again, which is exactly what the record exists to prevent.

What the client that used a secret gets when it presents it again. Its `connect` reply can be lost on the relays, and a client that retries is not a new attempt to establish a connection: ignoring it leaves the client that legitimately paired hanging until its timeout.

And what everyone else gets. Ignoring a used secret, as the specification suggests, looks like withholding from the holder of a leaked URL whether its secret was real. But the bunker answers a secret it never issued `invalid secret`, so silence for a used one tells that holder exactly that the secret was real and has been used, the signal the silence was meant to withhold. It also leaves a client holding a stale or mistyped URL waiting out its timeout, as it would against a signer that is down. Only answering both the same way reveals nothing.

## Decision

- The record of used secrets belongs to the bunker, not the session: it survives `stop` and `start`. `start` with a used secret serves, but has no secret to offer until the host calls `issueSecret`.
- It maps each used secret to the client that used it, bounded at 10,000 entries, evicting the oldest first. Acceptance never consults the record: only the one current secret is accepted, and it stops being current the moment it is used.
- A `connect` presenting a used secret is answered `invalid secret`, exactly as one presenting a secret never issued, and changes nothing. The exception is the client that used it, while that client is still connected: it is answered `ack` again. After `logout` or eviction that client is answered like any other. A used secret evicted from the record is answered `invalid secret` as well, because it is not the current secret.
- Using the secret records the use first, then fires `onSecretUsed(secret, clientPubkey)` and `onUpdate`. `getBunkerUrl` returns `null` until `issueSecret` supplies a fresh secret, which must be non-empty and not already on record.

## Consequences

- A secret connects exactly one client, however often the host restarts the bunker within one process, and eviction from the record changes nothing about how an old secret is answered.
- Answering a used secret departs from the specification's SHOULD knowingly: ignoring a used secret while answering an unknown one is the very signal the silence was meant to withhold, and ignoring both strands every client holding a stale URL until its timeout. Re-acknowledging the client that used the secret departs from it for the same reason, and tells a holder of a leaked URL nothing.
- The record forgets nothing across `stop` and `start`, but everything across a process restart. The host is told when a secret is used so it can retire its stored secret, issue a fresh one and persist the paired client for `restorePairing`; a host that ignores `onSecretUsed` will hand a used secret to `start` after a reload.
- A client whose `connect` reply was lost can retry and still pair.
- `issueSecret` may accept a secret evicted from the record; at ten thousand issued secrets that is theoretical, and such a secret still connects only once.
- A reader will expect the record to be session state, or to see eviction as a hole. The record's declaration and the check that re-acknowledges a client carry fences pointing here. Tests assert that a second client, the first after `logout`, and anyone after a restart with the used secret are answered `invalid secret`, and that the client still connected is answered `ack`.
- An earlier version of this record ignored a used secret, with no reply, unless it came from the client still connected by it.
- Shared decision: nostr-adrs ADR-0058.
