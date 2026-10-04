# 0018. The client switches relays once per handshake, and a failed switch keeps its own

## Status

Accepted

## Context

NIP-46 says "compliant clients should send a `switch_relays` request immediately upon establishing a connection (always, or at reasonable intervals)", that the signer answers "with its updated list of relays, or `null` if there is nothing to be changed", and that "immediately upon receiving an updated relay list, the _client_ should update its local state and send further requests on the new relays". It says nothing about a signer that answers with an error, answers with something that is not a relay list, or does not answer — and older signers predate the method.

Failing `connect` in any of those cases would lock the user out of a signer that serves every other request correctly, over an optimisation. Asking on every request, or on a timer, puts a round-trip or a background process into a library that otherwise sends only what its caller asked for.

A restored session (`initialUserPubkey`) performs no handshake at all.

## Decision

- `connect()` sends `switch_relays` once, straight after the connection is established — after the `connect` acknowledgement for `bunker://`, after the echoed secret for `nostrconnect://` — and before `get_public_key`.
- A JSON array with at least one valid relay URL replaces the client's relays: later requests are published there and the subscription is reopened there alone. Invalid entries are dropped.
- `null`, an error, a timeout, or anything else keeps the client's own relays, and the handshake carries on. A transport fault still propagates (ADR-0005).
- A restored session does not ask. `getRelayUrls()` exposes the adopted relays so the host persists them with the session and restores it on them.

## Consequences

- A signer that dropped or never implemented the method still pairs; one that did not answer costs one `timeoutMs` before `get_public_key` is sent.
- A client paired on its own relays migrates to the signer's (ADR-0012, ADR-0014), and the host must store the new relays or a restored session returns to the old ones.
- Relays change only at a handshake. A signer that moves relays mid-session is followed at the next pairing, not before.
- A reader may expect a failed switch to fail `connect`. The call that keeps the client's relays carries a fence pointing here, and tests drive an error, `null` and an unusable list and assert the handshake completes on the client's own relays.
