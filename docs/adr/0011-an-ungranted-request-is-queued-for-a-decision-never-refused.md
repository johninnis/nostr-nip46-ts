# 0011. An ungranted request is queued for a decision, never refused

## Status

Accepted

## Context

A bunker that answers `get_public_key` and every cipher method for any connected client, queueing only `sign_event`, lets its user decide what is signed but not what is decrypted: a connected application could read any message the user can read, and nobody would be asked. NIP-46 has a vocabulary for what a client may do — permissions of the form `method[:params]`, such as `nip44_decrypt` or `sign_event:4` — and says client-supplied metadata "MUST NOT" be used for authorisation, so something on the signer's side has to decide.

For a request the grants do not cover there are two choices: refuse it with an error, or ask the user. Refusing makes the grants the only way a method can ever be answered, so anything not anticipated at pairing fails permanently and the user is never asked. Asking is what a remote signer exists to do, and a decrypt the user has not pre-approved is no less worth asking about than a signature.

The bunker has no notion of an application: a `bunker://` session has one secret, and a client is identified by its key alone.

## Decision

- The bunker takes a mandatory `isAuthorised(clientPubkey, permission)` from the host and asks it, per request, about `get_public_key`, `sign_event` (as `sign_event:<kind>`) and the four `nip04_*` / `nip44_*` methods.
- A granted request is answered at once. An ungranted one is queued as a `PendingRequest` for the host to approve or reject, whatever its method. Nothing is refused for want of a grant.
- `connect` is gated by the current, unused secret (ADR-0017); `ping`, `switch_relays` and `logout` carry no capability and are always answered to a connected client, without asking.
- Parameters that do not parse are answered with an error when the request arrives, and never queued or asked about.
- The permissions a `nostrconnect://` URL requests are never treated as grants (ADR-0013).

## Consequences

- A host can put the user in front of every capability, not only signing, and an application that asks for something ungranted gets an answer once the user decides rather than a permanent error.
- The only refusals are unparseable input, an unknown method, a bad secret, an unconnected client and a full queue (ADR-0007).
- `isAuthorised` is required, not optional: without it the bunker cannot choose between answering and asking, and neither default is safe. A host that wants the previous behaviour grants everything except `sign_event`; one that wants to decide everything by hand returns `false`.
- The queue holds any capability request, so a queued request's `detail` is a union discriminated by `method`, and the host's approval UI must render each kind.
- The call that chooses between answering and queueing carries a fence pointing here.
