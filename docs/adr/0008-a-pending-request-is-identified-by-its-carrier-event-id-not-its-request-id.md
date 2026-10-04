# 0008. A pending request is identified by its carrier event id, not its request id

## Status

Accepted

## Context

A queued request must be addressable so the host can approve or reject it, and the obvious key is the request `id` the client chose: the response must echo it, and it is already in hand. It is unique only per client. NIP-46 lets each client mint ids however it likes, and sequential ids (`"1"`, `"2"`) are common, so with concurrent clients one client's request silently overwrites another's in the queue: the earlier client hangs and the host never sees its request. The clients cannot avoid it, since payloads are encrypted and neither sees the other's ids.

Every request arrives in its own kind 24133 event, whose id is a hash — unique by construction — and already deduplicated (ADR-0006).

## Decision

A pending request's identity is the id of the event that carried it, `PendingRequest.id`, and `approve` and `reject` take that `EventId`. The client's request id is kept beside it as `requestId`, solely to correlate the response.

## Consequences

- Concurrent clients, or one client reusing an id, can never displace each other's queued requests.
- `PendingRequest` carries two ids, and a reader will be tempted to merge them: one is the queue identity, the other is wire correlation. A test queues two requests sharing a request id and answers them independently.
- Nothing changes on the wire: the response still carries exactly the id the client chose.
