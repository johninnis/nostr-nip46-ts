# 0005. A relay's refusal is a result, and a transport fault propagates

## Status

Accepted

## Context

Every envelope is published to each relay of the conversation, through the injected transport, and one accepting relay is enough for the peer to receive it. The transport reports each relay's answer as `{ ok }`: a relay that refuses, times out or cannot be reached is an ordinary outcome, which a relay pool already reports as `ok: false`. A transport whose `publish` rejects its promise is something else — the port itself is broken.

Collecting every publish with `Promise.allSettled` looks resilient: a broken relay cannot stop the others. It also turns a broken transport into `delivery-failed`, which the client reports as `disconnected` and the host treats as a flaky network, so the defect is never seen.

## Decision

`sendEnvelope` publishes to every relay and waits with `Promise.all`. It succeeds when any relay answers `ok: true`, returns `delivery-failed` when every relay answers `ok: false` or there is no relay to try, and lets a rejected `publish` propagate. The client's call then rejects with the fault; the bunker's `approve` and `reject` reject; an automatic bunker reply, which has no caller, reports the fault through `reportUnhandledError`.

## Consequences

- A delivery failure always means relays refused; it never hides a broken transport.
- A transport must report a relay's refusal as `ok: false` and reject only when it is itself broken.
- A reader will be tempted to switch to `Promise.allSettled` for resilience. A fence at the call points here, and a test drives a rejecting `publish` and asserts the rejection propagates.
