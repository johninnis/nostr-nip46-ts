# 0014. A paired client's relays are recorded per client and answered alongside the signer's

## Status

Accepted

## Context

A `nostrconnect://` pairing (ADR-0013) names the relays the client listens on, which need not overlap the bunker's own. NIP-46 says a client should call `switch_relays` and migrate — "should", not "must". Publishing only to the client's relays loses a client that migrated; publishing only to the bunker's loses one that never does. Replacing the bunker's relay set with each pairing's strands the clients already talking on the old set, and one union of every client's relays would send each client's traffic to every other client's relays and leak them into the advertised `bunker://` URL.

## Decision

- Relays named by a pairing are recorded for that client alone, bounded like the other per-client state (ADR-0007).
- Every response to a client is published to the bunker's own relays together with that client's recorded relays; a client with none recorded is answered on the bunker's own relays only.
- The bunker subscribes on a pairing's relays only where it is not already listening, so relays shared by pairings, or with its own set, are subscribed once. `stop` cancels every subscription.
- The bunker's own relay set stays the one it started with: it is what `getBunkerUrl` advertises and `switch_relays` reports (ADR-0012), and `getSubscriptionStatus` reports the subscription on it.

## Consequences

- A paired client is reachable whether or not it migrates.
- Each response goes to a bounded set of relays — the signer's and one client's — and an unrelated pairing's relays never carry another client's traffic.
- The bunker can hold several subscriptions. A reader expecting one relay set per session will find one per client by construction; tests assert both a paired client answered on the union and an unpaired one on the bunker's own set.
