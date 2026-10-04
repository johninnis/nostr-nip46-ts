# 0013. A client-initiated pairing is authenticated without a `connect` request

## Status

Accepted

## Context

In a `bunker://` pairing the client sends `connect` with the bunker's secret, and that is how the bunker connects it. In the reverse flow the client mints `nostrconnect://<client-pubkey>?relay=…&secret=…` and listens; the user pastes it into the signer, which "sends `connect` *response* event to the `client-pubkey`" whose result is the secret, and the client learns the signer's key from that response's author. No `connect` request ever arrives. A bunker that connects clients only on `connect` would then answer every later request from that client `not connected`. Waiting for a later `connect` strands conforming clients, and treating a client that presents a known secret on some later request as connected weakens the one authentication rule the bunker has.

## Decision

- The bunker has a second, explicit way to connect a client: `acceptNostrConnect(url)`, called when the user accepts a parsed `nostrconnect://` URL, connects the URL's client key and sends it a `connect` response whose result is the URL's secret. The act of authorisation is the user pasting and accepting the URL.
- `restorePairing(clientPubkey, relays)` re-establishes such a pairing after a restart without sending the secret again, because the client is not waiting for it.
- The URL's `perms`, `name`, `url` and `image` are display hints for the host. Requested permissions are never honoured as grants (ADR-0011).

## Consequences

- There are exactly two ways a client becomes connected: a `connect` request carrying the bunker's current, unused secret (ADR-0017), and an accepted `nostrconnect://` URL. `restorePairing` re-establishes a connection one of them made.
- In this flow the secret proves the signer to the client; it is not a credential the bunker checks.
- Once connected, a client is a client: nothing distinguishes a client-initiated pairing afterwards. Only the host's own records know which pairings to restore.
- Shared decision: nostr-adrs ADR-0115.
