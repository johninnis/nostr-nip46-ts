# 0012. `switch_relays` reports the signer's own relay set

## Status

Accepted

## Context

NIP-46 defines the result of `switch_relays` as the signer's "updated list of relays, or `null` if there is nothing to be changed", and says the signer should stay in control of which relays a connection uses — explicitly because a client-initiated pairing may name relays foreign to the signer. Some clients gate their handshake on a non-error reply. The bunker's relay set is fixed when it starts; it never re-subscribes in answer to this method.

Answering with an invented `"ack"` gets such clients through, but it is not a type the method defines. Answering `null` is truthful for a client that already talks on the signer's relays, but gives a client paired on its own relays (ADR-0014) no reason to move. Answering with the client's relays as well as the signer's tells it to stay where it is, which defeats the method.

## Decision

The reply to `switch_relays` is the JSON-encoded list of the bunker's own relays — the set it was started with and advertises in its `bunker://` URL. Nothing is switched or re-subscribed in response.

## Consequences

- The reply has exactly the type the specification defines, whether or not the client needs to move.
- For a client that paired on its own relays, the reply is the hint to migrate; a client that ignores it keeps working, because the bunker also answers it on its own relays (ADR-0014).
- The reply is not an inventory of every relay the bunker answers that client on; it is an instruction about where to talk.
- A reader could expect a real switch. The dispatch carries a fence pointing here, and a test asserts the reply is the bunker's own set.
