# 0015. The client signer pairs by `nostrconnect://` by learning the signer from its echoed secret

## Status

Accepted

## Context

NIP-46 defines two ways to start a connection, and the client role implements the client's side of pairing, so it must support the one the client initiates as well as `bunker://`. In that flow the client does not know the remote signer's key in advance: it shows a `nostrconnect://` URL, waits, and "discovers `remote-signer-pubkey` from connect response author"; the `secret` "MUST be provided to avoid connection spoofing" and the client "MUST validate the `secret` returned by `connect` response". The response's request id is the signer's choice, so it cannot be correlated to anything the client sent. Kind 24133 is ephemeral, so relays do not store it: the client must already be listening when the signer answers.

A separate pairing function returning the signer's key would leave the host to build a second signer and to know that this one must not send `connect`. A second factory would duplicate the whole request path.

## Decision

- `createNip46ClientSigner` takes `remoteSignerPubkey: null` for a client-initiated pairing, with the URL's `secret` and relays; construction throws if there is no non-empty secret, which is a programming error.
- `connect()` then opens the subscription at once — on the client's relays, addressed to the client key, with no author filter — and waits for a response whose `result` equals the secret, compared in constant time. That response's author becomes the remote signer; every later event from any other author is dropped, and `switch_relays` (ADR-0018) and `get_public_key` follow as in the `bunker://` flow. No `connect` request is sent.
- A response carrying any other result is ignored, not treated as a refusal, since anyone can address the client key. The wait ends at `timeoutMs` or `disconnect()` with `disconnected`.
- `getRemoteSignerPubkey()` exposes the learned key so the host can persist the pairing and restore it later as an ordinary `bunker://` pairing with a known key.
- `formatNostrConnectUrl` and `parseNostrConnectUrl` are the single owners of the URL format; `perms` keeps each well-formed NIP-46 permission once — any NIP-46 method, or `sign_event:<kind>` for a valid kind — and drops anything else.

## Consequences

- One factory, one request path and one set of response checks serve both flows.
- The host must call `connect()` before showing the URL, or a fast signer's response can be missed.
- Once paired, the client asks the signer to `switch_relays` and moves to the relays it names (ADR-0018); a signer that does not answer with a list leaves it on the relays it named, where a bunker that answers on both (ADR-0014) still reaches it.
