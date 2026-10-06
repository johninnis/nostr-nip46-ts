# 0003. The envelope payload names its cipher, and each peer is answered in the cipher it used

## Status

Accepted

## Context

NIP-46 defines the kind 24133 content as "[NIP-44](44.md) encrypted", in both directions. Earlier revisions used NIP-04, and counterparties deployed against them still speak it. Refusing them drops their requests silently, since an envelope that cannot be decrypted gets no reply (ADR-0021), and the legacy peer hangs until it times out.

The two payloads cannot be confused. NIP-04 content has the form `<encrypted_text>?iv=<initialization_vector>`; a NIP-44 v2 payload is base64, whose alphabet has no `?`. Trying one cipher and falling back to the other would decrypt every envelope in the other cipher twice and offer each cipher the other's payloads.

## Decision

An inbound envelope containing `?iv=` is opened with NIP-04; any other is opened with NIP-44. It is decrypted once, with that cipher, and a result counts only if it parses as JSON. The cipher of the last envelope opened from a peer is remembered for that peer — per client in the bunker, for the remote signer in the client — and replies and later requests to that peer are sealed with it. A peer that has only spoken NIP-44 is only ever sent NIP-44; the client starts with NIP-44.

The `nip04_encrypt` and `nip04_decrypt` methods are unaffected: they operate on user-supplied payloads and are defined by the specification.

## Consequences

- Legacy peers work, and two current implementations never use NIP-04.
- NIP-04 has no MAC; ADR-0021 verifies the envelope's signature before decryption, which is what gives a NIP-04 envelope its integrity.
- The per-peer cipher state exists only for this fallback. When peers that cannot speak NIP-44 no longer matter, this record is superseded and NIP-04 envelope support deleted.
