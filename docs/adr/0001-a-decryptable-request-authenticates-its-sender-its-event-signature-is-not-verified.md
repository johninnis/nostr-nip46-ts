# 0001. A decryptable request authenticates its sender; its event signature is not verified

## Status

Superseded by ADR-0021. The rule below argued key custody of the payload but left `created_at` and the event id unauthenticated — a replay opening against id-based deduplication — and contradicted NIP-44's MUST that the event signature be validated before decrypting. ADR-0021 verifies the signature first.

## Context

Each request reaches the bunker as a signed kind 24133 event, and the bunker trusts its `pubkey` for connection gating, queue attribution, per-client relays and cipher choice. A reviewer expects a signature check before that trust, and its absence reads as a missing check.

The payload is encrypted under a conversation key derived by ECDH between the bunker's key and the claimed sender's key. That key can be reached from no other pair of keys, and NIP-44 authenticates the ciphertext with a MAC under it, so a payload that decrypts proves its author holds the private key for the `pubkey` it claims. A forger who sets `pubkey` to a connected client's key cannot derive the conversation key and so cannot produce a payload the bunker will read; the request is dropped before any field is used. The NIP-04 fallback (ADR-0003) has no MAC but uses the same ECDH secret, and its plaintext must still parse as a well-formed request.

## Decision

The bunker does not verify the signature of an inbound request event. Successful decryption under the claimed sender's conversation key is the proof of who sent it. An event that decrypts under neither cipher is dropped without a reply, because no request id can be recovered from it.

This authenticates who the sender is. Whether that sender is connected is a separate question, settled by the `connect` secret or an accepted `nostrconnect://` pairing (ADR-0013).

## Consequences

- The request path needs no signature verification, and has no second failure mode for it.
- A reader expecting a signature check before the `pubkey` is trusted will not find one; the decryption is the gate.
- The rule holds only while requests are confidential, sender-keyed payloads. If a request ever had to be retained or relayed as a verifiable artefact, this record is superseded.
