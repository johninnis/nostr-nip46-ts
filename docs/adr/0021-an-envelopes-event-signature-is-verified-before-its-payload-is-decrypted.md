# 0021. An envelope's event signature is verified before its payload is decrypted

## Status

Accepted

Supersedes ADR-0001, which took a successful decryption under the claimed sender's conversation key as the sole authentication of an inbound event and skipped signature verification. That decision is reversed here in full.

## Context

Each NIP-46 message arrives as a signed kind 24133 event whose payload is encrypted under a conversation key derived by ECDH between the two parties. NIP-44 mandates the order of operations: "The outer signature serves to authenticate the full payload, and MUST be validated before decrypting", and "Before decryption, the event's pubkey and signature MUST be validated as defined in NIP 01." ADR-0001 did not cite these clauses.

ADR-0001's argument — that decryption already proves the sender's key custody — is true of the payload but of nothing else in the envelope. The signature is what covers `created_at` and what makes the event id unforgeable: anyone can take a captured envelope, rewrite `created_at`, and recompute the id without holding a key. Redelivered events are deduplicated by event id (ADR-0006), so an unverified envelope can be replayed with a fresh timestamp under a fresh id and the request executed again. A legacy NIP-04 envelope (ADR-0003) has no MAC at all; without the signature its only integrity check is that the decrypted bytes parse.

## Decision

`handleEvent` in both roles — the bunker's and the client signer's — verifies the inbound event's signature (`verifyEventSignature`, injectable with the core default) before the event is remembered for deduplication and before its payload is decrypted. Verification comes first so that a signature-mangled copy of a legitimate event cannot poison the seen-set. An event whose signature fails is dropped without a reply, exactly as an undecryptable one is.

Both roles order their inbound gates cheapest-first: does the author match the awaited peer (where the role awaits one), is the signature valid, has this event id been seen, then decrypt. One order, both roles — anything else pays a Schnorr verification for an event a cheaper check would have dropped, or lets junk from an unexpected author occupy the seen-set.

## Consequences

- `createNip46Bunker` takes an optional `verifyEventSignature`; the client signer already had one for bunker-signed events, and the same verifier now also gates response envelopes.
- A replayed envelope with an altered `created_at` and recomputed id fails verification, so id-based deduplication cannot be bypassed that way.
- A MAC-less NIP-04 envelope gains integrity: every byte either role acts on is covered by the signature.
- Shared decision: nostr-adrs ADR-0048.
