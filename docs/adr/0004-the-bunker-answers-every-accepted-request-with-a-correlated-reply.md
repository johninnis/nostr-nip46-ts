# 0004. The bunker answers every accepted request with a correlated reply

## Status

Accepted

## Context

A client that has sent a request is blocked on a reply carrying its request id. Several things can go wrong on the bunker's side after the request is accepted: the signer can decline or fail to sign; a `nip44_encrypt` or `nip04_encrypt` can be refused by the cipher (an empty or over-long plaintext); a decryption can fail; and sealing the response envelope can itself fail, because a large signed event, or the ciphertext of a near-maximal encrypt result, exceeds the cipher's plaintext limit (NIP-44's 4294967295 bytes since its extended length format, shared ADR-0102). Leaving any of these unanswered hangs the client until its timeout and, for an approved request, silently loses the user's decision. NIP-46 already defines an `error` reply meaning "not fulfilled".

## Decision

- A signer that declines, returning `rejected`, is answered `user rejected`, for any method.
- Otherwise a failed `sign_event` is answered `signing failed`, a failed encryption `encryption failed`, and a failed decryption `decryption failed`.
- When a response that carried a result cannot be sealed, the bunker seals and sends the error `response too large` in its place. A response that was already an error and still cannot be sealed is dropped after one attempt.
- Only these outcomes are converted. A transport fault still propagates (ADR-0005).

## Consequences

- A client always gets a reply to an accepted request: its result or an explicit error, and it can tell a user's refusal from a failure.
- `approve` returns `ok` when the degraded `response too large` reply was delivered: the reply reached the client, even though the result did not.
- The second seal attempt carries a one-line fence pointing here and is pinned by a test that approves an over-large result.
