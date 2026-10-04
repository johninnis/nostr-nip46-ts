# 0010. An auth challenge the host cannot open fails the request

## Status

Accepted

## Context

NIP-46 expects the client to show an `auth_url` challenge to the user and keep listening for the real reply under the same request id. `onAuthChallenge` is optional, because a host with no way to open a page — a background task, a test — still wants a signer. Such a host could ignore the challenge and let the request wait, but the reply the bunker promises arrives only after the user authorises in a page nobody opened, so the request would sit until its timeout and then report `disconnected`, hiding the real reason.

## Decision

When a valid challenge (ADR-0009) arrives and no `onAuthChallenge` is supplied, the request fails at once with its method's own failure mode and the message `bunker requires authentication: <url>`. When `onAuthChallenge` is supplied, it is called and the request stays pending for the real reply.

## Consequences

- A host without a way to show the page learns why the request failed, and when, rather than waiting out the timeout.
- The failure carries the URL, so a host can still offer it to the user by other means.
- A challenge that is not a web URL is dropped either way (ADR-0009), so this failure never carries a non-web URL.
- Shared decision: nostr-adrs ADR-0112.
