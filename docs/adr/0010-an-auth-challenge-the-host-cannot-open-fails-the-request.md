# 0010. An auth challenge the host cannot open fails the request

## Status

Accepted

## Context

NIP-46 expects the client to show an `auth_url` challenge to the user and keep listening for the real reply under the same request id. `onAuthChallenge` is optional, because a host with no way to open a page — a background task, a test — still wants a signer. Such a host could ignore the challenge and let the request wait, but the reply the bunker promises arrives only after the user authorises in a page nobody opened, so the request would sit until its timeout and then report `disconnected`, hiding the real reason.

## Decision

When a valid challenge (ADR-0009) arrives and no `onAuthChallenge` is supplied, the request fails at once with its method's own failure mode and the message `bunker requires authentication: <url>`, the URL exactly as the bunker sent it. When `onAuthChallenge` is supplied, it is called and the request stays pending for the real reply, and its deadline restarts as an approval window, `approvalWindowMs`, five minutes by default. `timeoutMs` bounds a bunker that does not answer; a challenge is an answer, saying a person must now act, and a person approving on another device takes longer than a request takes on the network. Each challenge for the request restarts the window, replacing whatever was left of `timeoutMs` or of the window before it. A request still unanswered when the window closes fails as a timed-out request does: `disconnected`, with the message `bunker request timed out`.

The failure is the client's own, never the bunker's error, so it is not read as a decline: a URL containing `cancel` or `denied` leaves it in the method's own failure mode, not `rejected`.

## Consequences

- A host without a way to show the page learns why the request failed, and when, rather than waiting out the timeout.
- The failure carries the URL, so a host can still offer it to the user by other means.
- A challenge that is not a web URL fails the request whether or not `onAuthChallenge` is supplied, with a message that carries no URL (ADR-0009), so this failure never carries a non-web URL.
- A request waiting on a person is not cut off at `timeoutMs`, and a host need not raise `timeoutMs` — which would also slow its detection of a bunker that never answers — to give a person time to approve. Both ports apply the same default window.
- A bunker that keeps sending challenges keeps its request open. Each one reaches `onAuthChallenge`, so the host sees it happen and can `disconnect`; capping the restarts would be a change to this record.
- A fence at `handleChallenge` points here. Tests pin that a reply arriving after `timeoutMs` but within the window settles a challenged request, that one still unanswered when the window closes fails as a timeout, that a further challenge restarts the window, that the default window outlasts `timeoutMs` and closes five minutes after the challenge, and that a request no challenge answered still times out at `timeoutMs`.
- Shared decision: nostr-adrs ADR-0112.
