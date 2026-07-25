import type { NostrEvent, NostrFilter, RelayUrl } from "@innis/nostr-core"

/**
 * Lifecycle state of a NIP-46 subscription:
 * - `pending` — opening: awaiting a socket, an AUTH handshake, or the stored backlog to drain.
 * - `active` — live: the relay has signalled end-of-stored-events and the subscription is receiving.
 * - `closed` — terminally torn down (relay `CLOSED`, pool teardown) or never established.
 */
export type Nip46SubscriptionStatus = "pending" | "active" | "closed"

/** Inputs to a single NIP-46 subscription: a filter, the relay set to open it on, the per-event callback, and an optional lifecycle-status callback. */
export interface Nip46SubscribeOptions {
  /** The Nostr filter selecting kind 24133 envelopes addressed to this peer. */
  readonly filter: NostrFilter
  /** Every relay to open the subscription on; one matching event may arrive from any of them. */
  readonly relays: ReadonlyArray<RelayUrl>
  /** Invoked once per received event. De-duplication across relays is the caller's responsibility. */
  readonly onEvent: (event: NostrEvent) => void
  /** Invoked on every {@link Nip46SubscriptionStatus} transition, beginning with the subscription's initial state. */
  readonly onStatus?: (status: Nip46SubscriptionStatus) => void
}

/** Handle to a live subscription returned by {@link Nip46Transport.subscribe}. */
export interface Nip46Subscription {
  /** Tears the subscription down on every relay it was opened on. */
  readonly abort: () => void
}

/**
 * Outcome of publishing one envelope to one relay. Structurally satisfied by a relay pool's
 * own publish response (for example `@innis/nostr-relay-pool`'s `PublishResponse`), so a
 * transport can forward it unchanged.
 */
export interface Nip46PublishResult {
  /** `true` when that relay accepted the event. */
  readonly ok: boolean
}

/**
 * The sole Nostr-on-the-wire surface this library touches — an injected port so the library can
 * be ported to any environment and tested without a real relay pool. Typically wired straight to
 * a relay pool's `subscribe` / `publish` (for example `@innis/nostr-relay-pool`).
 */
export interface Nip46Transport {
  /** Opens a multi-relay subscription and returns a handle to abort it. */
  readonly subscribe: (options: Nip46SubscribeOptions) => Nip46Subscription
  /**
   * Publishes one event to a single relay and resolves with whether that relay accepted it.
   * A request whose envelope no relay accepted can never be answered, so the library fails it
   * immediately rather than leaving the caller waiting for the request timeout.
   */
  readonly publish: (relayUrl: RelayUrl, event: NostrEvent) => Promise<Nip46PublishResult>
}
