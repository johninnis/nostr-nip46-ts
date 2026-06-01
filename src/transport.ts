import type { NostrEvent, NostrFilter, RelayUrl } from "@innis/nostr-core"

/** Inputs to a single NIP-46 subscription: a filter, the relay set to open it on, and the per-event callback. */
export interface Nip46SubscribeOptions {
  /** The Nostr filter selecting kind 24133 envelopes addressed to this peer. */
  readonly filter: NostrFilter
  /** Every relay to open the subscription on; one matching event may arrive from any of them. */
  readonly relays: ReadonlyArray<RelayUrl>
  /** Invoked once per received event. De-duplication across relays is the caller's responsibility. */
  readonly onEvent: (event: NostrEvent) => void
}

/** Handle to a live subscription returned by {@link Nip46Transport.subscribe}. */
export interface Nip46Subscription {
  /** Tears the subscription down on every relay it was opened on. */
  readonly abort: () => void
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
   * Publishes one event to a single relay. The return value is intentionally `unknown`: the
   * library fires-and-forgets to every relay and never reads it, while real implementations may
   * return a richer publish result.
   */
  readonly publish: (relayUrl: RelayUrl, event: NostrEvent) => Promise<unknown>
}
