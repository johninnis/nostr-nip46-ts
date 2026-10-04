import type { CipherScheme, EventId, PublicKey, RelayUrl } from "@innis/nostr-core"
import { createBoundedMap, createSeenEventIds } from "./bounded-map.ts"
import type { PendingRequest } from "./pending-request.ts"

const AUTHENTICATED_CLIENT_LIMIT = 10_000
export const PENDING_REQUEST_LIMIT = 1_000
const CLIENT_CIPHER_LIMIT = 10_000

export interface BunkerSessionConfig {
  readonly userPubkey: PublicKey
  readonly relays: ReadonlyArray<RelayUrl>
}

export interface BunkerSession extends BunkerSessionConfig {
  readonly rememberSeen: (eventId: EventId) => boolean
  readonly authenticate: (client: PublicKey) => void
  readonly deauthenticate: (client: PublicKey) => void
  readonly isAuthenticated: (client: PublicKey) => boolean
  readonly recordCipher: (client: PublicKey, cipher: CipherScheme) => void
  readonly cipherFor: (client: PublicKey) => CipherScheme
  readonly recordRelays: (client: PublicKey, relays: ReadonlyArray<RelayUrl>) => void
  readonly relaysFor: (client: PublicKey) => ReadonlyArray<RelayUrl>
  readonly startListeningOn: (relays: ReadonlyArray<RelayUrl>) => ReadonlyArray<RelayUrl>
  readonly queue: (request: PendingRequest) => boolean
  readonly take: (id: EventId) => PendingRequest | undefined
  readonly pending: () => ReadonlyArray<PendingRequest>
}

const unique = (relays: ReadonlyArray<RelayUrl>): ReadonlyArray<RelayUrl> => [...new Set(relays)]

export const createBunkerSession = (config: BunkerSessionConfig): BunkerSession => {
  const seenEventIds = createSeenEventIds()
  const authenticatedClients = createBoundedMap<true>(AUTHENTICATED_CLIENT_LIMIT)
  const clientCiphers = createBoundedMap<CipherScheme>(CLIENT_CIPHER_LIMIT)
  const clientRelays = createBoundedMap<ReadonlyArray<RelayUrl>>(AUTHENTICATED_CLIENT_LIMIT)
  const listeningOn = new Set<RelayUrl>(config.relays)
  const pending = new Map<EventId, PendingRequest>()

  return Object.freeze({
    ...config,
    rememberSeen: seenEventIds.remember,
    authenticate: (client: PublicKey): void => authenticatedClients.set(client, true),
    deauthenticate: (client: PublicKey): void => authenticatedClients.forget(client),
    isAuthenticated: (client: PublicKey): boolean => authenticatedClients.has(client),
    recordCipher: (client: PublicKey, cipher: CipherScheme): void => clientCiphers.set(client, cipher),
    cipherFor: (client: PublicKey): CipherScheme => clientCiphers.get(client) ?? "nip44",
    recordRelays: (client: PublicKey, relays: ReadonlyArray<RelayUrl>): void =>
      clientRelays.set(client, unique(relays)),
    relaysFor: (client: PublicKey): ReadonlyArray<RelayUrl> => {
      const own = clientRelays.get(client)
      return own === undefined ? config.relays : unique([...config.relays, ...own])
    },
    startListeningOn: (relays: ReadonlyArray<RelayUrl>): ReadonlyArray<RelayUrl> => {
      const unlistened = unique(relays).filter((relay) => !listeningOn.has(relay))
      for (const relay of unlistened) listeningOn.add(relay)
      return unlistened
    },
    // Deliberate: a full queue refuses rather than evicts — a silently dropped request would hang its client — see ADR-0007
    queue: (request: PendingRequest): boolean => {
      if (pending.size >= PENDING_REQUEST_LIMIT) return false
      pending.set(request.id, request)
      return true
    },
    take: (id: EventId): PendingRequest | undefined => {
      const request = pending.get(id)
      pending.delete(id)
      return request
    },
    pending: (): ReadonlyArray<PendingRequest> => [...pending.values()],
  })
}
