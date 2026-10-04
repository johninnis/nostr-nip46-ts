import { isValidKind } from "@innis/nostr-core"
import { isNip46Method, type Nip46Method } from "./protocol.ts"

/**
 * A NIP-46 permission in the specification's `method[:params]` form: any NIP-46 method, or `sign_event:<kind>` for one
 * event kind. A bunker asks its host only about `get_public_key`, the four cipher methods and `sign_event:<kind>`; the
 * rest can appear in a list of requested permissions.
 */
export type Nip46Permission = Nip46Method | `sign_event:${number}`

const KIND_PARAMETER = /^\d+$/

const parsePermission = (raw: string): Nip46Permission | null => {
  const [method = "", parameter, ...rest] = raw.trim().split(":")
  if (rest.length > 0 || !isNip46Method(method)) return null
  if (parameter === undefined) return method
  const kind = Number(parameter)
  return method === "sign_event" && KIND_PARAMETER.test(parameter) && isValidKind(kind) ? `sign_event:${kind}` : null
}

export const parsePermissionList = (perms: string): ReadonlyArray<Nip46Permission> => [
  ...new Set(perms.split(",").map(parsePermission).filter((permission) => permission !== null)),
]
