import type { Result, SignerFailure } from "@innis/nostr-core"

export interface InFlightRequest {
  readonly settle: (result: Result<string, SignerFailure>) => void
  readonly failureType: SignerFailure["type"]
}

interface TimedRequest extends InFlightRequest {
  readonly timer: ReturnType<typeof setTimeout>
}

export interface InFlightRequests {
  readonly open: (id: string, request: InFlightRequest, milliseconds: number) => void
  readonly find: (id: string) => InFlightRequest | undefined
  readonly restartDeadline: (id: string, milliseconds: number) => void
  readonly settle: (id: string, result: Result<string, SignerFailure>) => void
  readonly abandon: (id: string) => boolean
  readonly settleAll: (result: Result<string, SignerFailure>) => void
}

export const createInFlightRequests = (expired: Result<never, SignerFailure>): InFlightRequests => {
  const requests = new Map<string, TimedRequest>()

  const remove = (id: string): TimedRequest | undefined => {
    const request = requests.get(id)
    if (request === undefined) return undefined
    requests.delete(id)
    clearTimeout(request.timer)
    return request
  }

  const settle = (id: string, result: Result<string, SignerFailure>): void => {
    remove(id)?.settle(result)
  }

  const track = (id: string, request: InFlightRequest, milliseconds: number): void => {
    requests.set(id, { ...request, timer: setTimeout(() => settle(id, expired), milliseconds) })
  }

  return Object.freeze({
    open: track,
    find: (id: string): InFlightRequest | undefined => requests.get(id),
    restartDeadline: (id: string, milliseconds: number): void => {
      const request = remove(id)
      if (request !== undefined) track(id, request, milliseconds)
    },
    settle,
    abandon: (id: string): boolean => remove(id) !== undefined,
    settleAll: (result: Result<string, SignerFailure>): void => {
      for (const id of [...requests.keys()]) settle(id, result)
    },
  })
}
