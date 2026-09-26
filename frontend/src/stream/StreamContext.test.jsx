/**
 * A burst of frames is one refetch. Refetching per frame would cancel each refetch with
 * the next, and during a flood the lists could stay loading for as long as it lasts.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { REFETCH_COALESCE_MS, StreamProvider } from './StreamContext'

vi.mock('../auth/AuthContext', () => ({ useAuth: () => ({ token: 'a-token' }) }))

class FakeSocket {
  static last = null
  constructor(url) {
    this.url = url
    FakeSocket.last = this
  }
  close() {}
}

describe('StreamProvider', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.stubGlobal('WebSocket', FakeSocket)
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  it('gathers a burst of alert frames into one refetch of each list', () => {
    const queryClient = new QueryClient()
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries').mockResolvedValue()
    render(
      <QueryClientProvider client={queryClient}>
        <StreamProvider>
          <span />
        </StreamProvider>
      </QueryClientProvider>,
    )

    const socket = FakeSocket.last
    act(() => socket.onopen())
    act(() => {
      for (let id = 1; id <= 20; id += 1) socket.onmessage({ data: JSON.stringify({ alert_id: id }) })
    })
    expect(invalidate).not.toHaveBeenCalled()

    act(() => vi.advanceTimersByTime(REFETCH_COALESCE_MS))
    expect(invalidate.mock.calls.map(([filters]) => filters.queryKey)).toEqual([
      ['alerts'],
      ['alert-summary'],
    ])

    // The next frame after the window starts a new one.
    act(() => socket.onmessage({ data: JSON.stringify({ alert_id: 21 }) }))
    act(() => vi.advanceTimersByTime(REFETCH_COALESCE_MS))
    expect(invalidate).toHaveBeenCalledTimes(4)
  })
})
