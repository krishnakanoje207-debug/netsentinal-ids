/**
 * One live alert stream for the whole console.
 *
 * The station clock in the header, the board on the overview and the alert feed all
 * show the same connection, so there is one WebSocket rather than one per page. When a
 * frame arrives the cached queries are refetched rather than spliced, so every list stays
 * exactly what the server would return.
 */

import { useQueryClient } from '@tanstack/react-query'
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'

import { useAuth } from '../auth/AuthContext'
import { useAlertStream } from './useAlertStream'

const StreamContext = createContext(null)

/** How long frames are gathered into one refetch. See onAlert. */
export const REFETCH_COALESCE_MS = 250

export function StreamProvider({ children }) {
  const { token } = useAuth()
  const queryClient = useQueryClient()

  // A burst of alerts (a scan, a flood) arrives as a burst of frames. Refetching per
  // frame would cancel each refetch with the next, and the lists could stay loading for
  // as long as the attack lasts, so frames within a short window share one refetch.
  const pending = useRef(null)
  const onAlert = useCallback(() => {
    if (pending.current !== null) return
    pending.current = setTimeout(() => {
      pending.current = null
      void queryClient.invalidateQueries({ queryKey: ['alerts'] })
      void queryClient.invalidateQueries({ queryKey: ['alert-summary'] })
    }, REFETCH_COALESCE_MS)
  }, [queryClient])
  useEffect(() => () => clearTimeout(pending.current), [])

  const stream = useAlertStream(token, onAlert)

  // When the current connection opened, so "connected for 12 min" can be said.
  const [openedAt, setOpenedAt] = useState(null)
  const previous = useRef(stream.status)
  useEffect(() => {
    if (stream.status === 'open' && previous.current !== 'open') setOpenedAt(Date.now())
    if (stream.status !== 'open') setOpenedAt(null)
    previous.current = stream.status
  }, [stream.status])

  const value = useMemo(() => ({ ...stream, openedAt }), [stream, openedAt])
  return <StreamContext.Provider value={value}>{children}</StreamContext.Provider>
}

/** @returns {{status: import('./useAlertStream').StreamStatus, received: number[],
 *   lastMessageAt: number | null, openedAt: number | null}} */
export function useStream() {
  const context = useContext(StreamContext)
  if (context === null) throw new Error('useStream must be used inside a StreamProvider')
  return context
}

/** Plain words for a connection state. */
export const STREAM_LABEL = {
  open: 'Live',
  connecting: 'Connecting',
  closed: 'Feed stopped',
}
