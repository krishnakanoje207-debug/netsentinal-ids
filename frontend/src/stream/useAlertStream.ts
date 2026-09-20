/**
 * The live alert feed.
 *
 * Reconnects with exponential backoff, because the dashboard runs over an SSH tunnel
 * and a tunnel drop is routine rather than exceptional. The connection state is
 * returned so the interface can say "disconnected" plainly - an analyst watching a feed
 * that has silently stopped will read the absence of alerts as calm.
 */

import { useCallback, useEffect, useRef, useState } from 'react'

export type StreamStatus = 'connecting' | 'open' | 'closed'

const FIRST_RETRY_MS = 1000
const MAX_RETRY_MS = 30_000

/** Backoff doubles per attempt and then holds, so a long outage stops hammering. */
export function retryDelay(attempt: number): number {
  return Math.min(FIRST_RETRY_MS * 2 ** attempt, MAX_RETRY_MS)
}

export function streamUrl(token: string, base: string = '/api/v1'): string {
  const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws'
  // The token goes in the query string because a browser cannot set headers on a
  // WebSocket handshake. See the note in backend routes/stream.py.
  return `${scheme}://${window.location.host}${base}/alerts/stream?token=${encodeURIComponent(token)}`
}

export interface AlertStreamState {
  status: StreamStatus
  /** Alert ids received since mounting, newest first. */
  received: number[]
  lastMessageAt: number | null
}

export function useAlertStream(
  token: string | null,
  onAlert?: (message: Record<string, unknown>) => void,
): AlertStreamState {
  const [status, setStatus] = useState<StreamStatus>('closed')
  const [received, setReceived] = useState<number[]>([])
  const [lastMessageAt, setLastMessageAt] = useState<number | null>(null)

  const attemptRef = useRef(0)
  const socketRef = useRef<WebSocket | null>(null)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const closedByUsRef = useRef(false)
  const handlerRef = useRef(onAlert)
  handlerRef.current = onAlert

  const connect = useCallback(
    (authToken: string) => {
      setStatus('connecting')
      const socket = new WebSocket(streamUrl(authToken))
      socketRef.current = socket

      socket.onopen = () => {
        attemptRef.current = 0
        setStatus('open')
      }

      socket.onmessage = (event: MessageEvent) => {
        setLastMessageAt(Date.now())
        try {
          const message = JSON.parse(String(event.data)) as Record<string, unknown>
          if (typeof message.alert_id === 'number') {
            setReceived((previous) => [message.alert_id as number, ...previous])
          }
          handlerRef.current?.(message)
        } catch {
          // A malformed frame must not tear down a working connection.
        }
      }

      socket.onclose = () => {
        setStatus('closed')
        if (closedByUsRef.current) return
        const delay = retryDelay(attemptRef.current)
        attemptRef.current += 1
        timerRef.current = setTimeout(() => connect(authToken), delay)
      }

      // onerror is always followed by onclose, so reconnection is handled there only.
      socket.onerror = () => setStatus('closed')
    },
    [],
  )

  useEffect(() => {
    if (!token) {
      setStatus('closed')
      return
    }
    closedByUsRef.current = false
    attemptRef.current = 0
    connect(token)

    return () => {
      closedByUsRef.current = true
      if (timerRef.current) clearTimeout(timerRef.current)
      socketRef.current?.close()
      socketRef.current = null
    }
  }, [token, connect])

  return { status, received, lastMessageAt }
}
