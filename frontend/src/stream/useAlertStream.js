/**
 * The live alert feed.
 *
 * Reconnects with exponential backoff, because the dashboard runs over an SSH tunnel
 * and a tunnel drop is routine rather than exceptional. The connection state is
 * returned so the interface can say "disconnected" plainly - an analyst watching a feed
 * that has silently stopped will read the absence of alerts as calm.
 */

import { useCallback, useEffect, useRef, useState } from 'react'

/** @typedef {'connecting' | 'open' | 'closed'} StreamStatus */

const FIRST_RETRY_MS = 1000
const MAX_RETRY_MS = 30_000

/** Backoff doubles per attempt and then holds, so a long outage stops hammering. */
export function retryDelay(attempt) {
  return Math.min(FIRST_RETRY_MS * 2 ** attempt, MAX_RETRY_MS)
}

export function streamUrl(token, base = '/api/v1') {
  const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws'
  // The token goes in the query string because a browser cannot set headers on a
  // WebSocket handshake. See the note in backend routes/stream.py.
  return `${scheme}://${window.location.host}${base}/alerts/stream?token=${encodeURIComponent(token)}`
}

/**
 * @param {string | null} token
 * @param {(message: Record<string, unknown>) => void} [onAlert]
 */
export function useAlertStream(token, onAlert) {
  const [status, setStatus] = useState('closed')
  const [received, setReceived] = useState([])
  const [lastMessageAt, setLastMessageAt] = useState(null)

  const attemptRef = useRef(0)
  const socketRef = useRef(null)
  const timerRef = useRef(null)
  const closedByUsRef = useRef(false)
  const handlerRef = useRef(onAlert)
  // Written in an effect, not during render: a ref assigned while rendering is read by
  // React's own rules as a side effect, and under StrictMode's double render it is one.
  useEffect(() => {
    handlerRef.current = onAlert
  }, [onAlert])

  // Held in a ref so onclose can reconnect without the callback capturing itself while
  // it is still being initialised.
  const connectRef = useRef(null)

  const connect = useCallback(
    (authToken) => {
      setStatus('connecting')
      const socket = new WebSocket(streamUrl(authToken))
      socketRef.current = socket

      socket.onopen = () => {
        attemptRef.current = 0
        setStatus('open')
      }

      socket.onmessage = (event) => {
        setLastMessageAt(Date.now())
        try {
          const message = JSON.parse(String(event.data))
          if (typeof message.alert_id === 'number') {
            setReceived((previous) => [message.alert_id, ...previous])
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
        timerRef.current = setTimeout(() => connectRef.current?.(authToken), delay)
      }

      // onerror is always followed by onclose, so reconnection is handled there only.
      socket.onerror = () => setStatus('closed')
    },
    [],
  )

  useEffect(() => {
    connectRef.current = connect
  }, [connect])

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
