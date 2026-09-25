import { useEffect, useState } from 'react'

/**
 * The current time, re-read every `intervalMs`, so "updated 4s ago" keeps counting.
 * Stops while the tab is hidden: nobody is reading it, and a background tab that wakes
 * the CPU every second for a label is waste.
 *
 * @param {number} [intervalMs]
 */
export function useNow(intervalMs = 1000) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    let timer = null
    const start = () => {
      setNow(Date.now())
      timer = setInterval(() => setNow(Date.now()), intervalMs)
    }
    const stop = () => {
      if (timer !== null) clearInterval(timer)
      timer = null
    }
    const onVisibility = () => (document.hidden ? stop() : start())
    start()
    document.addEventListener('visibilitychange', onVisibility)
    return () => {
      stop()
      document.removeEventListener('visibilitychange', onVisibility)
    }
  }, [intervalMs])
  return now
}

/**
 * "just now", "12s ago", "4 min ago", "2 h ago".
 *
 * @param {number | null | undefined} then epoch milliseconds
 * @param {number} now
 */
export function ago(then, now) {
  if (then === null || then === undefined) return 'never'
  const seconds = Math.max(0, Math.round((now - then) / 1000))
  if (seconds < 5) return 'just now'
  if (seconds < 60) return `${seconds}s ago`
  const minutes = Math.round(seconds / 60)
  if (minutes < 60) return `${minutes} min ago`
  return `${Math.round(minutes / 60)} h ago`
}

/**
 * Whether data has missed its refresh. Three missed polls is not a blip: the page
 * should say so rather than keep presenting old numbers as current.
 *
 * @param {number} updatedAt epoch milliseconds, 0 when never loaded
 * @param {number} now
 * @param {number} pollMs
 */
export function isStale(updatedAt, now, pollMs) {
  return updatedAt > 0 && now - updatedAt > pollMs * 3
}
