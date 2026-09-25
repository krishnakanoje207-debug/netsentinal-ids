/**
 * Text posted on split-flap cells, rolling through letters before it settles - the way
 * a departures board posts a destination. It rolls once, when it first appears, and
 * never again; with reduced motion requested it simply shows the text.
 */

import { useEffect, useState } from 'react'

const ROLL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789'

/** @param {{text: string, className?: string, stepMs?: number}} props */
export function FlapText({ text, className = '', stepMs = 45 }) {
  const letters = text.toUpperCase().split('')
  const [shown, setShown] = useState(() => {
    const reduced = typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
    return reduced ? letters : letters.map((letter) => (letter === ' ' ? ' ' : ROLL[0]))
  })

  useEffect(() => {
    const target = text.toUpperCase().split('')
    if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) {
      setShown(target)
      return undefined
    }
    let tick = 0
    const settledAt = 6 + target.length * 2
    const timer = window.setInterval(() => {
      tick += 1
      setShown(
        target.map((letter, index) => {
          if (letter === ' ') return ' '
          // Each cell settles a little after the one before it.
          if (tick >= 6 + index * 2) return letter
          return ROLL[(tick * 7 + index * 13) % ROLL.length]
        }),
      )
      if (tick >= settledAt) window.clearInterval(timer)
    }, stepMs)
    return () => window.clearInterval(timer)
  }, [text, stepMs])

  return (
    <span className={`flap flap-board ${className}`} role="img" aria-label={text}>
      {shown.map((letter, index) =>
        letter === ' ' ? (
          <span key={index} className="inline-block w-[0.35em]" aria-hidden="true" />
        ) : (
          <span key={index} className="flap-cell" aria-hidden="true">
            <span className="flap-half flap-top">
              <span>{letter}</span>
            </span>
            <span className="flap-half flap-bottom">
              <span>{letter}</span>
            </span>
          </span>
        ),
      )}
    </span>
  )
}
