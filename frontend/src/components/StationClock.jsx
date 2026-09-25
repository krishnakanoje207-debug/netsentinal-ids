/**
 * The station clock, and the one moving thing that proves the console is alive.
 *
 * The hour and minute hands tell the time, always. The red second hand is the live feed:
 * it sweeps round the dial - once every 58.5 seconds, then a pause at twelve, as a
 * railway clock waits for the master clock's minute impulse - only while the alert
 * stream is connected. When the stream is connecting or has dropped, the hand parks at
 * twelve and stays there. A stopped feed must look stopped: an analyst watching a
 * silently dead feed reads the absence of alerts as calm.
 *
 * The hand is driven by requestAnimationFrame on a ref, not by React state, so the sweep
 * costs no re-renders. With reduced motion requested it ticks once a second instead.
 */

import { useEffect, useRef } from 'react'

const SWEEP_MS = 58_500

/** @param {Date} date @returns {{hour: number, minute: number, second: number}} degrees */
export function handAngles(date) {
  const minutes = date.getMinutes()
  const hours = date.getHours() % 12
  const intoMinute = date.getSeconds() * 1000 + date.getMilliseconds()
  return {
    hour: hours * 30 + minutes * 0.5,
    // The minute hand jumps once a minute, as the station clock's does.
    minute: minutes * 6,
    second: Math.min(360, (intoMinute / SWEEP_MS) * 360),
  }
}

const MARKS = Array.from({ length: 60 }, (_, index) => index)

/**
 * @param {{live: boolean, size?: number, className?: string}} props
 */
export function StationClock({ live, size = 40, className = '' }) {
  const hourRef = useRef(null)
  const minuteRef = useRef(null)
  const secondRef = useRef(null)

  useEffect(() => {
    const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
    let frame = 0
    let timer = 0

    const draw = () => {
      const angles = handAngles(new Date())
      hourRef.current?.setAttribute('transform', `rotate(${angles.hour} 50 50)`)
      minuteRef.current?.setAttribute('transform', `rotate(${angles.minute} 50 50)`)
      let second = live ? angles.second : 0
      if (live && reduced) second = Math.floor(new Date().getSeconds()) * 6
      secondRef.current?.setAttribute('transform', `rotate(${second} 50 50)`)
    }

    draw()
    if (!live || reduced) {
      // Still a clock when the feed is down: the time keeps moving, the red hand does not.
      timer = window.setInterval(draw, 1000)
    } else {
      const loop = () => {
        draw()
        frame = requestAnimationFrame(loop)
      }
      frame = requestAnimationFrame(loop)
    }
    return () => {
      cancelAnimationFrame(frame)
      window.clearInterval(timer)
    }
  }, [live])

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 100 100"
      className={className}
      role="img"
      aria-label={live ? 'Station clock, live feed running' : 'Station clock, live feed stopped'}
      data-testid="station-clock"
      data-live={live ? 'true' : 'false'}
    >
      <circle cx="50" cy="50" r="48" fill="var(--color-panel)" stroke="var(--color-line-strong)" strokeWidth="1.5" />
      {MARKS.map((index) => {
        const hourMark = index % 5 === 0
        return (
          <rect
            key={index}
            x={hourMark ? 48.2 : 49.3}
            y={hourMark ? 5 : 5}
            width={hourMark ? 3.6 : 1.4}
            height={hourMark ? 12 : 4}
            fill="var(--color-ink)"
            transform={`rotate(${index * 6} 50 50)`}
          />
        )
      })}
      <g ref={hourRef}>
        <polygon points="47,58 53,58 52.2,22 47.8,22" fill="var(--color-ink)" />
      </g>
      <g ref={minuteRef}>
        <polygon points="47.8,60 52.2,60 51.6,9 48.4,9" fill="var(--color-ink)" />
      </g>
      <g
        ref={secondRef}
        style={{ transition: live ? 'none' : 'transform 600ms cubic-bezier(0.16, 1, 0.3, 1)' }}
      >
        <rect x="49.3" y="30" width="1.4" height="37" fill="var(--color-signal)" />
        <circle cx="50" cy="30" r="5.6" fill="var(--color-signal)" />
      </g>
      <circle cx="50" cy="50" r="1.6" fill="var(--color-ink)" />
    </svg>
  )
}
