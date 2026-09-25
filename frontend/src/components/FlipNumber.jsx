/**
 * A number on split-flap cells, as a departures board shows it.
 *
 * A cell flips only when its digit changes: the upper leaf falls to show the new digit's
 * top half, then the lower leaf lands. A count that did not change never moves - motion
 * here means the API sent a different number, never decoration.
 *
 * The digits are hidden from assistive technology; the whole value is the label.
 */

import { useState } from 'react'

/**
 * @param {number | null | undefined} value
 * @param {number} minDigits
 * @returns {string[]} one entry per cell, '' for a blank leading cell, '-' for no value
 */
export function cellsFor(value, minDigits) {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return Array.from({ length: Math.max(1, minDigits) }, () => '-')
  }
  const digits = String(Math.max(0, Math.round(value))).split('')
  while (digits.length < minDigits) digits.unshift('')
  return digits
}

const BLANK = ' '

/** @param {{digit: string, delay: number}} props */
function Cell({ digit, delay }) {
  // The digit this cell last settled on, and a counter that restarts the leaves when
  // the digit changes again before the previous flip has finished.
  const [state, setState] = useState({ now: digit, before: digit, flip: 0 })
  if (state.now !== digit) {
    setState({ now: digit, before: state.now, flip: state.flip + 1 })
  }
  const flipping = state.before !== state.now

  return (
    <span className="flap-cell" aria-hidden="true">
      <span className="flap-half flap-top">
        <span>{state.now || BLANK}</span>
      </span>
      <span className="flap-half flap-bottom">
        <span>{(flipping ? state.before : state.now) || BLANK}</span>
      </span>
      {flipping && (
        <span key={state.flip} className="contents">
          <span className="flap-half flap-top flap-leaf-fall" style={{ animationDelay: `${delay}ms` }}>
            <span>{state.before || BLANK}</span>
          </span>
          <span
            className="flap-half flap-bottom flap-leaf-land"
            style={{ animationDelay: `${delay + 170}ms` }}
            onAnimationEnd={() => setState((current) => ({ ...current, before: current.now }))}
          >
            <span>{state.now || BLANK}</span>
          </span>
        </span>
      )}
    </span>
  )
}

/**
 * @param {{value: number | null | undefined, minDigits?: number, label?: string,
 *   tone?: 'ink' | 'board', size?: 'md' | 'lg' | 'xl', className?: string}} props
 */
export function FlipNumber({ value, minDigits = 1, label, tone = 'ink', size = 'md', className = '' }) {
  const cells = cellsFor(value, minDigits)
  const text = value === null || value === undefined ? 'no value' : String(value)
  return (
    <span
      className={`flap flap-${tone} flap-${size} ${className}`}
      role="img"
      aria-label={label ? `${label}: ${text}` : text}
      data-testid="flip-number"
      data-value={value ?? ''}
    >
      {cells.map((digit, index) => (
        // Keyed from the right, so the units cell stays the units cell as the number grows.
        <Cell key={cells.length - index} digit={digit} delay={(cells.length - 1 - index) * 45} />
      ))}
    </span>
  )
}
