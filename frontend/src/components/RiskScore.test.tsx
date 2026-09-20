/**
 * The rule this component exists for: undecided is not benign.
 *
 * The fusion scorer returns no score when only shadow models voted, and the API sends no
 * explanation for signature or host alerts. Rendering either as 0% would put a green,
 * reassuring number in front of an analyst for a flow nothing actually cleared.
 */

import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { RiskScore, formatRisk, toneFor } from './RiskScore'

describe('toneFor', () => {
  it('treats a missing score as undecided, never as low', () => {
    expect(toneFor(null)).toBe('undecided')
    expect(toneFor(undefined)).toBe('undecided')
    expect(toneFor(Number.NaN)).toBe('undecided')
  })

  it('does not confuse a genuine zero with a missing score', () => {
    // A model that ran and returned 0.0 really did say "benign", which is different.
    expect(toneFor(0)).toBe('low')
  })

  it('escalates tone with the score', () => {
    expect(toneFor(0.1)).toBe('low')
    expect(toneFor(0.5)).toBe('medium')
    expect(toneFor(0.75)).toBe('high')
    expect(toneFor(0.95)).toBe('critical')
  })
})

describe('formatRisk', () => {
  it('renders a dash rather than a number when there is no score', () => {
    expect(formatRisk(null)).toBe('--')
    expect(formatRisk(undefined)).toBe('--')
  })

  it('renders a percentage for a real score', () => {
    expect(formatRisk(0)).toBe('0%')
    expect(formatRisk(0.934)).toBe('93%')
    expect(formatRisk(1)).toBe('100%')
  })
})

describe('RiskScore', () => {
  it('labels an undecided verdict explicitly', () => {
    render(<RiskScore score={null} />)
    expect(screen.getByTestId('risk-value')).toHaveTextContent('--')
    expect(screen.getByTestId('risk-value')).toHaveAttribute('data-tone', 'undecided')
    expect(screen.getByText('undecided')).toBeInTheDocument()
  })

  it('explains why there is no score', () => {
    render(<RiskScore score={null} undecidedReason="No active model scored this flow." />)
    expect(screen.getByTitle('No active model scored this flow.')).toBeInTheDocument()
  })

  it('marks a shadow verdict so it is not mistaken for an acted-on one', () => {
    render(<RiskScore score={0.91} shadow />)
    expect(screen.getByTestId('shadow-badge')).toHaveTextContent('shadow')
    expect(screen.getByTestId('risk-value')).toHaveTextContent('91%')
  })

  it('shows no shadow badge for an active verdict', () => {
    render(<RiskScore score={0.91} />)
    expect(screen.queryByTestId('shadow-badge')).not.toBeInTheDocument()
  })

  it('never shows a shadow badge instead of the undecided label', () => {
    // An undecided verdict is shadow by definition; saying both would be noise.
    render(<RiskScore score={null} shadow />)
    expect(screen.getByText('undecided')).toBeInTheDocument()
    expect(screen.queryByTestId('shadow-badge')).not.toBeInTheDocument()
  })
})
