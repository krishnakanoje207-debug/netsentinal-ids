/**
 * The values a verdict was computed from are what make it checkable, and a detection
 * stored before they were kept must say so rather than render as an empty table.
 */

import { render, screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { InputFeatures, formatValue } from './InputFeatures'

describe('formatValue', () => {
  it('shows whole numbers whole and fractions to three places', () => {
    expect(formatValue(443)).toBe('443')
    expect(formatValue(12.34567)).toBe('12.346')
  })

  it('does not round a tiny value to zero', () => {
    expect(formatValue(0.00012)).toBe('1.20e-4')
  })
})

describe('InputFeatures', () => {
  it('renders every value under its contract name', () => {
    render(<InputFeatures features={{ l4_dst_port: 80, duration_ms: 12.5, splt_len_0: -60 }} />)
    const table = screen.getByTestId('input-features')
    expect(within(table).getByText('l4_dst_port').closest('tr')).toHaveTextContent('80')
    expect(within(table).getByText('duration_ms').closest('tr')).toHaveTextContent('12.5')
    expect(within(table).getByText('splt_len_0').closest('tr')).toHaveTextContent('-60')
    expect(within(table).getByText(/3 values/)).toBeInTheDocument()
  })

  it('says the values were not recorded for a legacy detection', () => {
    render(<InputFeatures features={null} />)
    expect(screen.getByTestId('features-not-recorded')).toHaveTextContent('not recorded for this alert')
    expect(screen.queryByTestId('input-features')).toBeNull()
  })
})
