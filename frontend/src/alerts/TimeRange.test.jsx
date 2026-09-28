/**
 * The time range beside the search box. Each end is committed as it is set, the other
 * end is kept, and either can be cleared on its own to open that side of the range.
 */

import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { TimeRange } from './AlertFeed'

function setup(from = '', to = '') {
  const onChange = vi.fn()
  const view = render(<TimeRange from={from} to={to} onChange={onChange} />)
  return { onChange, view }
}

const start = () => screen.getByLabelText('Alerts raised from')
const end = () => screen.getByLabelText('Alerts raised until')

describe('TimeRange', () => {
  it('offers a picker for each end', () => {
    setup()
    expect(start()).toHaveAttribute('type', 'datetime-local')
    expect(end()).toHaveAttribute('type', 'datetime-local')
  })

  it('commits the start and keeps the end', () => {
    const { onChange } = setup('', '2026-09-20T12:00')
    fireEvent.change(start(), { target: { value: '2026-09-20T09:00' } })

    expect(onChange).toHaveBeenCalledWith({ from: '2026-09-20T09:00', to: '2026-09-20T12:00' })
  })

  it('commits the end and keeps the start', () => {
    const { onChange } = setup('2026-09-20T09:00', '')
    fireEvent.change(end(), { target: { value: '2026-09-20T12:00' } })

    expect(onChange).toHaveBeenCalledWith({ from: '2026-09-20T09:00', to: '2026-09-20T12:00' })
  })

  it('reports a cleared end, so that side of the range opens again', () => {
    const { onChange } = setup('2026-09-20T09:00', '2026-09-20T12:00')
    fireEvent.change(end(), { target: { value: '' } })

    expect(onChange).toHaveBeenCalledWith({ from: '2026-09-20T09:00', to: '' })
  })

  it('will not offer an end before the start, or a start after the end', () => {
    setup('2026-09-20T09:00', '2026-09-20T12:00')
    expect(end()).toHaveAttribute('min', '2026-09-20T09:00')
    expect(start()).toHaveAttribute('max', '2026-09-20T12:00')
  })

  it('follows a range that was changed elsewhere', () => {
    const { view } = setup('2026-09-20T09:00', '')
    expect(start()).toHaveValue('2026-09-20T09:00')

    view.rerender(<TimeRange from="" to="" onChange={vi.fn()} />)
    expect(start()).toHaveValue('')
  })
})
