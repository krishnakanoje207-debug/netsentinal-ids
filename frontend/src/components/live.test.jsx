/**
 * The pieces that make the console look alive, and the rule they share: motion and
 * freshness must report real state. A clock whose hand sweeps while the feed is down, a
 * count that flips when nothing changed, or a missing measurement drawn as zero would
 * each tell the viewer something untrue.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { pulls } from '../alerts/ShapChart'
import { AuthProvider } from '../auth/AuthContext'
import { ago, isStale } from '../lib/useNow'
import { ActivityStrip, activityTotals } from './ActivityStrip'
import { Board, boardTime } from './Board'
import { FlipNumber, cellsFor } from './FlipNumber'
import { HoverCard } from './HoverCard'
import { StationClock, handAngles } from './StationClock'

describe('StationClock', () => {
  it('tells the time with the hour and minute hands', () => {
    const angles = handAngles(new Date(2026, 8, 25, 3, 30, 0, 0))
    expect(angles.hour).toBe(105)
    expect(angles.minute).toBe(180)
  })

  it('sweeps the second hand round in 58.5 seconds, then waits at twelve', () => {
    expect(handAngles(new Date(2026, 8, 25, 3, 30, 29, 250)).second).toBeCloseTo(180)
    expect(handAngles(new Date(2026, 8, 25, 3, 30, 59, 0)).second).toBe(360)
  })

  it('parks the red hand at twelve when the feed is not live', () => {
    const { container } = render(<StationClock live={false} />)
    expect(screen.getByTestId('station-clock')).toHaveAttribute('data-live', 'false')
    expect(screen.getByRole('img')).toHaveAccessibleName(/feed stopped/)
    const hands = container.querySelectorAll('g')
    expect(hands[2].getAttribute('transform')).toBe('rotate(0 50 50)')
  })
})

describe('FlipNumber', () => {
  it('pads to the minimum width with blank cells', () => {
    expect(cellsFor(7, 3)).toEqual(['', '', '7'])
    expect(cellsFor(1234, 2)).toEqual(['1', '2', '3', '4'])
  })

  it('shows dashes, not a zero, when there is no value', () => {
    expect(cellsFor(null, 2)).toEqual(['-', '-'])
    expect(cellsFor(undefined, 1)).toEqual(['-'])
  })

  it('is read as one number', () => {
    render(<FlipNumber value={42} label="Threats" />)
    expect(screen.getByRole('img')).toHaveAccessibleName('Threats: 42')
  })

  it('flips only the cells whose digit changed', () => {
    const { container, rerender } = render(<FlipNumber value={41} />)
    expect(container.querySelectorAll('.flap-leaf-fall')).toHaveLength(0)
    rerender(<FlipNumber value={42} />)
    // The tens digit is still 4, so exactly one cell turns over.
    expect(container.querySelectorAll('.flap-leaf-fall')).toHaveLength(1)
  })

  it('does not move when the same value arrives again', () => {
    const { container, rerender } = render(<FlipNumber value={42} />)
    rerender(<FlipNumber value={42} />)
    expect(container.querySelectorAll('.flap-leaf-fall')).toHaveLength(0)
  })
})

describe('freshness', () => {
  it('says how long ago in words', () => {
    expect(ago(1000, 3000)).toBe('just now')
    expect(ago(0, 12_000)).toBe('12s ago')
    expect(ago(0, 240_000)).toBe('4 min ago')
    expect(ago(null, 5)).toBe('never')
  })

  it('calls data stale after three missed refreshes, not after one', () => {
    expect(isStale(10_000, 10_000 + 5_000 * 2, 5_000)).toBe(false)
    expect(isStale(10_000, 10_000 + 5_000 * 3 + 1, 5_000)).toBe(true)
    // Never loaded is "loading", not stale.
    expect(isStale(0, 99_999, 5_000)).toBe(false)
  })
})

describe('activity', () => {
  const bucket = (flows, alerts = 0) => ({ start: '2026-09-25T14:00:00Z', flows, alerts })

  it('adds up what it knows', () => {
    expect(activityTotals([bucket(10, 1), bucket(0, 2), bucket(5)])).toEqual({ alerts: 3, flows: 15 })
  })

  it('reports unknown flows as unknown, never as zero', () => {
    expect(activityTotals([bucket(null, 1), bucket(null)])).toEqual({ alerts: 1, flows: null })
  })
})

describe('ShapChart pulls', () => {
  it('sums each side of the tug of war', () => {
    expect(pulls({ a: 2, b: 0.5, c: -1.5 })).toEqual({ toward: 2.5, against: 1.5 })
  })
})

describe('boardTime', () => {
  it('uses the 24-hour clock, as a departures board does', () => {
    const now = new Date(2026, 8, 25, 21, 0, 0).getTime()
    expect(boardTime(new Date(2026, 8, 25, 20, 5, 9).toISOString(), now)).toMatch(/^20:05:09$/)
  })
})

describe('HoverCard', () => {
  it('opens on keyboard focus, not only on hover, and closes on Escape', async () => {
    vi.useFakeTimers()
    render(
      <HoverCard content={() => <p>the detail</p>}>
        <button type="button">anchor</button>
      </HoverCard>,
    )
    fireEvent.focus(screen.getByRole('button', { name: 'anchor' }))
    await act(async () => {
      vi.advanceTimersByTime(300)
    })
    expect(screen.getByRole('tooltip')).toHaveTextContent('the detail')
    fireEvent.keyDown(window, { key: 'Escape' })
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
    vi.useRealTimers()
  })
})

function withProviders(ui) {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <AuthProvider>
        <MemoryRouter>{ui}</MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>,
  )
}

describe('Board', () => {
  const ALERT = {
    alert_id: 9,
    source: 'early_flow',
    severity: 'critical',
    status: 'new',
    src_ip: '175.45.176.0',
    dst_ip: '149.171.126.12',
    mitre_technique: 'T1046',
    created_at: new Date().toISOString(),
    detection_id: 9,
  }

  it('posts each alert as a row that opens it', () => {
    withProviders(<Board title="Latest" alerts={[ALERT]} updatedAt={Date.now()} intervalMs={5000} emptyText="none" />)
    const row = screen.getByTestId('board-row')
    expect(row).toHaveAttribute('href', '/alerts/9')
    expect(row).toHaveTextContent('175.45.176.0')
    expect(row).toHaveTextContent('Network Service Discovery')
  })

  it('says when its data has stopped refreshing', () => {
    const longAgo = Date.now() - 60_000
    withProviders(<Board title="Latest" alerts={[ALERT]} updatedAt={longAgo} intervalMs={5000} emptyText="none" />)
    expect(screen.getByTestId('board-freshness')).toHaveTextContent(/Not updated since/)
  })

  it('shows its empty sentence rather than an empty board', () => {
    withProviders(<Board title="Latest" alerts={[]} updatedAt={Date.now()} intervalMs={5000} emptyText="No alerts yet." />)
    expect(screen.getByText('No alerts yet.')).toBeInTheDocument()
  })
})

describe('ActivityStrip', () => {
  beforeEach(() => {
    sessionStorage.setItem('netsentinel.token', 'good-token')
  })
  afterEach(() => {
    sessionStorage.clear()
    vi.unstubAllGlobals()
  })

  it('explains missing flow counts instead of drawing a quiet network', async () => {
    const buckets = Array.from({ length: 60 }, (_, index) => ({
      start: new Date(Date.UTC(2026, 8, 25, 14, index)).toISOString(),
      alerts: index === 59 ? 2 : 0,
      flows: null,
    }))
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input) => {
        const url = String(input)
        const body = url.includes('/auth/me')
          ? { user_id: 1, username: 'a', email: 'a@x.test', is_active: true, role: 'viewer', permissions: ['alerts:read'] }
          : { minutes: 60, until: buckets[59].start, buckets, flows_available: false }
        return { ok: true, status: 200, statusText: 'OK', json: async () => body }
      }),
    )
    withProviders(<ActivityStrip />)
    expect(await screen.findByTestId('flows-unavailable')).toHaveTextContent(/unknown, not quiet/)
    expect(screen.getByTestId('activity-reading')).toHaveTextContent('flow count unavailable, 2 alerts')
  })
})
