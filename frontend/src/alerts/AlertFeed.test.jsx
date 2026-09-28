/**
 * The feed reaches past its first page. Before paging, alert 51 and older could only be
 * found by searching for them, which an analyst who does not know they exist never does.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { api } from '../api/client'
import { AlertFeed, PAGE_SIZE } from './AlertFeed'

vi.mock('../auth/AuthContext', () => ({
  useAuth: () => ({ token: 'a-token', user: { permissions: [] } }),
}))
vi.mock('../stream/StreamContext', () => ({ useStream: () => ({ status: 'open' }) }))

function alert(id) {
  return {
    alert_id: id,
    source: 'ml',
    severity: 'high',
    status: 'new',
    src_ip: '203.0.113.9',
    dst_ip: '10.0.0.5',
    mitre_technique: null,
    risk_score: 0.9,
    created_at: new Date(Date.UTC(2026, 8, 26, 10, 0, 0) - id * 1000).toISOString(),
  }
}

function renderFeed() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <AlertFeed status="" severity="" q="" onFilterChange={() => {}} />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('AlertFeed paging', () => {
  beforeEach(() => vi.restoreAllMocks())

  it('offers older alerts after a full page and loads them from the next offset', async () => {
    const all = Array.from({ length: PAGE_SIZE + 3 }, (_, index) => alert(index + 1))
    const fetchAlerts = vi
      .spyOn(api, 'alerts')
      .mockImplementation(async (_token, { offset = 0, limit }) => all.slice(offset, offset + limit))

    renderFeed()
    expect(await screen.findByText(`${PAGE_SIZE} alerts shown`)).toBeInTheDocument()

    await userEvent.setup().click(screen.getByRole('button', { name: 'Show older alerts' }))

    expect(await screen.findByText(`${PAGE_SIZE + 3} alerts shown`)).toBeInTheDocument()
    expect(fetchAlerts).toHaveBeenLastCalledWith('a-token', expect.objectContaining({ offset: PAGE_SIZE }))
    // A short page is the last one.
    expect(screen.queryByRole('button', { name: 'Show older alerts' })).not.toBeInTheDocument()
  })

  it('does not offer more when the first page is not full', async () => {
    vi.spyOn(api, 'alerts').mockResolvedValue([alert(1), alert(2)])

    renderFeed()
    expect(await screen.findByText('2 alerts shown')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Show older alerts' })).not.toBeInTheDocument()
  })

  it('shows an alert once when a new arrival shifts it onto the next page', async () => {
    const firstPage = Array.from({ length: PAGE_SIZE }, (_, index) => alert(index + 1))
    vi.spyOn(api, 'alerts').mockImplementation(async (_token, { offset = 0 }) =>
      offset === 0 ? firstPage : [alert(PAGE_SIZE), alert(PAGE_SIZE + 1)],
    )

    renderFeed()
    await screen.findByText(`${PAGE_SIZE} alerts shown`)
    await userEvent.setup().click(screen.getByRole('button', { name: 'Show older alerts' }))

    expect(await screen.findByText(`${PAGE_SIZE + 1} alerts shown`)).toBeInTheDocument()
  })
})

describe('AlertFeed time range', () => {
  beforeEach(() => vi.restoreAllMocks())

  function renderWithRange(onFilterChange = () => {}) {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    return render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <AlertFeed
            status=""
            severity=""
            q=""
            from="2026-09-20T09:00"
            to=""
            onFilterChange={onFilterChange}
          />
        </MemoryRouter>
      </QueryClientProvider>,
    )
  }

  it('asks the API for the range on screen', async () => {
    const fetchAlerts = vi.spyOn(api, 'alerts').mockResolvedValue([alert(1)])

    renderWithRange()
    await screen.findByText('1 alert shown')

    expect(fetchAlerts).toHaveBeenCalledWith(
      'a-token',
      expect.objectContaining({ from: '2026-09-20T09:00', to: undefined }),
    )
  })

  it('shows the range as a filter that can be removed on its own', async () => {
    vi.spyOn(api, 'alerts').mockResolvedValue([])
    const onFilterChange = vi.fn()

    renderWithRange(onFilterChange)
    await userEvent.setup().click(
      await screen.findByRole('button', { name: 'Remove filter from 2026-09-20 09:00' }),
    )

    expect(onFilterChange).toHaveBeenCalledWith({ status: '', severity: '', q: '', from: '', to: '' })
  })
})
