/**
 * The tour points at real elements, skips what the viewer cannot see, and never
 * ambushes: an invitation once per browser, dismissible, and gone after the tour.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { AuthProvider } from '../auth/AuthContext'
import { PERMISSIONS } from '../api/types'
import { SEEN_KEY, TourButton, TourProvider } from './Tour'
import { TOUR_STEPS } from './steps'

function page() {
  return (
    <div>
      <span data-tour="clock">clock</span>
      <span data-tour="headline">headline</span>
      <TourButton />
    </div>
  )
}

function renderTour() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <AuthProvider>
        <MemoryRouter initialEntries={['/']}>
          <TourProvider>{page()}</TourProvider>
        </MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>,
  )
}

describe('tour', () => {
  beforeEach(() => {
    sessionStorage.setItem('netsentinel.token', 'good-token')
    localStorage.clear()
    Element.prototype.scrollIntoView = vi.fn()
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input) => {
        const url = String(input)
        const body = url.includes('/auth/me')
          ? { user_id: 1, username: 'a', email: 'a@x.test', is_active: true, role: 'soc_analyst', permissions: ['alerts:read'] }
          : []
        return { ok: true, status: 200, statusText: 'OK', json: async () => body }
      }),
    )
  })
  afterEach(() => {
    sessionStorage.clear()
    localStorage.clear()
    vi.unstubAllGlobals()
  })

  it('gates the estate and models stops on the permission that shows their page', () => {
    const gated = TOUR_STEPS.filter((step) => step.requires)
    expect(gated.map((step) => [step.id, step.requires])).toEqual([
      ['estate', PERMISSIONS.assetsRead],
      ['models', PERMISSIONS.modelsRead],
    ])
  })

  it('invites a first-time visitor once, and remembers a dismissal', async () => {
    const user = userEvent.setup()
    const { unmount } = renderTour()
    expect(await screen.findByTestId('tour-invite')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Not now' }))
    expect(screen.queryByTestId('tour-invite')).not.toBeInTheDocument()
    expect(localStorage.getItem(SEEN_KEY)).toBe('1')
    unmount()
    renderTour()
    await screen.findByRole('button', { name: /guided tour/i })
    expect(screen.queryByTestId('tour-invite')).not.toBeInTheDocument()
  })

  it('starts at the live clock and closes on Escape', async () => {
    const user = userEvent.setup()
    localStorage.setItem(SEEN_KEY, '1')
    renderTour()
    await user.click(await screen.findByRole('button', { name: /guided tour/i }))
    expect(await screen.findByRole('heading', { name: 'Is it working?' })).toBeInTheDocument()
    await user.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByTestId('tour')).not.toBeInTheDocument())
  })
})
