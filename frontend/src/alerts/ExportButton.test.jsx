/**
 * The export control has one job beyond fetching a file: it must not let a partial
 * export pass for a complete one, and it must save the file under the name the
 * server chose, because that name is where the truncation is recorded once the file
 * is on disk.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ExportButton } from './ExportButton'
import { AuthProvider } from '../auth/AuthContext'
import { filenameFrom } from '../api/client'

const ME = {
  user_id: 1,
  username: 'analyst',
  email: 'analyst@example.test',
  is_active: true,
  role: 'soc_analyst',
  permissions: ['alerts:read'],
}

/** A CSV response with the headers the server really sends. */
function csvResponse({ truncated = false, filename = 'netsentinel-alerts-20260920-100000.csv' }) {
  const headers = new Map([
    ['content-disposition', `attachment; filename="${filename}"`],
    ['x-export-truncated', truncated ? 'true' : 'false'],
  ])
  return {
    ok: true,
    status: 200,
    statusText: 'OK',
    headers: { get: (key) => headers.get(key) ?? null },
    blob: async () => new Blob(['alert_id\r\n100\r\n'], { type: 'text/csv' }),
  }
}

function setup({ status = '', severity = '', from, to, response = csvResponse({}) } = {}) {
  const save = vi.fn()
  vi.mocked(fetch).mockImplementation(async (input) => {
    if (String(input).includes('/auth/me')) {
      return { ok: true, status: 200, statusText: 'OK', json: async () => ME }
    }
    return response
  })

  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { mutations: { retry: false } } })}>
      <AuthProvider>
        <ExportButton status={status} severity={severity} from={from} to={to} save={save} />
      </AuthProvider>
    </QueryClientProvider>,
  )
  return { save, user: userEvent.setup() }
}

describe('filenameFrom', () => {
  it('takes the name the server chose', () => {
    expect(filenameFrom('attachment; filename="netsentinel-alerts-20260920-truncated.csv"')).toBe(
      'netsentinel-alerts-20260920-truncated.csv',
    )
  })

  it('falls back to something recognisable rather than the browser default', () => {
    expect(filenameFrom(null)).toBe('netsentinel-alerts.csv')
  })
})

describe('ExportButton', () => {
  beforeEach(() => {
    sessionStorage.setItem('netsentinel.token', 'good-token')
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    sessionStorage.clear()
    vi.unstubAllGlobals()
  })

  it('saves the file under the name the server chose', async () => {
    const { user, save } = setup({})
    await user.click(await screen.findByRole('button', { name: 'Export CSV' }))

    await waitFor(() => expect(save).toHaveBeenCalled())
    expect(save.mock.calls[0][1]).toBe('netsentinel-alerts-20260920-100000.csv')
  })

  it('exports what the filters currently show', async () => {
    const { user } = setup({ status: 'new', severity: 'high' })
    await user.click(await screen.findByRole('button', { name: 'Export CSV' }))

    await waitFor(() => {
      const requested = vi.mocked(fetch).mock.calls.map((call) => String(call[0]))
      // The file has to match the screen it was taken from, or it is evidence
      // nobody can reproduce.
      expect(requested.some((url) => url.includes('status=new&severity=high'))).toBe(true)
    })
  })

  it('offers a PDF beside the CSV, of the same filtered feed', async () => {
    const { user, save } = setup({
      severity: 'high',
      from: '2026-09-20T09:00',
      to: '2026-09-20T12:00',
      response: csvResponse({ filename: 'netsentinel-alerts-20260920-100000.pdf' }),
    })
    await user.click(await screen.findByRole('button', { name: 'Export PDF' }))

    await waitFor(() => expect(save).toHaveBeenCalled())
    expect(save.mock.calls[0][1]).toBe('netsentinel-alerts-20260920-100000.pdf')
    const url = new URL(
      vi.mocked(fetch).mock.calls.map((call) => String(call[0])).find((u) => u.includes('/export')),
      'http://localhost',
    )
    expect(url.searchParams.get('format')).toBe('pdf')
    expect(url.searchParams.get('severity')).toBe('high')
    // The picker's local time leaves as the UTC instant the API compares.
    expect(url.searchParams.get('from')).toBe(new Date('2026-09-20T09:00').toISOString())
    expect(url.searchParams.get('to')).toBe(new Date('2026-09-20T12:00').toISOString())
  })

  it('asks for the CSV without naming a format, which is the default', async () => {
    const { user } = setup({})
    await user.click(await screen.findByRole('button', { name: 'Export CSV' }))

    await waitFor(() => {
      const requested = vi.mocked(fetch).mock.calls.map((call) => String(call[0]))
      expect(requested.some((u) => u.includes('/export') && !u.includes('format='))).toBe(true)
    })
  })

  it('says so when the file is partial', async () => {
    const { user } = setup({ response: csvResponse({ truncated: true }) })
    await user.click(await screen.findByRole('button', { name: 'Export CSV' }))

    expect(await screen.findByTestId('export-truncated')).toHaveTextContent(/partial/i)
  })

  it('stays quiet when the export is complete', async () => {
    const { user, save } = setup({})
    await user.click(await screen.findByRole('button', { name: 'Export CSV' }))

    await waitFor(() => expect(save).toHaveBeenCalled())
    // Warning on every small export would teach the analyst to ignore the one that
    // matters.
    expect(screen.queryByTestId('export-truncated')).not.toBeInTheDocument()
  })

  it('reports a failure instead of saving an empty file', async () => {
    const { user, save } = setup({
      response: {
        ok: false,
        status: 403,
        statusText: 'Forbidden',
        json: async () => ({ detail: 'missing permission: alerts:read' }),
      },
    })
    await user.click(await screen.findByRole('button', { name: 'Export CSV' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('missing permission')
    expect(save).not.toHaveBeenCalled()
  })
})
