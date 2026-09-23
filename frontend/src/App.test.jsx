/**
 * Smoke test for the whole tree.
 *
 * The unit tests cover components in isolation, which cannot catch a provider wired in
 * the wrong order or a context consumed outside its provider. This mounts the real App.
 */

import { render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { App, createQueryClient } from './App'
import { ApiError } from './api/client'

describe('App', () => {
  beforeEach(() => {
    sessionStorage.clear()
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('shows the login form when there is no session', async () => {
    render(<App queryClient={createQueryClient()} />)
    expect(await screen.findByRole('button', { name: 'Sign in' })).toBeInTheDocument()
    expect(screen.getByLabelText(/username/i)).toBeInTheDocument()
    // Nothing should have been requested without a token.
    expect(fetch).not.toHaveBeenCalled()
  })

  it('discards a stored token the API rejects, rather than showing a broken shell', async () => {
    sessionStorage.setItem('netsentinel.token', 'expired-token')
    vi.mocked(fetch).mockResolvedValue({
      ok: false,
      status: 401,
      statusText: 'Unauthorized',
      json: async () => ({ detail: 'not authenticated' }),
    })

    render(<App queryClient={createQueryClient()} />)

    expect(await screen.findByRole('button', { name: 'Sign in' })).toBeInTheDocument()
    await waitFor(() => {
      expect(sessionStorage.getItem('netsentinel.token')).toBeNull()
    })
  })

  it('renders the shell once a stored token resolves to a user', async () => {
    sessionStorage.setItem('netsentinel.token', 'good-token')
    vi.mocked(fetch).mockImplementation(async (input) => {
      const url = String(input)
      if (url.includes('/auth/me')) {
        return {
          ok: true,
          status: 200,
          statusText: 'OK',
          json: async () => ({
            user_id: 1,
            username: 'analyst',
            email: 'a@example.test',
            is_active: true,
            role: 'soc_analyst',
            permissions: ['alerts:read', 'approvals:decide'],
          }),
        }
      }
      return {
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => [],
      }
    })

    render(<App queryClient={createQueryClient()} />)

    expect(await screen.findByText('analyst')).toBeInTheDocument()
    expect(screen.getByText('soc analyst')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Alerts' })).toBeInTheDocument()
  })
})

describe('createQueryClient', () => {
  function shouldRetry(error, attempt = 0) {
    const retry = createQueryClient().getDefaultOptions().queries?.retry
    if (typeof retry !== 'function') throw new Error('retry should be a predicate')
    return Boolean(retry(attempt, error))
  }

  it('does not retry errors that cannot succeed on a retry', () => {
    // Retrying a 403 only delays telling the analyst their role is the problem.
    expect(shouldRetry(new ApiError('forbidden', 403, 'nope'))).toBe(false)
    expect(shouldRetry(new ApiError('unauthenticated', 401, 'nope'))).toBe(false)
    expect(shouldRetry(new ApiError('not_found', 404, 'nope'))).toBe(false)
    expect(shouldRetry(new ApiError('invalid', 422, 'nope'))).toBe(false)
  })

  it('retries a transient failure', () => {
    expect(shouldRetry(new ApiError('network', 0, 'tunnel down'))).toBe(true)
    expect(shouldRetry(new ApiError('server', 500, 'boom'))).toBe(true)
  })

  it('gives up after two attempts', () => {
    expect(shouldRetry(new ApiError('server', 500, 'boom'), 2)).toBe(false)
  })
})
