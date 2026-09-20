/**
 * Error mapping, because the dashboard reacts differently to each kind: a 401 ends the
 * session, a 403 must not be retried, a 422 carries a message worth showing, and a dead
 * SSH tunnel is not the same as a failing server.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError, api, request } from './client'

function respond(status: number, body: unknown = {}, ok = false): Response {
  return {
    ok,
    status,
    statusText: `status ${status}`,
    json: async () => body,
  } as Response
}

describe('request', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('returns the parsed body on success', async () => {
    vi.mocked(fetch).mockResolvedValue(respond(200, { alert_id: 1 }, true))
    await expect(request('/alerts/1')).resolves.toEqual({ alert_id: 1 })
  })

  it('sends the bearer token when given one', async () => {
    vi.mocked(fetch).mockResolvedValue(respond(200, [], true))
    await request('/alerts', { token: 'abc' })

    const [, init] = vi.mocked(fetch).mock.calls[0]
    expect((init?.headers as Record<string, string>).Authorization).toBe('Bearer abc')
  })

  it('sends no Authorization header without a token', async () => {
    vi.mocked(fetch).mockResolvedValue(respond(200, [], true))
    await request('/health')

    const [, init] = vi.mocked(fetch).mock.calls[0]
    expect((init?.headers as Record<string, string>).Authorization).toBeUndefined()
  })

  it.each([
    [401, 'unauthenticated'],
    [403, 'forbidden'],
    [404, 'not_found'],
    [409, 'conflict'],
    [422, 'invalid'],
    [500, 'server'],
  ])('maps %i to %s', async (status, kind) => {
    vi.mocked(fetch).mockResolvedValue(respond(status, { detail: 'nope' }))
    await expect(request('/alerts')).rejects.toMatchObject({ kind, status })
  })

  it('surfaces the API detail message verbatim', async () => {
    vi.mocked(fetch).mockResolvedValue(
      respond(422, { detail: 'a rejection requires a comment explaining it' }),
    )
    await expect(request('/actions/1/decision', { method: 'POST' })).rejects.toThrow(
      'a rejection requires a comment explaining it',
    )
  })

  it('flattens a FastAPI validation error list', async () => {
    vi.mocked(fetch).mockResolvedValue(
      respond(422, { detail: [{ msg: 'field required' }, { msg: 'too long' }] }),
    )
    await expect(request('/alerts')).rejects.toThrow('field required; too long')
  })

  it('falls back to the status text when the body is not JSON', async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: false,
      status: 502,
      statusText: 'Bad Gateway',
      json: async () => {
        throw new Error('not json')
      },
    } as unknown as Response)
    await expect(request('/alerts')).rejects.toThrow('Bad Gateway')
  })

  it('distinguishes an unreachable API from a server error', async () => {
    // What a dropped SSH tunnel looks like.
    vi.mocked(fetch).mockRejectedValue(new TypeError('Failed to fetch'))
    await expect(request('/alerts')).rejects.toMatchObject({ kind: 'network', status: 0 })
  })

  it('posts login as a form, which is what the OAuth2 endpoint expects', async () => {
    vi.mocked(fetch).mockResolvedValue(respond(200, { access_token: 't' }, true))
    await api.login('analyst', 'secret')

    const [, init] = vi.mocked(fetch).mock.calls[0]
    expect((init?.headers as Record<string, string>)['Content-Type']).toBe(
      'application/x-www-form-urlencoded',
    )
    expect(String(init?.body)).toContain('username=analyst')
  })

  it('never puts credentials in the URL', async () => {
    vi.mocked(fetch).mockResolvedValue(respond(200, { access_token: 't' }, true))
    await api.login('analyst', 'secret')

    const [url] = vi.mocked(fetch).mock.calls[0]
    expect(String(url)).not.toContain('secret')
  })
})

describe('ApiError', () => {
  it('is an Error, so it survives react-query and error boundaries', () => {
    const error = new ApiError('forbidden', 403, 'missing permission: alerts:triage')
    expect(error).toBeInstanceOf(Error)
    expect(error.message).toContain('alerts:triage')
  })
})
