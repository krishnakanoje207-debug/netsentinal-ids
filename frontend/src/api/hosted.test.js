import { afterEach, expect, it, vi } from 'vitest'

afterEach(() => {
  vi.unstubAllEnvs()
  vi.unstubAllGlobals()
  vi.resetModules()
})

it('uses the Render origin for JSON requests, exports, and the live stream', async () => {
  vi.stubEnv('VITE_API_ORIGIN', 'https://netsentinel-api.onrender.com/')
  vi.resetModules()
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({}) }))
  const { request, rawRequest } = await import('./client')
  const { streamUrl } = await import('../stream/useAlertStream')
  await request('/alerts', { token: 'test-token' })
  await rawRequest('/alerts/export', { token: 'test-token' })
  expect(fetch.mock.calls[0][0]).toBe('https://netsentinel-api.onrender.com/api/v1/alerts')
  expect(fetch.mock.calls[1][0]).toBe('https://netsentinel-api.onrender.com/api/v1/alerts/export')
  expect(streamUrl('test-token')).toBe('wss://netsentinel-api.onrender.com/api/v1/alerts/stream?token=test-token')
})
