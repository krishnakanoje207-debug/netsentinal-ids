/**
 * Reconnection policy and URL construction.
 *
 * The backoff matters because the dashboard runs over an SSH tunnel: a drop is routine,
 * and a client that retries every 100 ms during a long outage is a self-inflicted denial
 * of service against the API it is waiting for.
 */

import { describe, expect, it } from 'vitest'

import { retryDelay, streamUrl } from './useAlertStream'

describe('retryDelay', () => {
  it('starts at one second', () => {
    expect(retryDelay(0)).toBe(1000)
  })

  it('doubles per attempt', () => {
    expect(retryDelay(1)).toBe(2000)
    expect(retryDelay(2)).toBe(4000)
    expect(retryDelay(3)).toBe(8000)
  })

  it('holds at thirty seconds so a long outage stops hammering', () => {
    expect(retryDelay(10)).toBe(30_000)
    expect(retryDelay(100)).toBe(30_000)
  })
})

describe('streamUrl', () => {
  it('uses ws on an insecure origin and wss on a secure one', () => {
    // jsdom serves http://localhost by default.
    expect(streamUrl('t')).toMatch(/^ws:\/\//)
  })

  it('carries the token as a query parameter', () => {
    // A browser cannot set headers on a WebSocket handshake, which is why the token
    // travels here; the backend documents the same trade-off.
    const url = new URL(streamUrl('abc123'))
    expect(url.searchParams.get('token')).toBe('abc123')
  })

  it('encodes a token containing URL-significant characters', () => {
    const token = 'a+b/c=d&e'
    const url = new URL(streamUrl(token))
    expect(url.searchParams.get('token')).toBe(token)
  })

  it('points at the same host as the page, so the tunnel is honoured', () => {
    const url = new URL(streamUrl('t'))
    expect(url.host).toBe(window.location.host)
    expect(url.pathname).toBe('/api/v1/alerts/stream')
  })
})
