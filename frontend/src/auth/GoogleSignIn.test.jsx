import { act, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { api } from '../api/client'
import { AuthProvider } from './AuthContext'
import { GoogleSignIn } from './GoogleSignIn'

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  sessionStorage.clear()
})

describe('GoogleSignIn', () => {
  it('keeps local login available without OAuth configuration and loads no Google script', async () => {
    vi.spyOn(api, 'googleConfig').mockResolvedValue({ client_id: null })
    render(<AuthProvider><GoogleSignIn /></AuthProvider>)
    expect(await screen.findByText(/not configured yet/)).toBeInTheDocument()
    expect(document.querySelector('script[src="https://accounts.google.com/gsi/client"]')).toBeNull()
  })

  it('exchanges the Google credential for a local session through the API', async () => {
    vi.spyOn(api, 'googleConfig').mockResolvedValue({ client_id: 'public-client-id' })
    vi.spyOn(api, 'googleLogin').mockResolvedValue({ access_token: 'local-session' })
    vi.spyOn(api, 'me').mockResolvedValue({ permissions: [], role: 'viewer' })
    const initialize = vi.fn()
    const renderButton = vi.fn()
    vi.stubGlobal('google', { accounts: { id: { initialize, renderButton } } })
    render(<AuthProvider><GoogleSignIn /></AuthProvider>)
    await waitFor(() => expect(renderButton).toHaveBeenCalledOnce())
    expect(initialize.mock.calls[0][0].client_id).toBe('public-client-id')
    await act(async () => initialize.mock.calls[0][0].callback({ credential: 'google-id-token' }))
    expect(api.googleLogin).toHaveBeenCalledWith('google-id-token')
    expect(sessionStorage.getItem('netsentinel.token')).toBe('local-session')
  })
})
