/**
 * Session state: the token, who holds it, and what they may do.
 *
 * The token lives in memory plus sessionStorage, not localStorage. sessionStorage dies
 * with the tab, which suits a shared analyst workstation, and the token's own lifetime
 * is 30 minutes. Neither defends against XSS - nothing in a browser really does - so
 * the real mitigations stay where they are: a short expiry, and an API reachable only
 * through the SSH tunnel.
 *
 * Permissions come from the API, never from decoding the token here. The server owns
 * the role-to-permission table; a second copy in TypeScript would drift from it.
 */

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'

import { ApiError, api } from '../api/client'
import type { CurrentUser } from '../api/types'

const STORAGE_KEY = 'netsentinel.token'

export interface AuthState {
  token: string | null
  user: CurrentUser | null
  loading: boolean
  error: string | null
  signIn: (username: string, password: string) => Promise<void>
  signOut: () => void
  can: (permission: string) => boolean
}

const AuthContext = createContext<AuthState | null>(null)

function readStoredToken(): string | null {
  try {
    return sessionStorage.getItem(STORAGE_KEY)
  } catch {
    // Storage can throw in a private window; an in-memory session still works.
    return null
  }
}

function storeToken(token: string | null): void {
  try {
    if (token === null) sessionStorage.removeItem(STORAGE_KEY)
    else sessionStorage.setItem(STORAGE_KEY, token)
  } catch {
    // Ignore: losing persistence is survivable, failing to log in is not.
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(readStoredToken)
  const [user, setUser] = useState<CurrentUser | null>(null)
  const [loading, setLoading] = useState<boolean>(token !== null)
  const [error, setError] = useState<string | null>(null)

  const signOut = useCallback(() => {
    setToken(null)
    setUser(null)
    setError(null)
    storeToken(null)
  }, [])

  // Resolve a restored token to a user before trusting it. A token that survived a
  // refresh may have expired, or its account may have been deactivated since.
  useEffect(() => {
    if (token === null) {
      setUser(null)
      setLoading(false)
      return
    }
    let cancelled = false
    setLoading(true)
    api
      .me(token)
      .then((me) => {
        if (!cancelled) setUser(me)
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        if (cause instanceof ApiError && cause.kind === 'unauthenticated') signOut()
        else setError(cause instanceof Error ? cause.message : 'cannot verify the session')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [token, signOut])

  const signIn = useCallback(async (username: string, password: string) => {
    setError(null)
    try {
      const response = await api.login(username, password)
      storeToken(response.access_token)
      setToken(response.access_token)
    } catch (cause) {
      const message =
        cause instanceof ApiError && cause.kind === 'unauthenticated'
          ? 'Incorrect username or password.'
          : cause instanceof Error
            ? cause.message
            : 'Sign in failed.'
      setError(message)
      throw cause
    }
  }, [])

  const can = useCallback(
    (permission: string) => user?.permissions.includes(permission) ?? false,
    [user],
  )

  const value = useMemo<AuthState>(
    () => ({ token, user, loading, error, signIn, signOut, can }),
    [token, user, loading, error, signIn, signOut, can],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthState {
  const context = useContext(AuthContext)
  if (context === null) throw new Error('useAuth must be used inside an AuthProvider')
  return context
}
