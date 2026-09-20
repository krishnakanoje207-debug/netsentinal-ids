import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useState } from 'react'
import { BrowserRouter, Link, Navigate, Route, Routes, useLocation } from 'react-router-dom'

import { ApiError } from './api/client'
import { ApprovalQueue } from './actions/ApprovalQueue'
import { AlertDetail } from './alerts/AlertDetail'
import { AlertFeed } from './alerts/AlertFeed'
import { AuthProvider, useAuth } from './auth/AuthContext'
import { LoginPage } from './auth/LoginPage'

export function createQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 2000,
        // Retrying a 401 or a 403 cannot succeed and only delays the real message.
        retry: (attempt, error) => {
          if (error instanceof ApiError) {
            if (error.kind === 'unauthenticated' || error.kind === 'forbidden') return false
            if (error.kind === 'not_found' || error.kind === 'invalid') return false
          }
          return attempt < 2
        },
      },
      mutations: { retry: false },
    },
  })
}

function NavLink({ to, children }) {
  const { pathname } = useLocation()
  const active = to === '/' ? pathname === '/' : pathname.startsWith(to)
  return (
    <Link
      to={to}
      className={`rounded px-2.5 py-1 text-sm ${
        active
          ? 'bg-[var(--color-panel-raised)] text-[var(--color-ink)]'
          : 'text-[var(--color-ink-dim)] hover:text-[var(--color-ink)]'
      }`}
    >
      {children}
    </Link>
  )
}

function Shell({ children }) {
  const { user, signOut } = useAuth()
  return (
    <div className="min-h-full">
      <nav className="flex items-center gap-2 border-b border-[var(--color-line)] bg-[var(--color-panel)] px-4 py-2">
        <span className="mr-3 text-sm font-semibold">NetSentinel-AI</span>
        <NavLink to="/">Alerts</NavLink>
        <NavLink to="/approvals">Approvals</NavLink>
        <div className="ml-auto flex items-center gap-3 text-xs text-[var(--color-ink-dim)]">
          <span>
            {user?.username}
            {user?.role ? ` (${user.role.replace(/_/g, ' ')})` : ''}
          </span>
          <button type="button" onClick={signOut} className="hover:text-[var(--color-ink)]">
            Sign out
          </button>
        </div>
      </nav>
      <main className="mx-auto max-w-6xl p-4">{children}</main>
    </div>
  )
}

function Authenticated() {
  const [filters, setFilters] = useState({ status: '', severity: '' })
  return (
    <Shell>
      <Routes>
        <Route
          path="/"
          element={
            <AlertFeed
              status={filters.status}
              severity={filters.severity}
              onFilterChange={setFilters}
            />
          }
        />
        <Route path="/alerts/:alertId" element={<AlertDetail />} />
        <Route path="/approvals" element={<ApprovalQueue />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Shell>
  )
}

function Gate() {
  const { token, user, loading } = useAuth()

  // A restored token is not trusted until /auth/me confirms it, so this waits rather
  // than flashing the dashboard for a session that has already expired.
  if (loading) {
    return (
      <main className="flex min-h-full items-center justify-center">
        <p className="text-sm text-[var(--color-ink-dim)]">Restoring session...</p>
      </main>
    )
  }
  if (token === null || user === null) return <LoginPage />
  return <Authenticated />
}

export function App({ queryClient = createQueryClient() }) {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <BrowserRouter>
          <Gate />
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  )
}
