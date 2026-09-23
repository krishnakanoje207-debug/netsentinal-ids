import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useState } from 'react'
import { BrowserRouter, Link, Navigate, Route, Routes, useLocation } from 'react-router-dom'

import { ApiError } from './api/client'
import { PERMISSIONS } from './api/types'
import { ApprovalQueue } from './actions/ApprovalQueue'
import { AlertDetail } from './alerts/AlertDetail'
import { AlertFeed } from './alerts/AlertFeed'
import { AuthProvider, useAuth } from './auth/AuthContext'
import { LoginPage } from './auth/LoginPage'
import { Mark } from './components/Mark'
import { ModelsPage } from './models/ModelsPage'

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
      aria-current={active ? 'page' : undefined}
      className={`relative flex h-full items-center px-3 text-sm transition-colors duration-150 ${
        active
          ? 'text-[var(--color-ink)] after:absolute after:inset-x-3 after:bottom-0 after:h-0.5 after:rounded-full after:bg-[var(--color-accent)]'
          : 'text-[var(--color-ink-dim)] hover:text-[var(--color-ink)]'
      }`}
    >
      {children}
    </Link>
  )
}

function Shell({ children }) {
  const { user, signOut, can } = useAuth()
  return (
    <div className="min-h-full">
      <nav className="sticky top-0 z-10 flex h-12 items-stretch gap-1 border-b border-[var(--color-line)] bg-[var(--color-panel)]/95 px-4 backdrop-blur-sm">
        <span className="mr-4 flex items-center gap-2 text-sm font-semibold tracking-tight">
          <Mark className="text-[var(--color-accent)]" />
          NetSentinel-AI
        </span>
        <NavLink to="/">Alerts</NavLink>
        <NavLink to="/approvals">Approvals</NavLink>
        {can(PERMISSIONS.modelsRead) && <NavLink to="/models">Models</NavLink>}
        <div className="ml-auto flex items-center gap-3 text-xs text-[var(--color-ink-dim)]">
          <span className="flex items-center gap-2">
            <span className="text-[var(--color-ink)]">{user?.username}</span>
            {user?.role && (
              <span className="rounded-full border border-[var(--color-line)] px-2 py-0.5 text-[11px]">
                {user.role.replace(/_/g, ' ')}
              </span>
            )}
          </span>
          <button
            type="button"
            onClick={signOut}
            className="rounded px-2 py-1 transition-colors duration-150 hover:bg-[var(--color-panel-raised)] hover:text-[var(--color-ink)]"
          >
            Sign out
          </button>
        </div>
      </nav>
      <main className="mx-auto max-w-6xl px-4 pt-6 pb-10">{children}</main>
    </div>
  )
}

function Authenticated() {
  const [filters, setFilters] = useState({ status: '', severity: '', q: '' })
  return (
    <Shell>
      <Routes>
        <Route
          path="/"
          element={
            <AlertFeed
              status={filters.status}
              severity={filters.severity}
              q={filters.q}
              onFilterChange={setFilters}
            />
          }
        />
        <Route path="/alerts/:alertId" element={<AlertDetail />} />
        <Route path="/approvals" element={<ApprovalQueue />} />
        <Route path="/models" element={<ModelsPage />} />
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
