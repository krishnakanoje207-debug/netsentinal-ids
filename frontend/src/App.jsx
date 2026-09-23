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
import { Brain, House, ListBullets, Scales, SignOut } from './components/icons'
import { Mark } from './components/Mark'
import { ROLES, roleName } from './lib/glossary'
import { ModelsPage } from './models/ModelsPage'
import { Overview } from './overview/Overview'

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

function NavLink({ to, icon: Icon, children }) {
  const { pathname } = useLocation()
  const active = to === '/' ? pathname === '/' : pathname.startsWith(to)
  return (
    <Link
      to={to}
      aria-current={active ? 'page' : undefined}
      title={typeof children === 'string' ? children : undefined}
      className={`relative flex h-full shrink-0 items-center px-2.5 text-sm md:px-3 transition-colors duration-150 ${
        active
          ? 'text-[var(--color-ink)] after:absolute after:inset-x-3 after:bottom-0 after:h-0.5 after:rounded-full after:bg-[var(--color-accent)]'
          : 'text-[var(--color-ink-dim)] hover:text-[var(--color-ink)]'
      }`}
    >
      <Icon size={18} className="md:mr-1.5 md:size-4" aria-hidden="true" />
      {/* Icons alone on a phone; the name stays for screen readers either way. */}
      <span className="sr-only md:not-sr-only">{children}</span>
    </Link>
  )
}

function Shell({ children }) {
  const { user, signOut, can } = useAuth()
  return (
    <div className="min-h-full">
      <nav className="sticky top-0 z-10 flex h-12 items-stretch gap-1 border-b border-[var(--color-line)] bg-[var(--color-panel)]/95 px-3 backdrop-blur-sm md:px-4">
        <span className="mr-2 flex shrink-0 items-center gap-2 text-sm font-semibold tracking-tight md:mr-4">
          <Mark className="text-[var(--color-accent)]" />
          <span className="hidden whitespace-nowrap sm:inline">NetSentinel-AI</span>
        </span>
        <NavLink to="/" icon={House}>Overview</NavLink>
        <NavLink to="/alerts" icon={ListBullets}>Alerts</NavLink>
        <NavLink to="/approvals" icon={Scales}>Approvals</NavLink>
        {can(PERMISSIONS.modelsRead) && <NavLink to="/models" icon={Brain}>Models</NavLink>}
        <div className="ml-auto flex items-center gap-3 text-xs text-[var(--color-ink-dim)]">
          <span className="hidden items-center gap-2 lg:flex">
            <span className="text-[var(--color-ink)]">{user?.username}</span>
            {user?.role && (
              <span
                className="rounded-full border border-[var(--color-line)] px-2 py-0.5 text-[11px]"
                title={ROLES[user.role]?.can}
              >
                {roleName(user.role)}
              </span>
            )}
          </span>
          <button
            type="button"
            onClick={signOut}
            className="press flex items-center gap-1.5 rounded px-2 py-1 transition-colors duration-150 hover:bg-[var(--color-panel-raised)] hover:text-[var(--color-ink)]"
          >
            <SignOut size={16} aria-hidden="true" />
            <span className="sr-only md:not-sr-only">Sign out</span>
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
        <Route path="/" element={<Overview onFilter={setFilters} />} />
        <Route
          path="/alerts"
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
