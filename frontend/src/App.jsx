import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Suspense, lazy, useState } from 'react'
import { BrowserRouter, Link, Navigate, Route, Routes, useLocation } from 'react-router-dom'

import { ApiError } from './api/client'
import { PERMISSIONS } from './api/types'
import { AuthProvider, useAuth } from './auth/AuthContext'
import { LoginPage } from './auth/LoginPage'
import { HoverCard } from './components/HoverCard'
import { Brain, HardDrives, House, ListBullets, Scales, SignOut } from './components/icons'
import { Mark } from './components/Mark'
import { StationClock } from './components/StationClock'
import { ROLES, roleName } from './lib/glossary'
import { ago, useNow } from './lib/useNow'
import { Overview } from './overview/Overview'
import { STREAM_LABEL, StreamProvider, useStream } from './stream/StreamContext'
import { ThemeProvider, ThemeToggle } from './theme/theme'
import { TourButton, TourProvider } from './tour/Tour'

// The overview is where everyone lands, so it ships in the first bundle; the other pages
// load when first opened.
const named = (loader, name) => lazy(() => loader().then((module) => ({ default: module[name] })))
const AlertFeed = named(() => import('./alerts/AlertFeed'), 'AlertFeed')
const AlertDetail = named(() => import('./alerts/AlertDetail'), 'AlertDetail')
const ApprovalQueue = named(() => import('./actions/ApprovalQueue'), 'ApprovalQueue')
const ModelsPage = named(() => import('./models/ModelsPage'), 'ModelsPage')
const EstatePage = named(() => import('./estate/EstatePage'), 'EstatePage')

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

/** A page sign: a pictogram plate and a name. The plate lights for the page you are on. */
function PageSign({ to, icon: Icon, children }) {
  const { pathname } = useLocation()
  const active = to === '/' ? pathname === '/' : pathname.startsWith(to)
  return (
    <Link
      to={to}
      viewTransition
      aria-current={active ? 'page' : undefined}
      className={`group flex shrink-0 items-center gap-2 rounded-md px-1.5 py-1 text-[0.9375rem] transition-colors duration-200 md:pr-3 ${
        active ? 'font-semibold text-ink' : 'text-ink-dim hover:text-ink'
      }`}
    >
      <span
        className={`sign-square ${active ? 'sign-square-lit' : 'group-hover:border-ink-faint group-hover:text-ink'}`}
        aria-hidden="true"
      >
        <Icon size={17} weight={active ? 'fill' : 'bold'} />
      </span>
      <span className="sr-only md:not-sr-only">{children}</span>
    </Link>
  )
}

/** The live state beside the clock, and its detail on hover. */
function LiveStatus() {
  const stream = useStream()
  const now = useNow(1000)
  const live = stream.status === 'open'
  const colour =
    stream.status === 'open' ? 'text-sev-low' : stream.status === 'connecting' ? 'text-sev-medium' : 'text-sev-critical'

  return (
    <HoverCard
      as="div"
      width={300}
      className="flex items-center gap-2.5 rounded-md py-1 pr-1 pl-1.5 outline-none focus-visible:outline-3"
      content={() => (
        <div className="space-y-2">
          <p className="font-bold">
            {live ? 'The live feed is connected' : stream.status === 'connecting' ? 'Connecting to the live feed' : 'The live feed has stopped'}
          </p>
          <p className="text-ink-dim">
            {live
              ? 'New alerts appear the moment they are raised, and the red hand keeps sweeping.'
              : 'Alerts raised now will not appear until the feed reconnects. The page keeps retrying on its own, backing off to every 30 seconds.'}
          </p>
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 border-t border-line pt-2 text-[0.8125rem]">
            <dt className="text-ink-faint">Connected</dt>
            <dd className="numeric">{stream.openedAt ? `for ${ago(stream.openedAt, now).replace(' ago', '')}` : 'no'}</dd>
            <dt className="text-ink-faint">Last alert pushed</dt>
            <dd className="numeric">{stream.lastMessageAt ? ago(stream.lastMessageAt, now) : 'none since connecting'}</dd>
          </dl>
        </div>
      )}
    >
      <span tabIndex={0} className="flex items-center gap-2.5 outline-none" data-tour="clock" data-testid="stream-status">
        <StationClock live={live} size={38} />
        <span className="hidden flex-col leading-tight sm:flex">
          <span className={`text-sm font-bold ${colour}`}>{STREAM_LABEL[stream.status]}</span>
          <span className="numeric text-xs text-ink-faint">
            {new Date(now).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' })}
          </span>
        </span>
      </span>
    </HoverCard>
  )
}

function Shell({ children }) {
  const { user, signOut, can } = useAuth()
  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-30 border-b border-line bg-panel/92 backdrop-blur-md">
        <div className="mx-auto flex h-16 max-w-[1440px] items-center gap-2 px-3 md:gap-4 md:px-6">
          <Link to="/" viewTransition className="flex shrink-0 items-center gap-2.5" aria-label="NetSentinel-AI, overview">
            <span className="sign-square sign-square-lit size-9" aria-hidden="true">
              <Mark size={22} />
            </span>
            <span className="hidden text-[1.0625rem] font-extrabold tracking-tight lg:inline">NetSentinel-AI</span>
          </Link>

          <nav aria-label="Pages" className="flex min-w-0 items-center gap-0.5 overflow-x-auto md:gap-1 lg:ml-4">
            <PageSign to="/" icon={House}>Overview</PageSign>
            <PageSign to="/alerts" icon={ListBullets}>Alerts</PageSign>
            <PageSign to="/approvals" icon={Scales}>Approvals</PageSign>
            {can(PERMISSIONS.assetsRead) && <PageSign to="/estate" icon={HardDrives}>Estate</PageSign>}
            {can(PERMISSIONS.modelsRead) && <PageSign to="/models" icon={Brain}>Models</PageSign>}
          </nav>

          <div className="ml-auto flex shrink-0 items-center gap-1.5 md:gap-2">
            <TourButton />
            <ThemeToggle />
            <LiveStatus />
            <HoverCard
              as="div"
              width={260}
              className="hidden lg:block"
              content={() => (
                <p className="text-ink-dim">{ROLES[user?.role]?.can ?? 'Signed in.'}</p>
              )}
            >
              <span tabIndex={0} className="flex flex-col items-end leading-tight outline-none">
                <span className="text-sm font-semibold">{user?.username}</span>
                <span className="text-xs text-ink-faint">{roleName(user?.role)}</span>
              </span>
            </HoverCard>
            <button
              type="button"
              onClick={signOut}
              className="press flex h-9 items-center gap-1.5 rounded-md px-2 text-sm text-ink-dim hover:bg-sunk hover:text-ink"
            >
              <SignOut size={17} weight="bold" aria-hidden="true" />
              <span className="sr-only">Sign out</span>
            </button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-[1440px] px-4 pt-7 pb-16 md:px-6">{children}</main>
    </div>
  )
}

function Authenticated() {
  const [filters, setFilters] = useState({ status: '', severity: '', q: '' })
  return (
    <StreamProvider>
      <TourProvider>
        <Shell>
          <Suspense fallback={<p className="text-ink-dim">Loading...</p>}>
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
            <Route path="/estate" element={<EstatePage onFilter={setFilters} />} />
            <Route path="/models" element={<ModelsPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
          </Suspense>
        </Shell>
      </TourProvider>
    </StreamProvider>
  )
}

function Gate() {
  const { token, user, loading } = useAuth()

  // A restored token is not trusted until /auth/me confirms it, so this waits rather
  // than flashing the dashboard for a session that has already expired.
  if (loading) {
    return (
      <main className="flex min-h-screen items-center justify-center">
        <p className="text-sm text-ink-dim">Restoring session...</p>
      </main>
    )
  }
  if (token === null || user === null) return <LoginPage />
  return <Authenticated />
}

export function App({ queryClient = createQueryClient() }) {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <AuthProvider>
          <BrowserRouter>
            <Gate />
          </BrowserRouter>
        </AuthProvider>
      </ThemeProvider>
    </QueryClientProvider>
  )
}
