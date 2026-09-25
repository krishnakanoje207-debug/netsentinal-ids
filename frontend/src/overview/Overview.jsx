/**
 * The first page anyone sees: how things stand, in sentences, with the live board beside.
 *
 * Written for the person who has never opened a SOC console - an examiner, the owner of
 * a server, a visitor to the demo - as much as for the analyst starting a shift. Every
 * number here is a count over the whole estate (GET /alerts/summary), not over the page
 * of the feed that happens to be loaded, and every number leads somewhere: clicking a
 * severity or an address opens the feed already filtered to it.
 */

import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'

import { api } from '../api/client'
import { PERMISSIONS } from '../api/types'
import { useAuth } from '../auth/AuthContext'
import { ActivityStrip, activityTotals } from '../components/ActivityStrip'
import { Board } from '../components/Board'
import { ErrorNotice } from '../components/ErrorNotice'
import { FlipNumber } from '../components/FlipNumber'
import { HoverCard } from '../components/HoverCard'
import { ArrowRight, House } from '../components/icons'
import { LineMap } from '../components/LineMap'
import { PageHeader } from '../components/PageHeader'
import { SeverityBadge } from '../components/SeverityBadge'
import { ROLES, SEVERITY_MEANING, TIERS, roleName } from '../lib/glossary'

const POLL_MS = 5000
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

/** @param {number} n @param {string} one @param {string} many */
function plural(n, one, many) {
  return `${n.toLocaleString()} ${n === 1 ? one : many}`
}

/**
 * The page's opening sentence. Plain words, and it never claims calm it cannot show:
 * with no data yet it says so rather than "all clear".
 *
 * @param {{total: number, by_severity: Record<string, number>, by_status: Record<string, number>}} summary
 * @param {number | undefined} pending
 */
export function headline(summary, pending) {
  if (summary.total === 0) {
    return 'No threats have been detected yet. The detectors are running and this page updates on its own.'
  }
  const open = (summary.by_status.new ?? 0) + (summary.by_status.triaging ?? 0)
  const critical = summary.by_severity.critical ?? 0
  const parts = [
    `${plural(summary.total, 'threat has', 'threats have')} been detected`,
    critical > 0 ? `${critical.toLocaleString()} of them critical` : null,
  ].filter(Boolean)
  let sentence = `${parts.join(', ')}. ${plural(open, 'alert is', 'alerts are')} still open.`
  if (pending !== undefined) {
    sentence +=
      pending === 0
        ? ' No blocks are waiting for a decision.'
        : ` ${plural(pending, 'block is', 'blocks are')} waiting for an analyst to approve or reject.`
  }
  return sentence
}

/**
 * The same sentence set in display type, with its counts on split-flap cells. Shown to
 * sighted readers; the plain sentence above it is what assistive technology reads.
 */
function DisplayHeadline({ summary, pending }) {
  if (summary.total === 0) {
    return (
      <p className="text-[1.625rem] leading-snug font-bold md:text-[2rem]" aria-hidden="true">
        No threats have been detected yet. The detectors are running.
      </p>
    )
  }
  const open = (summary.by_status.new ?? 0) + (summary.by_status.triaging ?? 0)
  const critical = summary.by_severity.critical ?? 0
  return (
    <p className="text-[1.625rem] leading-[1.55] font-bold md:text-[2rem]" aria-hidden="true">
      <FlipNumber value={summary.total} size="lg" /> {summary.total === 1 ? 'threat' : 'threats'} detected
      {critical > 0 && (
        <>
          , <FlipNumber value={critical} size="lg" className="flap-critical" />{' '}
          <span className="text-sev-critical">critical</span>
        </>
      )}
      . <FlipNumber value={open} size="lg" /> still open
      {pending !== undefined && pending > 0 && (
        <>
          , <FlipNumber value={pending} size="lg" /> waiting for a decision
        </>
      )}
      .
    </p>
  )
}

/** @param {{to: string, children: import('react').ReactNode, onBoard?: boolean}} props */
function MoreLink({ to, children, onBoard = false }) {
  return (
    <Link
      to={to}
      viewTransition
      className={`group inline-flex items-center gap-1 text-[0.8125rem] font-semibold ${
        onBoard ? 'text-board-ink' : 'text-accent'
      }`}
    >
      <span className="group-hover:underline">{children}</span>
      <ArrowRight size={13} weight="bold" className="transition-transform duration-200 group-hover:translate-x-0.5" aria-hidden="true" />
    </Link>
  )
}

/** @param {{onFilter: (filters: {status: string, severity: string, q: string}) => void}} props */
export function Overview({ onFilter }) {
  const { token, can, user } = useAuth()
  const navigate = useNavigate()

  const summary = useQuery({
    queryKey: ['alert-summary'],
    queryFn: () => api.alertSummary(token),
    enabled: token !== null,
    refetchInterval: POLL_MS,
  })
  const latest = useQuery({
    queryKey: ['alerts', 'board'],
    queryFn: () => api.alerts(token, { limit: 8 }),
    enabled: token !== null,
    refetchInterval: POLL_MS,
  })
  const pending = useQuery({
    queryKey: ['pending-actions'],
    queryFn: () => api.pendingActions(token),
    enabled: token !== null,
    refetchInterval: POLL_MS,
  })
  const models = useQuery({
    queryKey: ['models', '7d'],
    queryFn: () => api.models(token, '7d'),
    enabled: token !== null && can(PERMISSIONS.modelsRead),
  })
  const activity = useQuery({
    queryKey: ['activity', 60],
    queryFn: () => api.activity(token, 60),
    enabled: token !== null,
    refetchInterval: 10_000,
  })

  const data = summary.data
  const flows = activity.data?.buckets ? activityTotals(activity.data.buckets).flows : null
  const canSeeModels = can(PERMISSIONS.modelsRead)
  const lineStats = {
    flows,
    alerts: data?.total ?? null,
    deciding: canSeeModels && models.data ? models.data.filter((model) => model.mode === 'active').length : null,
    watching: canSeeModels && models.data ? models.data.filter((model) => model.mode === 'shadow').length : null,
    pending: pending.data?.length ?? null,
  }

  const filterBy = (filters) => {
    onFilter({ status: '', severity: '', q: '', ...filters })
    navigate('/alerts', { viewTransition: true })
  }

  return (
    <section>
      <PageHeader
        icon={House}
        title="Overview"
        description="How things stand right now, in plain words. Hover anything for more; click a number to see the alerts behind it."
      />

      {summary.error && <ErrorNotice error={summary.error} />}

      <div className="grid gap-6 lg:grid-cols-12">
        <div className="space-y-6 lg:col-span-5">
          <div data-tour="headline" className="rise-in">
            {summary.isLoading && <p className="text-ink-dim">Counting alerts...</p>}
            {data && (
              <>
                <p className="sr-only" data-testid="overview-headline">
                  {headline(data, pending.data?.length)}
                </p>
                <DisplayHeadline summary={data} pending={pending.data?.length} />
                {user?.role && ROLES[user.role] && (
                  <p className="mt-3 text-[0.9375rem] text-ink-dim" data-testid="overview-access">
                    You are signed in as <span className="font-semibold text-ink">{roleName(user.role)}</span>.{' '}
                    {ROLES[user.role].can}
                  </p>
                )}
              </>
            )}
          </div>

          {data && (
            <section className="panel p-2" data-tour="severity" aria-labelledby="severity-heading">
              <h2 id="severity-heading" className="px-3 pt-2 pb-1 text-sm font-bold text-ink-dim">
                Threats by severity
              </h2>
              <ul>
                {SEVERITY_ORDER.map((severity) => {
                  const count = data.by_severity[severity] ?? 0
                  const share = data.total === 0 ? 0 : count / data.total
                  return (
                    <li key={severity}>
                      <HoverCard
                        as="div"
                        width={280}
                        content={() => (
                          <div className="space-y-1.5">
                            <SeverityBadge severity={severity} />
                            <p className="font-semibold">{SEVERITY_MEANING[severity]}</p>
                            <p className="numeric text-ink-dim">
                              {count.toLocaleString()} of {data.total.toLocaleString()} alerts
                              {data.total > 0 ? ` (${Math.round(share * 100)}%)` : ''}.
                            </p>
                            <p className="text-xs text-ink-faint">Click to open exactly these alerts.</p>
                          </div>
                        )}
                      >
                        <button
                          type="button"
                          onClick={() => filterBy({ severity })}
                          className="group grid w-full grid-cols-[5.25rem_1fr_auto] items-center gap-3 rounded-md px-3 py-2.5 text-left transition-colors duration-150 hover:bg-sunk"
                          data-testid={`severity-row-${severity}`}
                        >
                          <SeverityBadge severity={severity} />
                          <span className="relative block h-2 overflow-hidden rounded-full bg-sunk group-hover:bg-panel">
                            <span
                              className="severity-bar absolute inset-0 rounded-full"
                              style={{
                                scale: `${count === 0 ? 0 : Math.max(0.02, share)} 1`,
                                background: `var(--color-fill-${severity})`,
                              }}
                            />
                          </span>
                          <span className="numeric min-w-[2.5rem] text-right text-lg font-bold">
                            {count.toLocaleString()}
                          </span>
                        </button>
                      </HoverCard>
                    </li>
                  )
                })}
              </ul>
            </section>
          )}
        </div>

        <div className="lg:col-span-7">
          <Board
            tour="board"
            title="Latest alerts"
            alerts={latest.data}
            loading={latest.isLoading}
            updatedAt={latest.dataUpdatedAt}
            intervalMs={POLL_MS}
            emptyText="No alerts yet. The detectors are running, and alerts are posted here the moment one is raised."
            action={<MoreLink to="/alerts" onBoard>All alerts</MoreLink>}
          />
          {latest.error && <ErrorNotice error={latest.error} />}
        </div>
      </div>

      <div className="mt-6">
        <ActivityStrip />
      </div>

      <div className="mt-6">
        <LineMap stats={lineStats} />
      </div>

      {data && (
        <div className="mt-6 grid items-start gap-6 lg:grid-cols-12">
          <section className="panel p-5 lg:col-span-4" aria-labelledby="pending-heading">
            <div className="mb-3 flex items-baseline justify-between gap-3">
              <h2 id="pending-heading" className="font-bold">
                Waiting for a decision
              </h2>
              <MoreLink to="/approvals">Approvals</MoreLink>
            </div>
            {pending.data && pending.data.length === 0 && (
              <p className="text-[0.9375rem] text-ink-dim">
                Nothing is waiting. Proposed blocks appear here until an analyst approves or rejects them.
              </p>
            )}
            {pending.data && pending.data.length > 0 && (
              <ul className="divide-y divide-line">
                {pending.data.slice(0, 4).map((action) => (
                  <li key={action.action_id} className="flex items-center justify-between gap-3 py-2">
                    <span>
                      Block <span className="data">{action.target}</span>
                    </span>
                    <Link
                      to={`/alerts/${action.alert_id}`}
                      viewTransition
                      className="text-[0.8125rem] font-semibold text-accent underline decoration-accent/35 hover:decoration-accent"
                    >
                      Why?
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="panel p-5 lg:col-span-4" aria-labelledby="sources-heading">
            <h2 id="sources-heading" className="mb-3 font-bold">
              Addresses raising the most alerts
            </h2>
            {data.top_sources.length === 0 ? (
              <p className="text-[0.9375rem] text-ink-dim">No source addresses yet.</p>
            ) : (
              <ol className="space-y-1">
                {data.top_sources.map((source) => (
                  <li key={source.address}>
                    <button
                      type="button"
                      onClick={() => filterBy({ q: source.address })}
                      className="group relative flex w-full items-center justify-between gap-3 overflow-hidden rounded-md px-2.5 py-2 text-left transition-colors duration-150 hover:bg-sunk"
                      title={`Open the ${source.alerts} alerts from ${source.address}`}
                    >
                      <span
                        className="absolute inset-y-1 left-0 rounded-r bg-sunk transition-colors group-hover:bg-line"
                        style={{ width: `${(source.alerts / data.top_sources[0].alerts) * 100}%` }}
                        aria-hidden="true"
                      />
                      <span className="data relative">{source.address}</span>
                      <span className="numeric relative text-sm text-ink-dim">
                        {plural(source.alerts, 'alert', 'alerts')}
                      </span>
                    </button>
                  </li>
                ))}
              </ol>
            )}
          </section>

          {models.data && models.data.length > 0 && (
            <section className="panel p-5 lg:col-span-4" aria-labelledby="models-heading">
              <div className="mb-3 flex items-baseline justify-between gap-3">
                <h2 id="models-heading" className="font-bold">
                  Detectors on duty
                </h2>
                <MoreLink to="/models">Models</MoreLink>
              </div>
              <ul className="divide-y divide-line">
                {models.data.map((model) => (
                  <li key={model.model_id} className="flex items-start justify-between gap-3 py-2">
                    <span>
                      <span className="block font-semibold">{TIERS[model.tier]?.name ?? model.name}</span>
                      <span className="data block text-ink-faint">
                        {model.name} {model.version}
                      </span>
                      <span className="block text-[0.8125rem] text-ink-dim">{TIERS[model.tier]?.does}</span>
                    </span>
                    <span
                      className={`mt-0.5 shrink-0 text-[0.8125rem] font-semibold ${
                        model.mode === 'active' ? 'text-sev-low' : 'text-ink-faint'
                      }`}
                    >
                      {model.mode === 'active' ? 'deciding' : model.mode === 'shadow' ? 'watching only' : 'retired'}
                    </span>
                  </li>
                ))}
              </ul>
            </section>
          )}
        </div>
      )}
    </section>
  )
}
