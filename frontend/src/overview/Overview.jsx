/**
 * The first page anyone sees: how things stand, in sentences.
 *
 * Written for the person who has never opened a SOC console - a manager, the owner of a
 * server, a visitor to the demo - as much as for the analyst starting a shift. Every
 * number here is a count over the whole estate (GET /alerts/summary), not over the page
 * of the feed that happens to be loaded, and every number leads somewhere: clicking a
 * severity or an address opens the feed already filtered to it.
 */

import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'

import { api } from '../api/client'
import { PERMISSIONS } from '../api/types'
import { useAuth } from '../auth/AuthContext'
import { ErrorNotice } from '../components/ErrorNotice'
import { ArrowRight, Brain, Broadcast, ChartBar, Scales } from '../components/icons'
import { PageHeader } from '../components/PageHeader'
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

/** @param {{children: import('react').ReactNode, title: string, action?: import('react').ReactNode}} props */
function Section({ title, action, children }) {
  return (
    <section className="rounded-lg border border-[var(--color-line)] bg-[var(--color-panel)] p-5">
      <div className="mb-4 flex items-baseline justify-between gap-3">
        <h2 className="text-sm font-semibold">{title}</h2>
        {action}
      </div>
      {children}
    </section>
  )
}

/** @param {{to: string, children: import('react').ReactNode}} props */
function MoreLink({ to, children }) {
  return (
    <Link
      to={to}
      className="inline-flex items-center gap-1 text-xs text-[var(--color-accent)] hover:underline"
    >
      {children}
      <ArrowRight size={12} aria-hidden="true" />
    </Link>
  )
}

const STEPS = [
  {
    icon: Broadcast,
    title: 'Watch',
    text: 'Every network conversation is summarised into a few numbers: how long, how fast, how much data.',
  },
  {
    icon: Brain,
    title: 'Score',
    text: 'Two AI models rate each conversation. One knows known attacks; one flags anything unusual.',
  },
  {
    icon: ChartBar,
    title: 'Explain',
    text: 'Each alert shows which measurements made it look like an attack, so a person can check the reasoning.',
  },
  {
    icon: Scales,
    title: 'Decide',
    text: 'Blocking an address always needs a person to approve it. The AI never acts alone.',
  },
]

/** @param {{onFilter: (filters: {status: string, severity: string, q: string}) => void}} props */
export function Overview({ onFilter }) {
  const { token, can, user } = useAuth()

  const summary = useQuery({
    queryKey: ['alert-summary'],
    queryFn: () => api.alertSummary(token),
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

  const data = summary.data
  const largest = data ? Math.max(1, ...Object.values(data.by_severity)) : 1

  return (
    <section>
      <PageHeader
        title="Overview"
        description="How things stand right now. Click any number to see the alerts behind it."
      />

      {summary.error && <ErrorNotice error={summary.error} />}
      {summary.isLoading && (
        <p className="text-sm text-[var(--color-ink-dim)]">Counting alerts...</p>
      )}

      {data && (
        <>
          <p
            className="mb-8 max-w-3xl text-lg leading-relaxed text-[var(--color-ink)]"
            data-testid="overview-headline"
          >
            {headline(data, pending.data?.length)}
          </p>
          {user?.role && ROLES[user.role] && (
            <p className="-mt-5 mb-8 text-sm text-[var(--color-ink-dim)]" data-testid="overview-access">
              You are signed in as <span className="text-[var(--color-ink)]">{roleName(user.role)}</span>.{' '}
              {ROLES[user.role].can}
            </p>
          )}

          <div className="grid gap-5 lg:grid-cols-[3fr_2fr]">
            <Section
              title="Threats by severity"
              action={<MoreLink to="/alerts">All alerts</MoreLink>}
            >
              <ul className="space-y-1">
                {SEVERITY_ORDER.map((severity) => {
                  const count = data.by_severity[severity] ?? 0
                  return (
                    <li key={severity}>
                      <Link
                        to="/alerts"
                        onClick={() => onFilter({ status: '', severity, q: '' })}
                        className="group grid grid-cols-[6.5rem_1fr_3.5rem] items-center gap-3 rounded-md px-2 py-2 transition-colors duration-150 hover:bg-[var(--color-panel-raised)]"
                        data-testid={`severity-row-${severity}`}
                      >
                        <span className="text-sm font-medium capitalize" style={{ color: `var(--color-sev-${severity})` }}>
                          {severity}
                        </span>
                        <span className="min-w-0">
                          <span
                            className="block h-1.5 rounded-full"
                            style={{
                              width: `${count === 0 ? 0 : Math.max(2, (count / largest) * 100)}%`,
                              background: `var(--color-sev-${severity})`,
                            }}
                          />
                          <span className="mt-1 block truncate text-xs text-[var(--color-ink-faint)]">
                            {SEVERITY_MEANING[severity]}
                          </span>
                        </span>
                        <span className="numeric text-right text-sm font-semibold">{count}</span>
                      </Link>
                    </li>
                  )
                })}
              </ul>
            </Section>

            <div className="grid content-start gap-5">
              <Section
                title="Waiting for a decision"
                action={<MoreLink to="/approvals">Open approvals</MoreLink>}
              >
                {pending.data && pending.data.length === 0 && (
                  <p className="text-sm text-[var(--color-ink-dim)]">
                    Nothing is waiting. Proposed blocks appear here until an analyst approves or
                    rejects them.
                  </p>
                )}
                {pending.data && pending.data.length > 0 && (
                  <ul className="space-y-2 text-sm">
                    {pending.data.slice(0, 4).map((action) => (
                      <li key={action.action_id} className="flex items-center justify-between gap-3">
                        <span>
                          Block <span className="data">{action.target}</span>
                        </span>
                        <Link
                          to={`/alerts/${action.alert_id}`}
                          className="text-xs text-[var(--color-ink-dim)] hover:text-[var(--color-ink)]"
                        >
                          why?
                        </Link>
                      </li>
                    ))}
                  </ul>
                )}
              </Section>

              <Section title="Addresses raising the most alerts">
                {data.top_sources.length === 0 ? (
                  <p className="text-sm text-[var(--color-ink-dim)]">No source addresses yet.</p>
                ) : (
                  <ul className="space-y-1">
                    {data.top_sources.map((source) => (
                      <li key={source.address}>
                        <Link
                          to="/alerts"
                          onClick={() => onFilter({ status: '', severity: '', q: source.address })}
                          className="flex items-center justify-between rounded-md px-2 py-1.5 transition-colors duration-150 hover:bg-[var(--color-panel-raised)]"
                        >
                          <span className="data">{source.address}</span>
                          <span className="numeric text-sm text-[var(--color-ink-dim)]">
                            {plural(source.alerts, 'alert', 'alerts')}
                          </span>
                        </Link>
                      </li>
                    ))}
                  </ul>
                )}
              </Section>
            </div>
          </div>

          {models.data && models.data.length > 0 && (
            <div className="mt-5">
              <Section title="Detection models" action={<MoreLink to="/models">Model details</MoreLink>}>
                <ul className="grid gap-4 sm:grid-cols-2">
                  {models.data.map((model) => (
                    <li key={model.model_id} className="text-sm">
                      <p className="font-medium">
                        {TIERS[model.tier]?.name ?? model.name}{' '}
                        <span className="text-xs font-normal text-[var(--color-ink-faint)]">
                          {model.mode === 'active' ? 'deciding' : model.mode === 'shadow' ? 'watching only' : 'retired'}
                        </span>
                      </p>
                      <p className="mt-0.5 text-[var(--color-ink-dim)]">{TIERS[model.tier]?.does}</p>
                    </li>
                  ))}
                </ul>
              </Section>
            </div>
          )}

          <section className="mt-10 border-t border-[var(--color-line)] pt-8">
            <h2 className="mb-5 text-sm font-semibold">How NetSentinel works</h2>
            <ol className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
              {STEPS.map(({ icon: Icon, title, text }) => (
                <li key={title}>
                  <Icon size={22} className="mb-2 text-[var(--color-accent)]" aria-hidden="true" />
                  <p className="text-sm font-medium">{title}</p>
                  <p className="mt-1 text-sm leading-relaxed text-[var(--color-ink-dim)]">{text}</p>
                </li>
              ))}
            </ol>
          </section>
        </>
      )}
    </section>
  )
}
