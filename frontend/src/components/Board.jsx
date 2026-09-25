/**
 * The departures board: alerts posted as they arrive, one fixed row anatomy.
 *
 * Time, severity, route (from -> to), technique, status - in that order on every board,
 * so a row is read the same way wherever it appears. Every row opens its alert.
 *
 * Motion on this board is evidence, not decoration:
 * - when the board first fills, its rows turn over one after another, as a board posts;
 * - a row that arrives later turns over and glows, because it is new;
 * - the thin line under the header fills over the real refresh interval and restarts
 *   each time fresh data lands, so the board visibly keeps checking;
 * - data that has missed three refreshes fades ("stale wears thin") and says so.
 */

import { useQuery } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import { api } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { featureLabel, techniqueName, tierName } from '../lib/glossary'
import { ago, isStale, useNow } from '../lib/useNow'
import { HoverCard } from './HoverCard'
import { RiskScore } from './RiskScore'
import { SeverityBadge, StatusPill } from './SeverityBadge'

/** "14:02:11" today, "25 Sep 14:02" before today. */
export function boardTime(iso, now = Date.now()) {
  const date = new Date(iso)
  const today = new Date(now)
  const sameDay = date.toDateString() === today.toDateString()
  // 24-hour, as a departures board shows it, so a time never wraps onto two lines.
  const time = date.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
    ...(sameDay ? { second: '2-digit' } : {}),
  })
  if (sameDay) return time
  return `${date.toLocaleDateString([], { day: 'numeric', month: 'short' })} ${time}`
}

/** The alert's own detail, fetched when its row is hovered. */
export function AlertPreview({ alertId }) {
  const { token } = useAuth()
  const { data, isLoading, error } = useQuery({
    queryKey: ['alert', alertId],
    queryFn: () => api.alert(token, alertId),
    enabled: token !== null,
    staleTime: 30_000,
  })
  if (isLoading) {
    return (
      <div className="space-y-2" aria-busy="true">
        <p className="text-ink-faint">Loading the reasons...</p>
        <span className="block h-2 w-3/4 animate-pulse rounded bg-sunk" />
        <span className="block h-2 w-1/2 animate-pulse rounded bg-sunk" />
      </div>
    )
  }
  if (error || !data) return <p className="text-ink-dim">Details could not be loaded. Open the alert to retry.</p>

  const explanation = data.explanation
  const reasons = explanation
    ? Object.entries(explanation.feature_contributions)
        .sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]))
        .slice(0, 3)
    : []
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-3">
        <SeverityBadge severity={data.severity} />
        <RiskScore
          score={explanation?.risk_score ?? null}
          shadow={explanation?.shadow ?? false}
          undecidedReason={explanation === null ? 'Raised by a signature or host sensor, so no model scored it.' : undefined}
        />
      </div>
      <p className="data text-ink">
        {data.src_ip ?? '--'} <span className="text-ink-faint">to</span> {data.dst_ip ?? '--'}
      </p>
      {data.mitre_technique && (
        <p className="text-ink-dim">
          <span className="data text-ink">{data.mitre_technique}</span> {techniqueName(data.mitre_technique)}
        </p>
      )}
      {explanation ? (
        <div>
          <p className="mb-1 text-xs font-semibold text-ink-faint">What stood out</p>
          <ul className="space-y-1">
            {reasons.map(([feature, value]) => (
              <li key={feature} className="flex items-center justify-between gap-3">
                <span>{featureLabel(feature)}</span>
                <span className={`text-xs font-semibold ${value >= 0 ? 'text-sev-critical' : 'text-sev-info'}`}>
                  {value >= 0 ? 'toward attack' : 'toward normal'}
                </span>
              </li>
            ))}
          </ul>
          <p className="mt-2 border-t border-line pt-2 text-xs text-ink-faint">
            {Object.entries(explanation.model_scores)
              .map(([tier, score]) => `${tierName(tier)} ${Math.round(score * 100)}%`)
              .join(' · ')}
          </p>
        </div>
      ) : (
        <p className="text-ink-dim">Raised by a signature or host sensor: no model measurements to show.</p>
      )}
    </div>
  )
}

/** The refresh line: fills over the poll interval, restarts when data lands. */
function PollLine({ updatedAt, intervalMs, stale }) {
  if (!updatedAt || stale) return <span className="block h-[2px] bg-board-line/40" aria-hidden="true" />
  return (
    <span className="block h-[2px] overflow-hidden bg-board-line/40" aria-hidden="true">
      <span
        key={updatedAt}
        className="poll-line block h-full origin-left bg-board-dim"
        style={{ animationDuration: `${intervalMs}ms` }}
      />
    </span>
  )
}

// On a phone a row is two lines - time, severity and status, then the route - because
// five columns at that width would truncate the addresses, which are the point. Wider,
// the route column is bounded (an address pair has a known length) and the technique
// takes the rest.
const COLUMNS =
  'grid grid-cols-[auto_auto_minmax(0,1fr)] items-center gap-x-3 gap-y-1 md:grid-cols-[5.25rem_5.5rem_minmax(0,17rem)_minmax(0,1fr)_7.5rem] md:gap-y-0'

/**
 * @param {{alerts: import('../api/types').Alert[] | undefined, title: string,
 *   action?: import('react').ReactNode, updatedAt: number, intervalMs: number,
 *   loading?: boolean, emptyText: string, limit?: number, tour?: string}} props
 */
export function Board({ alerts, title, action, updatedAt, intervalMs, loading = false, emptyText, limit, tour }) {
  const now = useNow(1000)
  const stale = isStale(updatedAt, now, intervalMs)
  const rows = limit ? (alerts ?? []).slice(0, limit) : (alerts ?? [])

  // Which rows the board has already posted, and which just arrived. Tracked as state
  // updated during render (React's pattern for deriving from changed props), so a new
  // row carries its arrival class on its very first paint.
  const ids = rows.map((row) => row.alert_id).join(',')
  const [track, setTrack] = useState({ key: '', seen: new Set(), filling: false, arrivals: new Set() })
  if (ids !== '' && ids !== track.key) {
    const current = ids.split(',').map(Number)
    if (track.key === '' && track.seen.size === 0) {
      // First fill: the board posts its rows one after another, with no arrival glow.
      setTrack({ key: ids, seen: new Set(current), filling: true, arrivals: new Set() })
    } else {
      // A refetch returning the same rows is not an arrival; only unseen ids are.
      const fresh = current.filter((id) => !track.seen.has(id))
      setTrack({
        key: ids,
        seen: new Set([...track.seen, ...current]),
        filling: track.filling,
        arrivals: fresh.length > 0 ? new Set([...track.arrivals, ...fresh]) : track.arrivals,
      })
    }
  }

  // Each state lapses on its own clock, so a burst of arrivals cannot pin it on.
  useEffect(() => {
    if (!track.filling) return undefined
    const timer = window.setTimeout(() => setTrack((now) => ({ ...now, filling: false })), 1400)
    return () => window.clearTimeout(timer)
  }, [track.filling])
  useEffect(() => {
    if (track.arrivals.size === 0) return undefined
    const timer = window.setTimeout(() => setTrack((now) => ({ ...now, arrivals: new Set() })), 2600)
    return () => window.clearTimeout(timer)
  }, [track.arrivals])

  return (
    <section className="board overflow-hidden" data-tour={tour} data-testid="board" aria-labelledby={`${title}-heading`}>
      <header className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 px-4 pt-3.5 pb-3 md:px-5">
        <h2 id={`${title}-heading`} className="text-lg font-extrabold tracking-tight">
          {title}
        </h2>
        <div className="flex items-center gap-3 text-[0.8125rem]">
          <span className={`numeric ${stale ? 'font-semibold text-attention' : 'text-board-dim'}`} data-testid="board-freshness">
            {updatedAt ? (stale ? `Not updated since ${ago(updatedAt, now)}` : `Checked ${ago(updatedAt, now)}`) : 'Loading'}
          </span>
          {action}
        </div>
      </header>
      <PollLine updatedAt={updatedAt} intervalMs={intervalMs} stale={stale} />

      <div className={`${COLUMNS} hidden bg-board-deep px-4 py-2 text-[0.6875rem] font-bold tracking-[0.08em] text-board-dim uppercase md:grid md:px-5`} aria-hidden="true">
        <span>Time</span>
        <span>Severity</span>
        <span>From → to</span>
        <span className="hidden md:block">Technique</span>
        <span>Status</span>
      </div>

      {loading && rows.length === 0 && (
        <p className="px-5 py-8 text-board-dim">Loading the board...</p>
      )}
      {!loading && rows.length === 0 && <p className="px-5 py-8 text-board-dim">{emptyText}</p>}

      <ol className={stale ? 'stale' : ''}>
        {rows.map((alert, index) => {
          const arrived = track.arrivals.has(alert.alert_id)
          const motion = arrived ? 'row-arrive arrival-glow' : track.filling ? 'row-arrive' : ''
          return (
            <li key={alert.alert_id} className="border-t border-board-line/60 first:border-t-0">
              <HoverCard as="div" content={() => <AlertPreview alertId={alert.alert_id} />}>
                <Link
                  to={`/alerts/${alert.alert_id}`}
                  viewTransition
                  className={`${COLUMNS} ${motion} group px-4 py-2.5 transition-colors duration-150 hover:bg-board-deep focus-visible:bg-board-deep md:px-5`}
                  style={track.filling && !arrived ? { animationDelay: `${Math.min(index, 12) * 45}ms` } : undefined}
                  data-testid="board-row"
                >
                  <span className="data text-board-ink">{boardTime(alert.created_at, now)}</span>
                  <span>
                    <SeverityBadge severity={alert.severity} />
                  </span>
                  <span className="data order-4 col-span-3 min-w-0 truncate text-board-ink md:order-none md:col-span-1">
                    <span className="sr-only">from </span>
                    {alert.src_ip ?? '--'}
                    <span className="px-1.5 text-board-dim" aria-hidden="true">→</span>
                    <span className="sr-only"> to </span>
                    {alert.dst_ip ?? '--'}
                  </span>
                  <span
                    className="hidden min-w-0 truncate text-[0.875rem] text-board-dim md:block"
                    title={techniqueName(alert.mitre_technique) ?? undefined}
                  >
                    {alert.mitre_technique ? (
                      <>
                        <span className="data text-board-ink">{alert.mitre_technique}</span>{' '}
                        {techniqueName(alert.mitre_technique)}
                      </>
                    ) : (
                      <span aria-label="no technique named">--</span>
                    )}
                  </span>
                  <span className="order-3 justify-self-end md:order-none md:justify-self-auto">
                    <StatusPill status={alert.status} onBoard />
                  </span>
                </Link>
              </HoverCard>
            </li>
          )
        })}
      </ol>
    </section>
  )
}
