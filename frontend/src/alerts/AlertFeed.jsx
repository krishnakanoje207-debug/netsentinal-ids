/**
 * The alert feed: newest first, which is what the API's index is ordered for.
 *
 * Polling on a five-second interval as well as listening on the WebSocket. Belt and
 * braces on purpose: the socket gives immediacy, the poll guarantees the list is right
 * even if a frame was missed while the tunnel was down.
 */

import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import { api } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { SeverityBadge, StatusPill } from '../components/SeverityBadge'
import { ErrorNotice } from '../components/ErrorNotice'
import { ExportButton } from './ExportButton'
import { useAlertStream } from '../stream/useAlertStream'

const POLL_MS = 5000

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
const STATUSES = [
  'new',
  'triaging',
  'escalated',
  'closed_true_positive',
  'closed_false_positive',
]

/** @param {{status: import('../stream/useAlertStream').StreamStatus}} props */
function StreamIndicator({ status }) {
  const label = status === 'open' ? 'live' : status === 'connecting' ? 'connecting' : 'disconnected'
  const colour =
    status === 'open'
      ? 'var(--color-sev-low)'
      : status === 'connecting'
        ? 'var(--color-sev-medium)'
        : 'var(--color-sev-high)'
  return (
    <span className="flex items-center gap-1.5 text-xs" data-testid="stream-status">
      <span
        className={`inline-block h-2 w-2 rounded-full ${status === 'open' ? 'live-dot' : ''}`}
        style={{ background: colour }}
      />
      <span style={{ color: colour }}>{label}</span>
    </span>
  )
}

/**
 * The search box.
 *
 * Submitted rather than searched on every keystroke, because half a typed address
 * is not an address: searching as the analyst types "203.0.113.9" would refuse
 * "203", "203.0" and "203.0.11" on the way, and a box that flashes errors while you
 * use it is a box people stop reading.
 *
 * @param {{value: string, onSearch: (next: string) => void}} props
 */
export function SearchBox({ value, onSearch }) {
  const [draft, setDraft] = useState(value)

  // The committed value can change without this box being touched - a cleared
  // filter, or a restored session - and the field has to follow it.
  useEffect(() => setDraft(value), [value])

  return (
    <form
      role="search"
      onSubmit={(event) => {
        event.preventDefault()
        onSearch(draft.trim())
      }}
      className="flex gap-1"
    >
      <input
        type="search"
        value={draft}
        onChange={(event) => setDraft(event.target.value)}
        aria-label="Search by address, network or technique"
        placeholder="203.0.113.9, 10.0.0.0/8, T1046"
        className="control data w-72"
      />
      <button type="submit" className="control">
        Search
      </button>
    </form>
  )
}

/**
 * @param {{status: string, severity: string, q: string,
 *   onFilterChange: (next: {status: string, severity: string, q: string}) => void}} props
 */
export function AlertFeed({ status, severity, q, onFilterChange }) {
  const { token } = useAuth()
  const queryClient = useQueryClient()

  const stream = useAlertStream(token, () => {
    // A new alert arrived; let the query refetch rather than splicing it in, so the
    // list stays exactly what the server would return.
    void queryClient.invalidateQueries({ queryKey: ['alerts'] })
  })

  const { data, error, isLoading } = useQuery({
    queryKey: ['alerts', status, severity, q],
    queryFn: () =>
      api.alerts(token, {
        status: status || undefined,
        severity: severity || undefined,
        q: q || undefined,
      }),
    enabled: token !== null,
    refetchInterval: POLL_MS,
  })

  return (
    <section>
      <header className="mb-5 flex flex-wrap items-end gap-x-4 gap-y-3">
        <div className="max-w-xl">
          <div className="flex items-baseline gap-3">
            <h1 className="text-xl font-semibold tracking-tight">Alerts</h1>
            {data && (
              <span className="numeric text-sm text-[var(--color-ink-dim)]">{data.length} shown</span>
            )}
            <StreamIndicator status={stream.status} />
          </div>
          <p className="mt-1 text-sm text-[var(--color-ink-dim)]">
            Every connection the models flagged, newest first. Open one to see why it was
            flagged and what can be done about it.
          </p>
        </div>

        <div className="ml-auto flex flex-wrap items-start gap-2">
          <SearchBox value={q} onSearch={(next) => onFilterChange({ status, severity, q: next })} />
          <select
            aria-label="Filter by status"
            value={status}
            onChange={(event) => onFilterChange({ status: event.target.value, severity, q })}
            className="control"
          >
            <option value="">All statuses</option>
            {STATUSES.map((value) => (
              <option key={value} value={value}>
                {value.replace(/_/g, ' ')}
              </option>
            ))}
          </select>
          <select
            aria-label="Filter by severity"
            value={severity}
            onChange={(event) => onFilterChange({ status, severity: event.target.value, q })}
            className="control"
          >
            <option value="">All severities</option>
            {SEVERITIES.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
          <ExportButton status={status} severity={severity} q={q} />
        </div>
      </header>

      {error && <ErrorNotice error={error} />}

      {isLoading && <p className="text-sm text-[var(--color-ink-dim)]">Loading alerts...</p>}

      {data && data.length === 0 && (
        <p className="rounded border border-[var(--color-line)] bg-[var(--color-panel)] p-4 text-sm text-[var(--color-ink-dim)]">
          No alerts match {q ? `"${q}"` : 'these filters'}. That is not the same as nothing
          happening - check the stream indicator above is live.
        </p>
      )}

      {data && data.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-[var(--color-line)] bg-[var(--color-panel)]/40">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-[var(--color-line)] bg-[var(--color-panel)] text-left text-[11px] uppercase tracking-wider text-[var(--color-ink-faint)] [&>th]:px-3 [&>th]:py-2.5">
              <th className="font-medium" title="When the alert was raised. Click it to open the alert">Time</th>
              <th className="font-medium" title="How urgent it is, from critical down to info">Severity</th>
              <th className="font-medium" title="Which sensor or model raised it">Source</th>
              <th className="font-medium" title="The address the traffic came from">From</th>
              <th className="font-medium" title="The address it was aimed at">To</th>
              <th className="font-medium" title="The MITRE ATT&CK technique, when one was identified">Technique</th>
              <th className="font-medium" title="Where the alert is in its review">Status</th>
            </tr>
          </thead>
          <tbody>
            {data.map((alert) => (
              <tr
                key={alert.alert_id}
                className={`border-b border-[var(--color-line)]/50 transition-colors duration-100 last:border-b-0 hover:bg-[var(--color-panel-raised)] [&>td]:px-3 [&>td]:py-2 ${
                  alert.severity === 'critical' ? 'bg-[var(--color-sev-critical)]/[0.035]' : ''
                }`}
              >
                <td>
                  <Link
                    to={`/alerts/${alert.alert_id}`}
                    className="data text-[var(--color-accent)] hover:underline"
                  >
                    {new Date(alert.created_at).toLocaleTimeString()}
                  </Link>
                </td>
                <td>
                  <SeverityBadge severity={alert.severity} />
                </td>
                <td className="text-[var(--color-ink-dim)]">{alert.source}</td>
                <td className="data">{alert.src_ip ?? '--'}</td>
                <td className="data">{alert.dst_ip ?? '--'}</td>
                <td className="data text-[var(--color-ink-dim)]">
                  {alert.mitre_technique ?? '--'}
                </td>
                <td>
                  <StatusPill status={alert.status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      )}
    </section>
  )
}
