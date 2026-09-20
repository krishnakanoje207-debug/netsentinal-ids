/**
 * The alert feed: newest first, which is what the API's index is ordered for.
 *
 * Polling on a five-second interval as well as listening on the WebSocket. Belt and
 * braces on purpose: the socket gives immediacy, the poll guarantees the list is right
 * even if a frame was missed while the tunnel was down.
 */

import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'

import { api } from '../api/client'
import type { Alert, AlertStatus, Severity } from '../api/types'
import { useAuth } from '../auth/AuthContext'
import { SeverityBadge, StatusPill } from '../components/SeverityBadge'
import { ErrorNotice } from '../components/ErrorNotice'
import { useAlertStream } from '../stream/useAlertStream'

const POLL_MS = 5000

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
const STATUSES: AlertStatus[] = [
  'new',
  'triaging',
  'escalated',
  'closed_true_positive',
  'closed_false_positive',
]

function StreamIndicator({ status }: { status: 'connecting' | 'open' | 'closed' }) {
  const label = status === 'open' ? 'live' : status === 'connecting' ? 'connecting' : 'disconnected'
  const colour =
    status === 'open'
      ? 'var(--color-sev-low)'
      : status === 'connecting'
        ? 'var(--color-sev-medium)'
        : 'var(--color-sev-high)'
  return (
    <span className="flex items-center gap-1.5 text-xs" data-testid="stream-status">
      <span className="inline-block h-2 w-2 rounded-full" style={{ background: colour }} />
      <span style={{ color: colour }}>{label}</span>
    </span>
  )
}

export function AlertFeed({
  status,
  severity,
  onFilterChange,
}: {
  status: string
  severity: string
  onFilterChange: (next: { status: string; severity: string }) => void
}) {
  const { token } = useAuth()
  const queryClient = useQueryClient()

  const stream = useAlertStream(token, () => {
    // A new alert arrived; let the query refetch rather than splicing it in, so the
    // list stays exactly what the server would return.
    void queryClient.invalidateQueries({ queryKey: ['alerts'] })
  })

  const { data, error, isLoading } = useQuery({
    queryKey: ['alerts', status, severity],
    queryFn: () => api.alerts(token as string, { status: status || undefined, severity: severity || undefined }),
    enabled: token !== null,
    refetchInterval: POLL_MS,
  })

  return (
    <section>
      <header className="mb-3 flex flex-wrap items-center gap-3">
        <h1 className="text-lg font-semibold">Alerts</h1>
        <StreamIndicator status={stream.status} />

        <div className="ml-auto flex gap-2">
          <select
            aria-label="Filter by status"
            value={status}
            onChange={(event) => onFilterChange({ status: event.target.value, severity })}
            className="rounded border border-[var(--color-line)] bg-[var(--color-panel)] px-2 py-1 text-xs"
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
            onChange={(event) => onFilterChange({ status, severity: event.target.value })}
            className="rounded border border-[var(--color-line)] bg-[var(--color-panel)] px-2 py-1 text-xs"
          >
            <option value="">All severities</option>
            {SEVERITIES.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </div>
      </header>

      {error && <ErrorNotice error={error} />}

      {isLoading && <p className="text-sm text-[var(--color-ink-dim)]">Loading alerts...</p>}

      {data && data.length === 0 && (
        <p className="rounded border border-[var(--color-line)] bg-[var(--color-panel)] p-4 text-sm text-[var(--color-ink-dim)]">
          No alerts match these filters. That is not the same as nothing happening - check
          the stream indicator above is live.
        </p>
      )}

      {data && data.length > 0 && (
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-[var(--color-line)] text-left text-[11px] uppercase tracking-wide text-[var(--color-ink-faint)]">
              <th className="py-2 pr-3 font-medium">Time</th>
              <th className="py-2 pr-3 font-medium">Severity</th>
              <th className="py-2 pr-3 font-medium">Source</th>
              <th className="py-2 pr-3 font-medium">From</th>
              <th className="py-2 pr-3 font-medium">To</th>
              <th className="py-2 pr-3 font-medium">Technique</th>
              <th className="py-2 pr-3 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {data.map((alert: Alert) => (
              <tr
                key={alert.alert_id}
                className="border-b border-[var(--color-line)]/50 hover:bg-[var(--color-panel)]"
              >
                <td className="py-2 pr-3">
                  <Link
                    to={`/alerts/${alert.alert_id}`}
                    className="numeric text-[var(--color-accent)] hover:underline"
                  >
                    {new Date(alert.created_at).toLocaleTimeString()}
                  </Link>
                </td>
                <td className="py-2 pr-3">
                  <SeverityBadge severity={alert.severity} />
                </td>
                <td className="py-2 pr-3 text-[var(--color-ink-dim)]">{alert.source}</td>
                <td className="numeric py-2 pr-3">{alert.src_ip ?? '--'}</td>
                <td className="numeric py-2 pr-3">{alert.dst_ip ?? '--'}</td>
                <td className="py-2 pr-3 text-[var(--color-ink-dim)]">
                  {alert.mitre_technique ?? '--'}
                </td>
                <td className="py-2 pr-3">
                  <StatusPill status={alert.status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}
