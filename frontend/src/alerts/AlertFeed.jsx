/**
 * The alert feed: the full departures board, newest first, which is what the API's
 * index is ordered for.
 *
 * Polling on a five-second interval as well as listening on the WebSocket. Belt and
 * braces on purpose: the socket gives immediacy, the poll guarantees the list is right
 * even if a frame was missed while the tunnel was down. The stream itself lives in the
 * shell, so its state is the header clock's.
 */

import { useInfiniteQuery } from '@tanstack/react-query'
import { useEffect, useState } from 'react'

import { api } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { Board } from '../components/Board'
import { ErrorNotice } from '../components/ErrorNotice'
import { ListBullets, MagnifyingGlass, X } from '../components/icons'
import { PageHeader } from '../components/PageHeader'
import { statusLabel } from '../components/SeverityBadge'
import { useStream } from '../stream/StreamContext'
import { ExportButton } from './ExportButton'

const POLL_MS = 5000
/** Rows per request; "Show older alerts" asks for the next page. */
export const PAGE_SIZE = 50

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
const STATUSES = [
  'new',
  'triaging',
  'escalated',
  'closed_true_positive',
  'closed_false_positive',
]

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
      className="flex"
    >
      <label className="relative flex items-center">
        <MagnifyingGlass size={16} weight="bold" className="pointer-events-none absolute left-2.5 text-ink-faint" aria-hidden="true" />
        <input
          type="search"
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          aria-label="Search by address, network or technique"
          placeholder="203.0.113.9, 10.0.0.0/8, T1046"
          className="control data w-full rounded-r-none pl-8 sm:w-72"
        />
      </label>
      <button type="submit" className="control press -ml-px rounded-l-none font-semibold">
        Search
      </button>
    </form>
  )
}

/** The filters in force, in words, each removable. */
function ActiveFilters({ status, severity, q, onFilterChange }) {
  const chips = [
    q && { key: 'q', label: `"${q}"`, clear: { status, severity, q: '' } },
    severity && { key: 'severity', label: `${severity} severity`, clear: { status, severity: '', q } },
    status && { key: 'status', label: statusLabel(status), clear: { status: '', severity, q } },
  ].filter(Boolean)
  if (chips.length === 0) return null
  return (
    <div className="mb-4 flex flex-wrap items-center gap-2 text-sm">
      <span className="text-ink-dim">Showing only</span>
      {chips.map((chip) => (
        <button
          key={chip.key}
          type="button"
          onClick={() => onFilterChange(chip.clear)}
          className="press inline-flex items-center gap-1.5 rounded-full border border-line-strong bg-panel py-0.5 pr-2 pl-3 hover:bg-sunk"
          aria-label={`Remove filter ${chip.label}`}
        >
          <span className="capitalize">{chip.label}</span>
          <X size={12} weight="bold" aria-hidden="true" />
        </button>
      ))}
      <button
        type="button"
        onClick={() => onFilterChange({ status: '', severity: '', q: '' })}
        className="text-[0.8125rem] font-semibold text-accent hover:underline"
      >
        Clear all
      </button>
    </div>
  )
}

/** @param {import('../api/types').Alert[]} rows */
function uniqueById(rows) {
  const seen = new Set()
  return rows.filter((row) => !seen.has(row.alert_id) && seen.add(row.alert_id))
}

/**
 * @param {{status: string, severity: string, q: string,
 *   onFilterChange: (next: {status: string, severity: string, q: string}) => void}} props
 */
export function AlertFeed({ status, severity, q, onFilterChange }) {
  const { token } = useAuth()
  const stream = useStream()

  // Pages by offset. A refetch reloads every page shown, and an alert that arrives
  // between pages shifts the next one down a row, so rows are de-duplicated by id.
  const { data, error, isLoading, dataUpdatedAt, fetchNextPage, hasNextPage, isFetchingNextPage } =
    useInfiniteQuery({
      queryKey: ['alerts', 'feed', status, severity, q],
      queryFn: ({ pageParam }) =>
        api.alerts(token, {
          status: status || undefined,
          severity: severity || undefined,
          q: q || undefined,
          limit: PAGE_SIZE,
          offset: pageParam,
        }),
      initialPageParam: 0,
      getNextPageParam: (lastPage, pages) =>
        lastPage.length === PAGE_SIZE ? pages.length * PAGE_SIZE : undefined,
      enabled: token !== null,
      refetchInterval: POLL_MS,
    })
  const alerts = data ? uniqueById(data.pages.flat()) : undefined

  const filtered = Boolean(status || severity || q)
  const emptyText = filtered
    ? `No alerts match ${q ? `"${q}"` : 'these filters'}. That is not the same as nothing happening.`
    : stream.status === 'open'
      ? 'No alerts yet. The live feed is connected, and alerts are posted here the moment one is raised.'
      : 'No alerts yet, and the live feed is not connected, so this board is refreshed every five seconds instead.'

  return (
    <section>
      <PageHeader
        icon={ListBullets}
        title="Alerts"
        description="Every connection the detectors flagged, newest first. Hover a row for its reasons; open one to see what can be done."
      />

      <div className="mb-4 flex flex-wrap items-start gap-2" data-tour="filters">
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
              {statusLabel(value)}
            </option>
          ))}
        </select>
        <select
          aria-label="Filter by severity"
          value={severity}
          onChange={(event) => onFilterChange({ status, severity: event.target.value, q })}
          className="control capitalize"
        >
          <option value="">All severities</option>
          {SEVERITIES.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>
        <div className="sm:ml-auto">
          <ExportButton status={status} severity={severity} q={q} />
        </div>
      </div>

      <ActiveFilters status={status} severity={severity} q={q} onFilterChange={onFilterChange} />

      {error && <ErrorNotice error={error} />}

      <Board
        title={alerts ? `${alerts.length} ${alerts.length === 1 ? 'alert' : 'alerts'} shown` : 'Alerts'}
        alerts={alerts}
        loading={isLoading}
        updatedAt={dataUpdatedAt}
        intervalMs={POLL_MS}
        emptyText={emptyText}
      />
      {hasNextPage && (
        <div className="mt-4 flex justify-center">
          <button
            type="button"
            className="control font-semibold"
            onClick={() => void fetchNextPage()}
            disabled={isFetchingNextPage}
          >
            {isFetchingNextPage ? 'Loading older alerts...' : 'Show older alerts'}
          </button>
        </div>
      )}
    </section>
  )
}
