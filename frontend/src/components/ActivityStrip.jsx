/**
 * The last hour, one column per real minute.
 *
 * Time is drawn to scale: every column is exactly one minute, a quiet minute is an empty
 * column rather than being smoothed away, and the axis is labelled with clock times. The
 * right-most column is the current minute, still filling, and is drawn as such.
 *
 * Flow counts come from the flow store and can be unavailable. Then the bars are not
 * drawn and the strip says why - a missing measurement is not a quiet network.
 *
 * Hover a column, or focus the strip and use the arrow keys, to read one minute.
 */

import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'

import { api } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { ago, isStale, useNow } from '../lib/useNow'

const POLL_MS = 10_000
const MINUTES = 60

function clock(iso) {
  return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' })
}

/** @param {import('../api/types').ActivityBucket[]} buckets */
export function activityTotals(buckets) {
  const alerts = buckets.reduce((sum, bucket) => sum + bucket.alerts, 0)
  const known = buckets.filter((bucket) => bucket.flows !== null)
  const flows = known.length === 0 ? null : known.reduce((sum, bucket) => sum + bucket.flows, 0)
  return { alerts, flows }
}

/** @param {{bucket: import('../api/types').ActivityBucket, current: boolean}} props */
function minuteSentence({ bucket, current }) {
  const flows =
    bucket.flows === null ? 'flow count unavailable' : `${bucket.flows.toLocaleString()} flows checked`
  const alerts = `${bucket.alerts} ${bucket.alerts === 1 ? 'alert' : 'alerts'}`
  return `${clock(bucket.start)}${current ? ' (this minute, still counting)' : ''}: ${flows}, ${alerts}.`
}

export function ActivityStrip() {
  const { token } = useAuth()
  const now = useNow(1000)
  const [selected, setSelected] = useState(null)

  const { data, error, dataUpdatedAt, isLoading } = useQuery({
    queryKey: ['activity', MINUTES],
    queryFn: () => api.activity(token, MINUTES),
    enabled: token !== null,
    refetchInterval: POLL_MS,
  })

  const buckets = data?.buckets ?? []
  const maxFlows = Math.max(1, ...buckets.map((bucket) => bucket.flows ?? 0))
  const maxAlerts = Math.max(1, ...buckets.map((bucket) => bucket.alerts))
  const totals = activityTotals(buckets)
  const stale = isStale(dataUpdatedAt, now, POLL_MS)
  const active = selected ?? buckets.length - 1
  const reading = buckets[active]

  return (
    <section className="panel px-4 pt-4 pb-3 md:px-5" data-tour="activity" aria-labelledby="activity-heading">
      <header className="flex flex-wrap items-baseline justify-between gap-x-6 gap-y-1">
        <h2 id="activity-heading" className="text-lg font-extrabold tracking-tight">
          The last hour, minute by minute
        </h2>
        <div className="flex flex-wrap items-center gap-x-5 gap-y-1 text-[0.8125rem] text-ink-dim">
          <span className="inline-flex items-center gap-1.5">
            <span className="inline-block h-3 w-2 rounded-[2px] bg-accent" aria-hidden="true" /> Flows checked
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="inline-block size-2.5 rounded-full bg-signal" aria-hidden="true" /> Alerts raised
          </span>
          <span className={`numeric ${stale ? 'font-semibold text-sev-medium' : 'text-ink-faint'}`}>
            {dataUpdatedAt ? (stale ? `Not updated since ${ago(dataUpdatedAt, now)}` : `Checked ${ago(dataUpdatedAt, now)}`) : ''}
          </span>
        </div>
      </header>

      {error && (
        <p className="py-6 text-sm text-ink-dim">
          Minute-by-minute activity is not available from this API: {error.message}. The alert
          counts above are unaffected.
        </p>
      )}
      {isLoading && <p className="py-6 text-sm text-ink-dim">Loading the last hour...</p>}

      {buckets.length > 0 && (
        <>
          <p className="mt-2 min-h-[1.5rem] text-[0.9375rem]" aria-live="polite" data-testid="activity-reading">
            {reading ? minuteSentence({ bucket: reading, current: active === buckets.length - 1 }) : ''}
          </p>
          <div
            tabIndex={0}
            role="img"
            aria-label={`Last ${MINUTES} minutes: ${totals.flows === null ? 'flow counts unavailable' : `${totals.flows.toLocaleString()} flows checked`}, ${totals.alerts} alerts raised. Use the arrow keys to read each minute.`}
            onKeyDown={(event) => {
              if (event.key === 'ArrowLeft') setSelected(Math.max(0, active - 1))
              else if (event.key === 'ArrowRight') setSelected(Math.min(buckets.length - 1, active + 1))
              else return
              event.preventDefault()
            }}
            onPointerLeave={() => setSelected(null)}
            className={`relative mt-1 grid h-28 items-end gap-[2px] rounded-sm outline-offset-4 ${stale ? 'stale' : ''}`}
            style={{ gridTemplateColumns: `repeat(${buckets.length}, minmax(0, 1fr))` }}
          >
            {buckets.map((bucket, index) => {
              const current = index === buckets.length - 1
              const flowHeight = bucket.flows === null ? 0 : bucket.flows === 0 ? 0 : Math.max(3, (bucket.flows / maxFlows) * 100)
              return (
                <div
                  key={bucket.start}
                  onPointerEnter={() => setSelected(index)}
                  className={`relative flex h-full flex-col justify-end rounded-t-[2px] transition-colors duration-150 ${
                    index === active ? 'bg-sunk' : ''
                  }`}
                >
                  {bucket.alerts > 0 && (
                    <span
                      className="absolute left-1/2 size-2 -translate-x-1/2 rounded-full bg-signal"
                      style={{ bottom: `calc(${Math.min(92, flowHeight + 6 + (bucket.alerts / maxAlerts) * 8)}% )` }}
                      aria-hidden="true"
                    />
                  )}
                  <span
                    className={`block rounded-t-[2px] transition-[height] duration-700 ease-[var(--ease-out-expo)] ${
                      current ? 'activity-current' : 'bg-accent'
                    } ${index === active ? 'opacity-100' : 'opacity-80'}`}
                    style={{ height: `${flowHeight}%` }}
                    aria-hidden="true"
                  />
                </div>
              )
            })}
          </div>
          <div className="mt-1.5 flex justify-between text-xs text-ink-faint" aria-hidden="true">
            {buckets
              .filter((_, index) => index % 10 === 0)
              .map((bucket, index) => (
                // Every twenty minutes on a phone, every ten wider.
                <span key={bucket.start} className={`numeric ${index % 2 === 1 ? 'hidden sm:inline' : ''}`}>
                  {clock(bucket.start)}
                </span>
              ))}
            <span className="numeric font-semibold text-ink-dim">now</span>
          </div>
          {!data.flows_available && (
            <p className="mt-2 text-[0.8125rem] text-ink-dim" data-testid="flows-unavailable">
              Flow counts are unavailable: the flow store could not be read. Alerts are still counted,
              and an empty bar here means unknown, not quiet.
            </p>
          )}
        </>
      )}
    </section>
  )
}
