/**
 * The registry: which model is deciding, which is still watching, and what the
 * watching one has earned.
 *
 * Decisions that shaped this screen:
 *
 * - The evidence is the page, not a detail view behind it. Promotion is the one
 *   decision in this system gated on measurement rather than on somebody being
 *   confident, so the numbers sit next to the button that acts on them.
 * - `unlabelled` is a column, not a footnote. A tier that fires constantly on flows
 *   nobody ever opens reads as perfect precision and is not, and precision shown
 *   alone would let this page make that argument.
 * - A metric that could not be computed renders as a dash, never as 0. "No evidence"
 *   and "came out at zero" are different findings and the page must not merge them.
 * - A model that cannot be promoted says why in a sentence the API wrote. A disabled
 *   button with no reason sends an ML engineer to the logs to find out whether to
 *   keep triaging or to try a different candidate.
 * - Without models:deploy the promote control is not rendered. Showing a button that
 *   can only ever return 403 teaches people to ignore errors.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'

import { api } from '../api/client'
import { PERMISSIONS } from '../api/types'
import { useAuth } from '../auth/AuthContext'
import { ErrorNotice } from '../components/ErrorNotice'

const WINDOWS = ['24h', '7d', '14d', '30d']

const MODE_CLASS = {
  active: 'border-[var(--color-sev-low)] text-[var(--color-sev-low)]',
  shadow: 'border-[var(--color-sev-info)] text-[var(--color-sev-info)]',
  retired: 'border-[var(--color-line)] text-[var(--color-ink-faint)]',
}

const MODE_TITLE = {
  active: 'Decides. Its verdicts raise alerts.',
  shadow: 'Scores live traffic and pages nobody.',
  retired: 'Replaced by a promotion. Kept for its history.',
}

/** @param {{mode: import('../api/types').ModelMode}} props */
export function ModeBadge({ mode }) {
  return (
    <span
      title={MODE_TITLE[mode]}
      className={`inline-block rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${MODE_CLASS[mode]}`}
      data-testid="mode-badge"
    >
      {mode}
    </span>
  )
}

/**
 * A dash rather than a zero when there is nothing behind the number.
 *
 * @param {number | null | undefined} value
 * @param {number} [digits]
 */
export function metric(value, digits = 3) {
  return value === null || value === undefined ? '--' : value.toFixed(digits)
}

/**
 * A decision threshold, never rounded to zero. A confident, calibrated model can sit
 * at 0.0047, and "0.00" reads as a model that flags everything.
 */
export function threshold(value) {
  if (value === null || value === undefined) return '--'
  return value !== 0 && Math.abs(value) < 0.01 ? value.toPrecision(2) : value.toFixed(2)
}

/** @param {{model: import('../api/types').MLModel}} props */
function EvidenceRow({ model }) {
  const { evidence } = model
  return (
    <>
      <td className="numeric py-2 pr-3">{evidence.labelled}</td>
      <td className="numeric py-2 pr-3 text-[var(--color-ink-faint)]">{evidence.unlabelled}</td>
      <td className="numeric py-2 pr-3">{metric(evidence.precision)}</td>
      <td className="numeric py-2 pr-3">{metric(evidence.recall)}</td>
      <td className="numeric py-2 pr-3">{metric(evidence.average_precision)}</td>
      <td className="numeric py-2 pr-3">{metric(evidence.false_positives_per_day, 1)}</td>
      <td className="numeric py-2 pr-3 text-[var(--color-ink-dim)]">
        {metric(evidence.days, 1)}
      </td>
    </>
  )
}

/**
 * @param {{model: import('../api/types').MLModel, canDeploy: boolean,
 *   pending: boolean, onPromote: () => void}} props
 */
export function ModelRow({ model, canDeploy, pending, onPromote }) {
  const promotable = model.blocked_by === null

  return (
    <tr
      className="border-b border-[var(--color-line)]/50 transition-colors duration-100 last:border-b-0 hover:bg-[var(--color-panel-raised)] [&>td]:py-3 [&>td:first-child]:pl-3"
      data-testid={`model-${model.model_id}`}
    >
      <td className="py-2 pr-3">
        <span className="font-medium">{model.name}</span>{' '}
        <span className="data text-[var(--color-ink-dim)]">{model.version}</span>
      </td>
      <td className="numeric py-2 pr-3 text-[var(--color-ink-dim)]">{model.tier}</td>
      <td className="py-2 pr-3">
        <ModeBadge mode={model.mode} />
      </td>
      <td className="numeric py-2 pr-3 text-[var(--color-ink-dim)]">
        {threshold(model.threshold)}
      </td>
      <EvidenceRow model={model} />
      <td className="py-2">
        {canDeploy && model.mode === 'shadow' ? (
          <button
            type="button"
            disabled={pending || !promotable}
            title={model.blocked_by ?? undefined}
            onClick={onPromote}
            className="control disabled:opacity-40"
          >
            Promote
          </button>
        ) : null}
        {model.blocked_by && model.mode === 'shadow' && (
          <p className="text-[11px] text-[var(--color-ink-faint)]" data-testid="blocked-reason">
            {model.blocked_by}
          </p>
        )}
      </td>
    </tr>
  )
}

export function ModelsPage() {
  const { token, can } = useAuth()
  const queryClient = useQueryClient()
  const canDeploy = can(PERMISSIONS.modelsDeploy)
  const [since, setSince] = useState('7d')

  const { data, error, isLoading } = useQuery({
    queryKey: ['models', since],
    queryFn: () => api.models(token, since),
    enabled: token !== null,
  })

  const promote = useMutation({
    // The window travels with the promotion, so the evidence written into the audit
    // row is measured over the window whose numbers are on screen.
    mutationFn: (modelId) => api.promoteModel(token, modelId, since),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['models'] })
    },
  })

  return (
    <section>
      <header className="mb-4 flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-semibold tracking-tight">Models</h1>
        <select
          aria-label="Report window"
          value={since}
          onChange={(event) => setSince(event.target.value)}
          className="control ml-auto"
        >
          {WINDOWS.map((value) => (
            <option key={value} value={value}>
              Last {value}
            </option>
          ))}
        </select>
      </header>

      {error && <ErrorNotice error={error} />}
      {promote.error && <ErrorNotice error={promote.error} />}

      {isLoading && <p className="text-sm text-[var(--color-ink-dim)]">Loading registry...</p>}

      {data && data.length === 0 && (
        <p className="rounded-lg border border-[var(--color-line)] bg-[var(--color-panel)] p-4 text-sm text-[var(--color-ink-dim)]">
          No models are registered. Register one with netsentinel-register-model before the
          sensor can score anything.
        </p>
      )}

      {data && data.length > 0 && (
        <>
          <div className="overflow-x-auto rounded-lg border border-[var(--color-line)] bg-[var(--color-panel)]/40">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-[var(--color-line)] bg-[var(--color-panel)] text-left text-[11px] uppercase tracking-wider text-[var(--color-ink-faint)] [&>th:first-child]:pl-3">
                <th className="py-2 pr-3 font-medium">Model</th>
                <th className="py-2 pr-3 font-medium">Tier</th>
                <th className="py-2 pr-3 font-medium">Mode</th>
                <th className="py-2 pr-3 font-medium">Threshold</th>
                <th className="py-2 pr-3 font-medium">Labelled</th>
                <th className="py-2 pr-3 font-medium" title="Verdicts nobody triaged">
                  Unlabelled
                </th>
                <th className="py-2 pr-3 font-medium">Precision</th>
                <th className="py-2 pr-3 font-medium">Recall</th>
                <th
                  className="py-2 pr-3 font-medium"
                  title="Average precision: threshold-free ranking quality, and how candidates are compared"
                >
                  AP
                </th>
                <th className="py-2 pr-3 font-medium">FP/day</th>
                <th className="py-2 pr-3 font-medium">Days</th>
                <th className="py-2 font-medium" />
              </tr>
            </thead>
            <tbody>
              {data.map((model) => (
                <ModelRow
                  key={model.model_id}
                  model={model}
                  canDeploy={canDeploy}
                  pending={promote.isPending}
                  onPromote={() => promote.mutate(model.model_id)}
                />
              ))}
            </tbody>
          </table>
          </div>

          <p className="mt-3 text-xs text-[var(--color-ink-faint)]">
            These are not ground-truth metrics. They measure agreement with analyst verdicts
            on the flows that were triaged, which is a biased sample - nobody labels the
            traffic nothing fired on. Read precision next to the unlabelled count, and treat
            a dash as no evidence rather than as a zero.
          </p>
        </>
      )}
    </section>
  )
}
