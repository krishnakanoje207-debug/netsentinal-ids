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
import { Brain } from '../components/icons'
import { PageHeader } from '../components/PageHeader'
import { TIERS } from '../lib/glossary'

const WINDOWS = ['24h', '7d', '14d', '30d']

/** A lamp and a word: lit green while deciding, an open ring while watching. */
const MODE_LAMP = {
  active: 'bg-sev-low',
  shadow: 'border-2 border-sev-info bg-transparent',
  retired: 'bg-line-strong',
}
const MODE_TEXT = {
  active: 'text-sev-low',
  shadow: 'text-sev-info',
  retired: 'text-ink-faint',
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
      className={`inline-flex items-center gap-1.5 text-[0.75rem] font-bold tracking-[0.06em] uppercase ${MODE_TEXT[mode]}`}
      data-testid="mode-badge"
    >
      <span className={`inline-block size-2.5 rounded-full ${MODE_LAMP[mode]}`} aria-hidden="true" />
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
      <td className="numeric px-3 text-right">{evidence.labelled}</td>
      <td className="numeric px-3 text-right text-ink-faint">{evidence.unlabelled}</td>
      <td className="numeric px-3 text-right font-semibold">{metric(evidence.precision)}</td>
      <td className="numeric px-3 text-right font-semibold">{metric(evidence.recall)}</td>
      <td className="numeric px-3 text-right">{metric(evidence.average_precision)}</td>
      <td className="numeric px-3 text-right">{metric(evidence.false_positives_per_day, 1)}</td>
      <td className="numeric px-3 text-right text-ink-dim">{metric(evidence.days, 1)}</td>
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
      className="border-t border-line align-top transition-colors duration-150 hover:bg-sunk [&>td]:py-3.5"
      data-testid={`model-${model.model_id}`}
    >
      <td className="pr-3 pl-4">
        <span className="block font-bold">{model.name}</span>
        <span className="data text-ink-dim">{model.version}</span>
      </td>
      <td className="px-3" title={TIERS[model.tier]?.does}>
        <span className="block font-semibold whitespace-nowrap">{TIERS[model.tier]?.name ?? `Tier ${model.tier}`}</span>
        <span className="block text-[0.8125rem] text-ink-faint">Tier {model.tier}</span>
      </td>
      <td className="px-3">
        <ModeBadge mode={model.mode} />
      </td>
      <td className="numeric px-3 text-right text-ink-dim">{threshold(model.threshold)}</td>
      <EvidenceRow model={model} />
      <td className="pr-4 pl-3">
        {canDeploy && model.mode === 'shadow' ? (
          <button
            type="button"
            disabled={pending || !promotable}
            title={model.blocked_by ?? undefined}
            onClick={onPromote}
            className="control press font-semibold disabled:opacity-40"
          >
            Promote
          </button>
        ) : null}
        {model.blocked_by && model.mode === 'shadow' && (
          <p className="mt-1.5 max-w-[14rem] text-[0.8125rem] leading-snug text-ink-faint" data-testid="blocked-reason">
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
      <PageHeader
        icon={Brain}
        title="Models"
        description="The AI models that score traffic. A new model starts in shadow mode: it watches and is measured against analysts' verdicts, but decides nothing until an ML engineer promotes it."
      >
        <select
          aria-label="Report window"
          value={since}
          onChange={(event) => setSince(event.target.value)}
          className="control"
        >
          {WINDOWS.map((value) => (
            <option key={value} value={value}>
              Last {value}
            </option>
          ))}
        </select>
      </PageHeader>

      {error && <ErrorNotice error={error} />}
      {promote.error && <ErrorNotice error={promote.error} />}

      {isLoading && <p className="text-ink-dim">Loading registry...</p>}

      {data && data.length === 0 && (
        <p className="panel p-6 text-[0.9375rem] text-ink-dim">
          No models are registered. Register one with netsentinel-register-model before the
          sensor can score anything.
        </p>
      )}

      {data && data.length > 0 && (
        <>
          <div className="panel overflow-x-auto" data-tour="models">
          <table className="w-full border-collapse text-[0.9375rem]">
            <thead>
              <tr className="bg-sunk text-left text-[0.6875rem] font-bold tracking-[0.08em] text-ink-dim uppercase [&>th]:px-3 [&>th]:py-2.5 [&>th:first-child]:pl-4 [&>th:nth-child(n+4)]:text-right">
                <th className="font-bold">Model</th>
                <th className="font-bold">Tier</th>
                <th className="font-bold" title="Active models decide; shadow models only watch">Mode</th>
                <th className="font-bold" title="The score above which a flow becomes an alert">Threshold</th>
                <th className="font-bold" title="Alerts an analyst confirmed or dismissed">Reviewed</th>
                <th className="font-bold" title="Verdicts nobody has reviewed yet">
                  Not reviewed
                </th>
                <th className="font-bold" title="Of the alerts reviewed, the share that were real attacks">Precision</th>
                <th className="font-bold" title="Of the real attacks reviewed, the share this model caught">Recall</th>
                <th
                  className="font-bold"
                  title="Average precision: threshold-free ranking quality, and how candidates are compared"
                >
                  AP
                </th>
                <th className="font-bold" title="False alarms per day">False alarms/day</th>
                <th className="font-bold" title="Days of evidence in the window">Days</th>
                <th className="font-bold" />
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

          <p className="mt-3 max-w-3xl text-[0.8125rem] text-ink-faint">
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
