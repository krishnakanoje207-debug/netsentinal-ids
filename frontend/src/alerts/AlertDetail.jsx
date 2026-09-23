/**
 * One alert: what happened, why the model thought so, and what to do about it.
 *
 * Two absences are shown explicitly rather than glossed over:
 *
 * - no explanation at all, because the alert came from Suricata or Wazuh and no model
 *   was involved;
 * - an explanation whose verdict was shadow-mode, so it was recorded but not acted on.
 *
 * Both would be easy to render as a blank panel, and a blank panel reads as "nothing to
 * worry about".
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Suspense, lazy } from 'react'
import { Link, useParams } from 'react-router-dom'

import { api } from '../api/client'
import { PERMISSIONS } from '../api/types'
import { useAuth } from '../auth/AuthContext'
import { ErrorNotice } from '../components/ErrorNotice'
import { RiskScore } from '../components/RiskScore'
import { SeverityBadge, statusLabel } from '../components/SeverityBadge'
// Recharts is the largest dependency in the bundle and only this page needs it, so the
// alert feed - the landing page - does not pay for it.
const ShapChart = lazy(() =>
  import('./ShapChart').then((module) => ({ default: module.ShapChart })),
)

const TRIAGE_OPTIONS = [
  'new',
  'triaging',
  'escalated',
  'closed_true_positive',
  'closed_false_positive',
]

function Field({ label, children }) {
  return (
    <div>
      <dt className="text-[11px] uppercase tracking-wide text-[var(--color-ink-faint)]">{label}</dt>
      <dd className="numeric mt-0.5 text-sm">{children}</dd>
    </div>
  )
}

export function AlertDetail() {
  const { alertId } = useParams()
  const { token, can } = useAuth()
  const queryClient = useQueryClient()
  const id = Number(alertId)

  const { data: alert, error, isLoading } = useQuery({
    queryKey: ['alert', id],
    queryFn: () => api.alert(token, id),
    enabled: token !== null && Number.isFinite(id),
  })

  const triage = useMutation({
    mutationFn: (status) => api.setAlertStatus(token, id, status),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['alert', id] })
      void queryClient.invalidateQueries({ queryKey: ['alerts'] })
    },
  })

  if (isLoading) return <p className="text-sm text-[var(--color-ink-dim)]">Loading alert...</p>
  if (error) return <ErrorNotice error={error} />
  if (!alert) return null

  const explanation = alert.explanation

  return (
    <article className="space-y-4">
      <header className="flex flex-wrap items-center gap-3">
        <Link to="/" className="text-sm text-[var(--color-accent)] hover:underline">
          &larr; Alerts
        </Link>
        <h1 className="text-xl font-semibold tracking-tight">Alert {alert.alert_id}</h1>
        <SeverityBadge severity={alert.severity} />
        <RiskScore
          score={explanation?.risk_score ?? null}
          shadow={explanation?.shadow ?? false}
          undecidedReason={
            explanation === null
              ? 'This alert came from a signature or host sensor, so no model scored it.'
              : undefined
          }
        />
      </header>

      <dl className="grid grid-cols-2 gap-3 rounded-lg border border-[var(--color-line)] bg-[var(--color-panel)] p-4 sm:grid-cols-3">
        <Field label="Source">{alert.source}</Field>
        <Field label="Status">{statusLabel(alert.status)}</Field>
        <Field label="Raised">{new Date(alert.created_at).toLocaleString()}</Field>
        <Field label="From"><span className="data">{alert.src_ip ?? '--'}</span></Field>
        <Field label="To"><span className="data">{alert.dst_ip ?? '--'}</span></Field>
        <Field label="MITRE technique">{alert.mitre_technique ?? '--'}</Field>
      </dl>

      {explanation?.shadow && (
        <p
          className="rounded border border-[var(--color-sev-medium)]/50 bg-[var(--color-sev-medium)]/10 p-3 text-sm"
          data-testid="shadow-notice"
        >
          This verdict was produced in <strong>shadow mode</strong>. It was recorded so it
          can be compared against your judgement, and nothing was acted on.
        </p>
      )}

      <section className="rounded-lg border border-[var(--color-line)] bg-[var(--color-panel)] p-4">
        <h2 className="mb-3 text-sm font-semibold">Why this was flagged</h2>
        {explanation === null ? (
          <p className="text-sm text-[var(--color-ink-dim)]" data-testid="no-explanation">
            No model explanation exists for this alert. It was raised by a signature or host
            sensor rather than by the ML engine, so there are no feature contributions to
            show - not an absence of evidence, a different kind of evidence.
          </p>
        ) : (
          <>
            <Suspense
              fallback={
                <p className="text-sm text-[var(--color-ink-dim)]">Loading explanation...</p>
              }
            >
              <ShapChart contributions={explanation.feature_contributions} />
            </Suspense>
            <div className="mt-4 border-t border-[var(--color-line)] pt-3">
              <h3 className="mb-1.5 text-[11px] uppercase tracking-wide text-[var(--color-ink-faint)]">
                Per-model scores
              </h3>
              <ul className="flex flex-wrap gap-x-5 gap-y-1 text-sm">
                {Object.entries(explanation.model_scores).map(([tier, score]) => (
                  <li key={tier} className="numeric">
                    <span className="text-[var(--color-ink-dim)]">{tier}</span>{' '}
                    {(score * 100).toFixed(0)}%
                  </li>
                ))}
              </ul>
            </div>
          </>
        )}
      </section>

      {alert.ioc_values.length > 0 && (
        <section className="rounded-lg border border-[var(--color-line)] bg-[var(--color-panel)] p-4">
          <h2 className="mb-2 text-sm font-semibold">Matched threat intelligence</h2>
          <ul className="numeric space-y-1 text-sm">
            {alert.ioc_values.map((value) => (
              <li key={value}>{value}</li>
            ))}
          </ul>
        </section>
      )}

      {can(PERMISSIONS.alertsTriage) && (
        <section className="rounded-lg border border-[var(--color-line)] bg-[var(--color-panel)] p-4">
          <h2 className="mb-2 text-sm font-semibold">Triage</h2>
          {triage.error && <ErrorNotice error={triage.error} />}
          <div className="flex flex-wrap gap-2">
            {TRIAGE_OPTIONS.filter((option) => option !== alert.status).map((option) => (
              <button
                key={option}
                type="button"
                disabled={triage.isPending}
                onClick={() => triage.mutate(option)}
                className="control hover:border-[var(--color-accent)] hover:text-[var(--color-accent)] disabled:opacity-50"
              >
                {statusLabel(option)}
              </button>
            ))}
          </div>
        </section>
      )}
    </article>
  )
}
