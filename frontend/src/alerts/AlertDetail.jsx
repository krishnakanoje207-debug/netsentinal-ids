/**
 * One alert: what happened, why the model thought so, and what to do about it.
 *
 * Written to be read top to bottom by someone who has never seen the system: a sentence
 * saying what happened, the reasons in plain words, then the actions this account is
 * allowed to take - and, for an account that may take none, a sentence saying so rather
 * than an empty space.
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
import { CheckCircle, Eye, FolderOpen, Prohibit, XCircle } from '../components/icons'
import { RiskScore } from '../components/RiskScore'
import { SeverityBadge, statusLabel } from '../components/SeverityBadge'
import { SEVERITY_MEANING, STATUS_MEANING, featureLabel, tierName } from '../lib/glossary'

// Recharts is the largest dependency in the bundle and only this page needs it, so the
// pages people land on do not pay for it.
const ShapChart = lazy(() =>
  import('./ShapChart').then((module) => ({ default: module.ShapChart })),
)

/** Triage moves, named for what the analyst means rather than the status they set. */
const TRIAGE = [
  { status: 'triaging', label: "I'm looking at it", icon: Eye },
  { status: 'closed_true_positive', label: 'Confirm attack', icon: CheckCircle },
  { status: 'closed_false_positive', label: 'False alarm', icon: XCircle },
  { status: 'new', label: 'Reopen', icon: null },
]

/** @param {string[]} names */
function spokenList(names) {
  if (names.length <= 1) return names.join('')
  return `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`
}

/**
 * The alert in one or two sentences, from the fields the API sends. Nothing is inferred
 * that the data does not say: no port, because the explanation carries influences, not
 * the raw values.
 *
 * @param {import('../api/types').AlertDetail} alert
 */
export function whatHappened(alert) {
  const from = alert.src_ip ?? 'an unknown address'
  const to = alert.dst_ip ?? 'an unknown address'
  const when = new Date(alert.created_at).toLocaleString()
  const explanation = alert.explanation
  if (!explanation) {
    return `At ${when}, the ${alert.source} sensor raised an alert on traffic from ${from} to ${to}.`
  }
  const score = Math.round(explanation.risk_score * 100)
  const reasons = spokenList(explanation.top_features.slice(0, 3).map((f) => featureLabel(f).toLowerCase()))
  return (
    `At ${when}, traffic from ${from} to ${to} was rated ${score}% likely to be an attack. ` +
    `What stood out most: ${reasons}.`
  )
}

/** @param {{label: string, children: import('react').ReactNode, hint?: string}} props */
function Field({ label, children, hint }) {
  return (
    <div>
      <dt className="text-xs text-[var(--color-ink-faint)]">{label}</dt>
      <dd className="mt-0.5 text-sm">{children}</dd>
      {hint && <dd className="mt-0.5 text-xs text-[var(--color-ink-dim)]">{hint}</dd>}
    </div>
  )
}

/** @param {{title: string, children: import('react').ReactNode, description?: string}} props */
function Panel({ title, description, children }) {
  return (
    <section className="rounded-lg border border-[var(--color-line)] bg-[var(--color-panel)] p-5">
      <h2 className="text-sm font-semibold">{title}</h2>
      {description && <p className="mt-1 text-sm text-[var(--color-ink-dim)]">{description}</p>}
      <div className="mt-4">{children}</div>
    </section>
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

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ['alert', id] })
    void queryClient.invalidateQueries({ queryKey: ['alerts'] })
    void queryClient.invalidateQueries({ queryKey: ['alert-summary'] })
  }

  const triage = useMutation({
    mutationFn: (status) => api.setAlertStatus(token, id, status),
    onSuccess: refresh,
  })
  const escalate = useMutation({
    mutationFn: () => api.escalate(token, id),
    onSuccess: refresh,
  })
  const propose = useMutation({
    mutationFn: () => api.proposeAction(token, id, 'block_ip'),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['pending-actions'] }),
  })

  if (isLoading) return <p className="text-sm text-[var(--color-ink-dim)]">Loading alert...</p>
  if (error) return <ErrorNotice error={error} />
  if (!alert) return null

  const explanation = alert.explanation
  const canTriage = can(PERMISSIONS.alertsTriage)
  const canPropose = can(PERMISSIONS.responsePropose)
  const busy = triage.isPending || escalate.isPending || propose.isPending

  return (
    <article className="space-y-5">
      <Link to="/alerts" className="text-sm text-[var(--color-accent)] hover:underline">
        &larr; All alerts
      </Link>

      <header className="flex flex-wrap items-center gap-3">
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

      <p className="max-w-3xl text-base leading-relaxed" data-testid="what-happened">
        {whatHappened(alert)}
      </p>

      <dl className="grid grid-cols-2 gap-x-6 gap-y-4 rounded-lg border border-[var(--color-line)] bg-[var(--color-panel)] p-5 sm:grid-cols-3">
        <Field label="Severity" hint={SEVERITY_MEANING[alert.severity]}>
          <span className="capitalize">{alert.severity}</span>
        </Field>
        <Field label="Status" hint={STATUS_MEANING[alert.status]}>
          {statusLabel(alert.status)}
        </Field>
        <Field label="Raised">{new Date(alert.created_at).toLocaleString()}</Field>
        <Field label="From" hint="Where the traffic came from">
          <span className="data">{alert.src_ip ?? '--'}</span>
        </Field>
        <Field label="To" hint="The machine it was aimed at">
          <span className="data">{alert.dst_ip ?? '--'}</span>
        </Field>
        <Field label="Attack technique (MITRE)" hint={alert.mitre_technique ? undefined : 'Not identified for this alert'}>
          {alert.mitre_technique ?? '--'}
        </Field>
      </dl>

      {explanation?.shadow && (
        <p
          className="rounded-lg border border-[var(--color-sev-medium)]/50 bg-[var(--color-sev-medium)]/10 p-3 text-sm"
          data-testid="shadow-notice"
        >
          This verdict was produced in <strong>shadow mode</strong>: recorded so it can be
          compared against your judgement, and nothing was acted on.
        </p>
      )}

      <Panel
        title="Why this was flagged"
        description={
          explanation === null
            ? undefined
            : 'Each bar is one measurement of the traffic. Longer bars mattered more to the verdict.'
        }
      >
        {explanation === null ? (
          <p className="text-sm text-[var(--color-ink-dim)]" data-testid="no-explanation">
            No model explanation exists for this alert. It was raised by a signature or host
            sensor rather than by the AI models, so there are no measurements to show. That is
            a different kind of evidence, not an absence of it.
          </p>
        ) : (
          <>
            <Suspense
              fallback={<p className="text-sm text-[var(--color-ink-dim)]">Loading explanation...</p>}
            >
              <ShapChart contributions={explanation.feature_contributions} />
            </Suspense>
            <div className="mt-5 border-t border-[var(--color-line)] pt-4">
              <h3 className="text-xs text-[var(--color-ink-faint)]">What each model said</h3>
              <ul className="mt-2 flex flex-wrap gap-x-8 gap-y-2 text-sm">
                {Object.entries(explanation.model_scores).map(([tier, score]) => (
                  <li key={tier}>
                    <span className="text-[var(--color-ink-dim)]">{tierName(tier)}</span>{' '}
                    <span className="numeric font-semibold">{(score * 100).toFixed(0)}%</span>
                  </li>
                ))}
              </ul>
            </div>
          </>
        )}
      </Panel>

      {alert.ioc_values.length > 0 && (
        <Panel
          title="Known bad indicators"
          description="These values appear in the threat-intelligence feeds this system checks against."
        >
          <ul className="space-y-1 text-sm">
            {alert.ioc_values.map((value) => (
              <li key={value} className="data">
                {value}
              </li>
            ))}
          </ul>
        </Panel>
      )}

      <Panel
        title="What you can do"
        description={
          canTriage || canPropose
            ? 'Nothing here blocks traffic on its own. A block always waits for an analyst to approve it.'
            : 'Your account can read this alert but not act on it.'
        }
      >
        {(triage.error || escalate.error || propose.error) && (
          <div className="mb-3">
            <ErrorNotice error={triage.error || escalate.error || propose.error} />
          </div>
        )}
        {escalate.data && (
          <p className="mb-3 text-sm text-[var(--color-sev-low)]" role="status">
            Incident {escalate.data.incident_id} opened.{' '}
            {escalate.data.iris_case_id
              ? `Case ${escalate.data.iris_case_id} created in DFIR-IRIS.`
              : 'The case-management system is not connected, so the incident is recorded here only.'}
          </p>
        )}
        {propose.data && (
          <p className="mb-3 text-sm text-[var(--color-sev-low)]" role="status">
            Block on <span className="data">{propose.data.target}</span> proposed. It now waits on
            the Approvals page for an analyst.
          </p>
        )}

        {canTriage && (
          <div className="flex flex-wrap gap-2">
            {TRIAGE.filter((option) => option.status !== alert.status).map(({ status, label, icon: Icon }) => (
              <button
                key={status}
                type="button"
                disabled={busy}
                onClick={() => triage.mutate(status)}
                title={STATUS_MEANING[status]}
                className="control inline-flex items-center gap-1.5 disabled:opacity-50"
              >
                {Icon && <Icon size={14} aria-hidden="true" />}
                {label}
              </button>
            ))}
            {alert.status !== 'escalated' && (
              <button
                type="button"
                disabled={busy}
                onClick={() => escalate.mutate()}
                title="Open an incident so the investigation has an owner"
                className="control inline-flex items-center gap-1.5 disabled:opacity-50"
              >
                <FolderOpen size={14} aria-hidden="true" />
                Escalate to incident
              </button>
            )}
          </div>
        )}

        {canPropose && (
          <div className={canTriage ? 'mt-3' : ''}>
            <button
              type="button"
              disabled={busy || !alert.src_ip || Boolean(propose.data)}
              onClick={() => propose.mutate()}
              className="control inline-flex items-center gap-1.5 border-[var(--color-sev-high)]/60 text-[var(--color-sev-high)] disabled:opacity-50"
            >
              <Prohibit size={14} aria-hidden="true" />
              Propose blocking {alert.src_ip ?? 'the source'}
            </button>
          </div>
        )}
      </Panel>
    </article>
  )
}
