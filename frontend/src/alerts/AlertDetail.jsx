/**
 * One alert: what happened, why the model thought so, and what to do about it.
 *
 * Written to be read top to bottom by someone who has never seen the system: a sentence
 * saying what happened, the reasons as opposing pulls, then the actions this account is
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
import { Link, useParams } from 'react-router-dom'

import { api } from '../api/client'
import { PERMISSIONS } from '../api/types'
import { useAuth } from '../auth/AuthContext'
import { ErrorNotice } from '../components/ErrorNotice'
import { ArrowLeft, CheckCircle, Eye, FolderOpen, Prohibit, XCircle } from '../components/icons'
import { RiskScore } from '../components/RiskScore'
import { SeverityBadge, StatusPill, statusLabel } from '../components/SeverityBadge'
import {
  SEVERITY_MEANING,
  STATUS_MEANING,
  featureLabel,
  techniqueName,
  tierName,
} from '../lib/glossary'
import { ShapChart } from './ShapChart'

/** Triage moves, named for what the analyst means rather than the status they set. */
const TRIAGE = [
  { status: 'triaging', label: "I'm looking at it", icon: Eye },
  { status: 'closed_true_positive', label: 'Confirm attack', icon: CheckCircle },
  { status: 'closed_false_positive', label: 'False alarm', icon: XCircle },
  { status: 'new', label: 'Reopen', icon: null },
]

/** The model's verdict, in words and in the severity palette. */
const ASSESSMENT = {
  likely_malicious: { label: 'Likely malicious', tone: 'text-sev-critical border-sev-critical' },
  needs_investigation: { label: 'Needs investigation', tone: 'text-sev-medium border-sev-medium' },
  likely_benign: { label: 'Likely harmless', tone: 'text-sev-low border-sev-low' },
}

/** Where the alert is on its way from being seen to being decided. */
const DECIDED = {
  new: 'Waiting for a person',
  triaging: 'Being reviewed',
  escalated: 'Incident opened',
  closed_true_positive: 'Confirmed attack',
  closed_false_positive: 'False alarm',
}

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
    <div className="py-3 first:pt-0 last:pb-0">
      <dt className="text-[0.8125rem] font-semibold text-ink-faint">{label}</dt>
      <dd className="mt-0.5">{children}</dd>
      {hint && <dd className="mt-0.5 text-[0.8125rem] text-ink-dim">{hint}</dd>}
    </div>
  )
}

/** @param {{title: string, children: import('react').ReactNode, description?: string, tour?: string}} props */
function Panel({ title, description, children, tour }) {
  return (
    <section className="panel p-5 md:p-6" data-tour={tour}>
      <h2 className="text-lg font-extrabold tracking-tight">{title}</h2>
      {description && <p className="mt-1 text-[0.9375rem] text-ink-dim">{description}</p>}
      <div className="mt-5">{children}</div>
    </section>
  )
}

/** Seen, scored, explained, decided: the alert's journey so far. */
function Journey({ alert }) {
  const explanation = alert.explanation
  const stops = [
    { name: 'Seen', value: new Date(alert.created_at).toLocaleTimeString([], { hourCycle: 'h23' }), done: true },
    {
      name: 'Scored',
      value: explanation ? `${Math.round(explanation.risk_score * 100)}% likely an attack` : 'By a signature rule',
      done: true,
    },
    {
      name: 'Explained',
      value: explanation
        ? `${Object.keys(explanation.feature_contributions).length} measurements weighed`
        : 'No model measurements',
      done: explanation !== null,
    },
    { name: 'Decided', value: DECIDED[alert.status] ?? statusLabel(alert.status), done: alert.status !== 'new' },
  ]
  return (
    <ol className="journey grid grid-cols-4" aria-label="Where this alert is">
      {stops.map((stop, index) => (
        <li key={stop.name} className="relative pr-2">
          {index < stops.length - 1 && (
            <span className={`journey-seg ${stops[index + 1].done ? 'journey-seg-done' : ''}`} aria-hidden="true" />
          )}
          <span className={`journey-stop ${stop.done ? 'journey-stop-done' : ''}`} aria-hidden="true" />
          <span className="mt-2 block text-[0.8125rem] font-bold">{stop.name}</span>
          <span className="block text-[0.8125rem] leading-snug text-ink-dim">{stop.value}</span>
        </li>
      ))}
    </ol>
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

  const summary = useQuery({
    queryKey: ['copilot-summary', id],
    queryFn: () => api.copilotSummary(token, id),
    enabled: token !== null && Number.isFinite(id),
  })

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

  if (isLoading) return <p className="text-ink-dim">Loading alert...</p>
  if (error) return <ErrorNotice error={error} />
  if (!alert) return null

  const explanation = alert.explanation
  const canTriage = can(PERMISSIONS.alertsTriage)
  const canPropose = can(PERMISSIONS.responsePropose)
  const busy = triage.isPending || escalate.isPending || propose.isPending

  return (
    <article className="rise-in">
      <Link
        to="/alerts"
        viewTransition
        className="group mb-5 inline-flex items-center gap-1.5 text-sm font-semibold text-accent"
      >
        <ArrowLeft size={14} weight="bold" className="transition-transform duration-200 group-hover:-translate-x-0.5" aria-hidden="true" />
        <span className="group-hover:underline">All alerts</span>
      </Link>

      <header className="panel mb-6 p-5 md:p-6">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <h1 className="text-[1.75rem] leading-tight font-extrabold md:text-[2rem]">Alert {alert.alert_id}</h1>
          <SeverityBadge severity={alert.severity} />
          <StatusPill status={alert.status} />
          <span className="ml-auto text-2xl">
            <RiskScore
              score={explanation?.risk_score ?? null}
              shadow={explanation?.shadow ?? false}
              undecidedReason={
                explanation === null
                  ? 'This alert came from a signature or host sensor, so no model scored it.'
                  : undefined
              }
            />
          </span>
        </div>
        <p className="data mt-3 text-lg text-ink">
          <span className="sr-only">From </span>
          {alert.src_ip ?? '--'}
          <span className="px-2 text-ink-faint" aria-hidden="true">→</span>
          <span className="sr-only"> to </span>
          {alert.dst_ip ?? '--'}
        </p>
        <p className="mt-4 max-w-3xl text-[1.0625rem] leading-relaxed" data-testid="what-happened">
          {whatHappened(alert)}
        </p>
        <div className="mt-6 border-t border-line pt-5">
          <Journey alert={alert} />
        </div>
      </header>

      {explanation?.shadow && (
        <p
          className="mb-6 rounded-md border border-sev-medium/50 bg-fill-medium/15 p-4 text-[0.9375rem]"
          data-testid="shadow-notice"
        >
          This verdict was produced in <strong>shadow mode</strong>: recorded so it can be compared
          against your judgement, and nothing was acted on.
        </p>
      )}

      <div className="grid gap-6 lg:grid-cols-12">
        <div className="space-y-6 lg:col-span-8">
          <Panel
            tour="reasons"
            title="Why this was flagged"
            description={
              explanation === null
                ? undefined
                : 'Each row is one measurement of the traffic. Longer bars mattered more to the verdict.'
            }
          >
            {explanation === null ? (
              <p className="text-ink-dim" data-testid="no-explanation">
                No model explanation exists for this alert. It was raised by a signature or host
                sensor rather than by the AI models, so there are no measurements to show. That is
                a different kind of evidence, not an absence of it.
              </p>
            ) : (
              <>
                <ShapChart contributions={explanation.feature_contributions} />
                <div className="mt-6 border-t border-line pt-5">
                  <h3 className="text-sm font-bold text-ink-dim">What each model said</h3>
                  <ul className="mt-3 grid gap-3 sm:grid-cols-2">
                    {Object.entries(explanation.model_scores).map(([tier, score]) => (
                      <li key={tier}>
                        <div className="flex items-baseline justify-between gap-3">
                          <span>{tierName(tier)}</span>
                          <span className="numeric font-bold">{(score * 100).toFixed(0)}%</span>
                        </div>
                        <span className="mt-1 block h-1.5 overflow-hidden rounded-full bg-sunk">
                          <span
                            className="severity-bar block h-full rounded-full bg-accent"
                            style={{ scale: `${Math.max(0.01, score)} 1` }}
                          />
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              </>
            )}
          </Panel>

          <Panel
            title="AI summary"
            description="Written by a language model running on this machine. It can be wrong: the evidence above is what counts."
          >
            {summary.data ? (
              <div className="space-y-3 text-[0.9375rem]" data-testid="copilot-summary">
                <p className="flex flex-wrap items-center gap-2">
                  <span className="font-bold">{summary.data.headline}</span>
                  <span
                    className={`rounded-full border px-2.5 py-0.5 text-[0.8125rem] font-semibold ${
                      ASSESSMENT[summary.data.assessment]?.tone ?? 'border-line text-ink-dim'
                    }`}
                  >
                    {ASSESSMENT[summary.data.assessment]?.label ?? summary.data.assessment}
                  </span>
                </p>
                <p>{summary.data.what_happened}</p>
                <p className="text-ink-dim">{summary.data.why_it_scored}</p>
                <div>
                  <p className="text-[0.8125rem] font-semibold text-ink-faint">Suggested next steps</p>
                  <ul className="mt-1 list-disc space-y-1 pl-5">
                    {summary.data.next_steps.map((step) => (
                      <li key={step}>{step}</li>
                    ))}
                  </ul>
                </div>
                <p className="text-[0.8125rem] text-ink-faint">Model: {summary.data.llm_model}</p>
              </div>
            ) : (
              <p className="text-ink-dim">
                {summary.isLoading ? 'Looking for a summary...' : 'No AI summary has been written for this alert yet.'}
              </p>
            )}
          </Panel>

          {alert.ioc_values.length > 0 && (
            <Panel
              title="Known bad indicators"
              description="These values appear in the threat-intelligence feeds this system checks against."
            >
              <ul className="space-y-1">
                {alert.ioc_values.map((value) => (
                  <li key={value} className="data">
                    {value}
                  </li>
                ))}
              </ul>
            </Panel>
          )}
        </div>

        <aside className="space-y-6 lg:col-span-4">
          <div className="lg:sticky lg:top-24 lg:space-y-6">
            <section className="panel p-5 md:p-6" data-tour="actions">
              <h2 className="text-lg font-extrabold tracking-tight">What you can do</h2>
              <p className="mt-1 text-[0.9375rem] text-ink-dim">
                {canTriage || canPropose
                  ? 'Nothing here blocks traffic on its own. A block always waits for an analyst to approve it.'
                  : 'Your account can read this alert but not act on it.'}
              </p>

              <div className="mt-4 space-y-3">
                {(triage.error || escalate.error || propose.error) && (
                  <ErrorNotice error={triage.error || escalate.error || propose.error} />
                )}
                {escalate.data && (
                  <p className="text-[0.9375rem] font-semibold text-sev-low" role="status">
                    Incident {escalate.data.incident_id} opened.{' '}
                    {escalate.data.iris_case_id
                      ? `Case ${escalate.data.iris_case_id} created in DFIR-IRIS.`
                      : 'The case-management system is not connected, so the incident is recorded here only.'}
                  </p>
                )}
                {propose.data && (
                  <p className="text-[0.9375rem] font-semibold text-sev-low" role="status">
                    Block on <span className="data">{propose.data.target}</span> proposed. It now waits on
                    the Approvals page for an analyst.
                  </p>
                )}

                {canTriage && (
                  <div className="grid gap-2">
                    {TRIAGE.filter((option) => option.status !== alert.status).map(({ status, label, icon: Icon }) => (
                      <button
                        key={status}
                        type="button"
                        disabled={busy}
                        onClick={() => triage.mutate(status)}
                        title={STATUS_MEANING[status]}
                        className="control press inline-flex h-10 items-center gap-2 font-semibold disabled:opacity-50"
                      >
                        {Icon && <Icon size={17} weight="bold" aria-hidden="true" />}
                        {label}
                      </button>
                    ))}
                    {alert.status !== 'escalated' && (
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => escalate.mutate()}
                        title="Open an incident so the investigation has an owner"
                        className="control press inline-flex h-10 items-center gap-2 font-semibold disabled:opacity-50"
                      >
                        <FolderOpen size={17} weight="bold" aria-hidden="true" />
                        Escalate to incident
                      </button>
                    )}
                  </div>
                )}

                {canPropose && (
                  <button
                    type="button"
                    disabled={busy || !alert.src_ip || Boolean(propose.data)}
                    onClick={() => propose.mutate()}
                    className="press inline-flex h-10 w-full items-center justify-center gap-2 rounded-md border-2 border-sev-critical px-3 text-sm font-bold text-sev-critical hover:bg-fill-critical hover:text-white disabled:opacity-50"
                  >
                    <Prohibit size={17} weight="bold" aria-hidden="true" />
                    Propose blocking {alert.src_ip ?? 'the source'}
                  </button>
                )}
              </div>
            </section>

            <dl className="panel divide-y divide-line p-5 md:p-6">
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
              <Field
                label="Attack technique (MITRE ATT&CK)"
                hint={
                  !alert.mitre_technique
                    ? explanation
                      ? 'Not identified: the models were not sure enough which kind of attack this is'
                      : 'The detection rule did not name one'
                    : explanation
                      ? 'Suggested by the attack-family model'
                      : 'From the detection rule'
                }
              >
                {alert.mitre_technique ? (
                  <>
                    <span className="data">{alert.mitre_technique}</span>
                    {techniqueName(alert.mitre_technique) && (
                      <span className="ml-1.5">{techniqueName(alert.mitre_technique)}</span>
                    )}
                  </>
                ) : (
                  '--'
                )}
              </Field>
            </dl>
          </div>
        </aside>
      </div>
    </article>
  )
}
