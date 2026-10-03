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
 *
 * The response history keeps the same discipline: an action is "in force" only once the
 * responder applied it, and asking for it to be lifted says the request is queued, not
 * that traffic is flowing again.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'

import { api } from '../api/client'
import { PERMISSIONS } from '../api/types'
import { useAuth } from '../auth/AuthContext'
import { ErrorNotice } from '../components/ErrorNotice'
import { ArrowCounterClockwise, ArrowLeft, CheckCircle, Eye, FolderOpen, Prohibit, XCircle } from '../components/icons'
import { RiskScore } from '../components/RiskScore'
import { SeverityBadge, StatusPill, statusLabel } from '../components/SeverityBadge'
import {
  ACTION_NAME,
  ACTION_STATUS,
  SEVERITY_MEANING,
  STATUS_MEANING,
  featureLabel,
  techniqueName,
  isWatchingOnly,
  tierName,
} from '../lib/glossary'
import { InputFeatures } from './InputFeatures'
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

/** The plate colour per action state: colour only where something is in force or moving. */
const ACTION_TONE = {
  pending_approval: 'border-sev-medium text-sev-medium',
  approved: 'border-sev-medium text-sev-medium',
  rejected: 'border-line-strong text-ink-dim',
  executed: 'border-sev-critical text-sev-critical',
  rollback_requested: 'border-sev-medium text-sev-medium',
  rolled_back: 'border-line-strong text-ink-dim',
  failed: 'border-sev-high text-sev-high',
}

/** States the responder has yet to move on, so the list is worth polling while one is shown. */
const MOVING = new Set(['pending_approval', 'approved', 'rollback_requested'])

/** @param {string | null} value */
function when(value) {
  return value ? new Date(value).toLocaleString() : null
}

/**
 * One action and, for an executed one this account may undo, the request to lift it.
 *
 * @param {{action: import('../api/types').ResponseAction, canDecide: boolean, alertId: number}} props
 */
function ActionRow({ action, canDecide, alertId }) {
  const { token } = useAuth()
  const queryClient = useQueryClient()
  const [asking, setAsking] = useState(false)
  const [reason, setReason] = useState('')
  const lift = useMutation({
    mutationFn: () => api.requestRollback(token, action.action_id, reason.trim()),
    onSuccess: () => {
      setAsking(false)
      void queryClient.invalidateQueries({ queryKey: ['alert-actions', alertId] })
    },
  })
  const state = ACTION_STATUS[action.status] ?? { label: action.status, meaning: '' }
  const offerLift = canDecide && action.status === 'executed' && action.undoable

  return (
    <li className="py-4 first:pt-0 last:pb-0" data-testid={`alert-action-${action.action_id}`}>
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <span className="font-bold">{ACTION_NAME[action.action_type] ?? action.action_type}</span>
        <code className="data rounded bg-sunk px-1.5 py-0.5">{action.target}</code>
        <span
          className={`ml-auto rounded-[3px] border px-2 py-0.5 text-[0.8125rem] font-semibold ${ACTION_TONE[action.status] ?? 'border-line text-ink-dim'}`}
        >
          {state.label}
        </span>
      </div>
      <p className="mt-1 text-[0.875rem] text-ink-dim">{state.meaning}</p>
      {action.approval && (
        <p className="mt-1 text-[0.875rem] text-ink-dim">
          {action.approval.decision === 'approved' ? 'Approved' : 'Rejected'} by account{' '}
          {action.approval.approver_id}
          {when(action.approval.decided_at) && ` on ${when(action.approval.decided_at)}`}
          {action.approval.comment && (
            <>
              : <q className="text-ink">{action.approval.comment}</q>
            </>
          )}
        </p>
      )}
      {when(action.executed_at) && (
        <p className="mt-1 text-[0.875rem] text-ink-dim">Applied on {when(action.executed_at)}</p>
      )}
      {canDecide && action.status === 'executed' && !action.undoable && (
        <p className="mt-2 text-[0.875rem] text-ink-faint">This kind of action cannot be undone.</p>
      )}

      {lift.data && (
        <p className="mt-2 text-[0.9375rem] font-semibold text-sev-low" role="status">
          Lift requested. It stays in force until the responder lifts it; this list will then say
          Lifted.
        </p>
      )}
      {lift.error && (
        <div className="mt-2">
          <ErrorNotice error={lift.error} />
        </div>
      )}

      {offerLift && !asking && !lift.data && (
        <button
          type="button"
          onClick={() => setAsking(true)}
          className="control press mt-3 inline-flex h-9 items-center gap-2 text-sm font-semibold"
        >
          <ArrowCounterClockwise size={16} weight="bold" aria-hidden="true" />
          Ask to lift this
        </button>
      )}
      {offerLift && asking && (
        <form
          className="mt-3 space-y-2"
          onSubmit={(event) => {
            event.preventDefault()
            if (reason.trim()) lift.mutate()
          }}
        >
          <label className="block">
            <span className="text-[0.8125rem] font-semibold text-ink-dim">Why should it be lifted? (required)</span>
            <textarea
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              rows={2}
              placeholder="What about the original judgement was wrong?"
              className="mt-1.5 w-full rounded-md border border-line-strong bg-panel p-2.5 text-[0.9375rem] transition-colors duration-150 hover:border-ink-faint"
              aria-label={`Reason for lifting action ${action.action_id}`}
            />
          </label>
          <div className="flex gap-2">
            <button
              type="submit"
              disabled={lift.isPending || !reason.trim()}
              title={reason.trim() ? undefined : 'A lift needs a reason the next analyst can read'}
              className="press h-9 rounded-md bg-fill-critical px-4 text-sm font-bold text-white hover:brightness-110 disabled:opacity-50"
            >
              Request the lift
            </button>
            <button type="button" onClick={() => setAsking(false)} className="control press h-9 text-sm font-semibold">
              Cancel
            </button>
          </div>
          <p className="text-[0.8125rem] text-ink-faint">
            This queues the request. The responder lifts it afterwards, not this button.
          </p>
        </form>
      )}
    </li>
  )
}

/**
 * Everything proposed against this alert and what became of it.
 *
 * @param {{alertId: number, canDecide: boolean}} props
 */
function ActionHistory({ alertId, canDecide }) {
  const { token } = useAuth()
  const { data, error, isLoading } = useQuery({
    queryKey: ['alert-actions', alertId],
    queryFn: () => api.alertActions(token, alertId),
    enabled: token !== null,
    // Polled only while the responder still has something to do, so "In force" or
    // "Lifted" appears without a reload and a settled list costs nothing.
    refetchInterval: (query) =>
      (query.state.data ?? []).some((action) => MOVING.has(action.status)) ? 5000 : false,
  })

  return (
    <Panel
      title="What was done about it"
      description="Blocks and other responses proposed for this alert, and where each one stands."
      tour="responses"
    >
      {error ? (
        <ErrorNotice error={error} />
      ) : isLoading ? (
        <p className="text-ink-dim">Loading responses...</p>
      ) : data && data.length > 0 ? (
        <ul className="divide-y divide-line" data-testid="alert-actions">
          {data.map((action) => (
            <ActionRow key={action.action_id} action={action} canDecide={canDecide} alertId={alertId} />
          ))}
        </ul>
      ) : (
        <p className="text-ink-dim">No response has been proposed for this alert.</p>
      )}
    </Panel>
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
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['pending-actions'] })
      void queryClient.invalidateQueries({ queryKey: ['alert-actions', id] })
    },
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
                  <InputFeatures features={explanation.features} />
                </div>
                <div className="mt-6 border-t border-line pt-5">
                  <h3 className="text-sm font-bold text-ink-dim">What each model said</h3>
                  <ul className="mt-3 grid gap-3 sm:grid-cols-2">
                    {Object.entries(explanation.model_scores).map(([tier, score]) => (
                      <li key={tier}>
                        <div className="flex items-baseline justify-between gap-3">
                          <span>
                            {tierName(tier)}
                            {isWatchingOnly(tier) && (
                              <span className="ml-2 text-[0.8125rem] text-ink-faint">watching only</span>
                            )}
                          </span>
                          <span className="numeric font-bold">{(score * 100).toFixed(0)}%</span>
                        </div>
                        <span className="mt-1 block h-1.5 overflow-hidden rounded-full bg-sunk">
                          <span
                            className={`severity-bar block h-full rounded-full ${isWatchingOnly(tier) ? 'bg-ink-faint' : 'bg-accent'}`}
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

          <ActionHistory alertId={id} canDecide={can(PERMISSIONS.approvalsDecide)} />

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

          {alert.corroborated_by_alert_id != null && (
            <Panel
              title="Confirmed by a signature"
              description="A Suricata rule matched traffic between the same two addresses at the same time, so this alert was raised one severity level."
            >
              <Link
                to={`/alerts/${alert.corroborated_by_alert_id}`}
                viewTransition
                className="font-semibold text-accent hover:underline"
              >
                Signature alert {alert.corroborated_by_alert_id}
              </Link>
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
