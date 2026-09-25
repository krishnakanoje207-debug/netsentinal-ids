/**
 * The human gate, as an interface.
 *
 * Decisions that shaped this screen:
 *
 * - Approving says "approve" and never "block now". The API moves the action to
 *   approved and an executor carries it out afterwards, so a button promising the
 *   traffic has stopped would be lying about what just happened.
 * - A rejection needs a comment, which the API enforces with a 422. The submit button
 *   is disabled until one is written, so the rule is visible before the round trip
 *   rather than as an error afterwards.
 * - Without approvals:decide the buttons are not rendered at all. Showing controls that
 *   can only ever return 403 teaches an analyst to ignore errors.
 * - The reason for the proposal is one hover away: "Why?" previews the alert's reasons
 *   without leaving the queue.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router-dom'

import { api } from '../api/client'
import { PERMISSIONS } from '../api/types'
import { useAuth } from '../auth/AuthContext'
import { AlertPreview } from '../components/Board'
import { ErrorNotice } from '../components/ErrorNotice'
import { HoverCard } from '../components/HoverCard'
import { Prohibit, Scales } from '../components/icons'
import { PageHeader } from '../components/PageHeader'

const ACTION_LABEL = {
  block_ip: 'Block IP address',
  isolate_host: 'Isolate host',
  kill_process: 'Kill process',
  disable_account: 'Disable account',
}

/**
 * @param {{action: import('../api/types').ResponseAction,
 *   onDecide: (decision: import('../api/types').ApprovalDecision,
 *              comment: string | null) => void,
 *   pending: boolean, canDecide: boolean}} props
 */
export function ActionCard({ action, onDecide, pending, canDecide }) {
  const [comment, setComment] = useState('')
  const rejectionReady = comment.trim().length > 0

  return (
    <li className="panel rise-in grid gap-5 p-5 md:grid-cols-[minmax(0,1fr)_minmax(0,22rem)] md:p-6" data-testid={`action-${action.action_id}`}>
      <div className="flex items-start gap-4">
        <span className="sign-square mt-0.5 size-11 shrink-0 border-sev-critical text-sev-critical" aria-hidden="true">
          <Prohibit size={22} weight="bold" />
        </span>
        <div className="min-w-0">
          <p className="text-lg font-extrabold tracking-tight">
            {ACTION_LABEL[action.action_type] ?? action.action_type}
          </p>
          <p className="mt-1">
            <code className="data rounded bg-sunk px-2 py-1 text-base">{action.target}</code>
          </p>
          {action.action_type === 'block_ip' && (
            <p className="mt-3 text-[0.9375rem] text-ink-dim">
              If approved, this address is blocked at the network edge. The block lifts on its own
              after a few hours, or earlier if someone rolls it back.
            </p>
          )}
          <HoverCard as="span" className="mt-3 inline-block" content={() => <AlertPreview alertId={action.alert_id} />}>
            <Link
              to={`/alerts/${action.alert_id}`}
              viewTransition
              className="text-sm font-semibold text-accent underline decoration-accent/35 hover:decoration-accent"
            >
              Why? See alert {action.alert_id}
            </Link>
          </HoverCard>
        </div>
      </div>

      {canDecide ? (
        <div className="space-y-3 md:border-l md:border-line md:pl-5">
          <label className="block">
            <span className="text-[0.8125rem] font-semibold text-ink-dim">Comment (required to reject)</span>
            <textarea
              value={comment}
              onChange={(event) => setComment(event.target.value)}
              rows={2}
              placeholder="Why is this the right call?"
              className="mt-1.5 w-full rounded-md border border-line-strong bg-panel p-2.5 text-[0.9375rem] transition-colors duration-150 hover:border-ink-faint"
              aria-label={`Comment on action ${action.action_id}`}
            />
          </label>

          <div className="flex gap-2">
            <button
              type="button"
              disabled={pending}
              onClick={() => onDecide('approved', comment.trim() || null)}
              className="press h-10 flex-1 rounded-md bg-fill-critical px-4 text-sm font-bold text-white hover:brightness-110 disabled:opacity-50"
            >
              Approve
            </button>
            <button
              type="button"
              disabled={pending || !rejectionReady}
              title={rejectionReady ? undefined : 'A rejection requires a comment explaining it'}
              onClick={() => onDecide('rejected', comment.trim())}
              className="control press h-10 flex-1 font-semibold disabled:opacity-40"
            >
              Reject
            </button>
          </div>
          <p className="text-[0.8125rem] text-ink-faint">
            Approving authorises this action. It is carried out by the response executor
            afterwards, not by this button.
          </p>
        </div>
      ) : (
        <p className="self-center text-[0.9375rem] text-ink-faint md:border-l md:border-line md:pl-5">
          Your role cannot decide on responses.
        </p>
      )}
    </li>
  )
}

export function ApprovalQueue() {
  const { token, can } = useAuth()
  const queryClient = useQueryClient()
  const canDecide = can(PERMISSIONS.approvalsDecide)

  const { data, error, isLoading } = useQuery({
    queryKey: ['pending-actions'],
    queryFn: () => api.pendingActions(token),
    enabled: token !== null,
    refetchInterval: 5000,
  })

  const decide = useMutation({
    mutationFn: ({ actionId, decision, comment }) =>
      api.decide(token, actionId, decision, comment),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['pending-actions'] })
    },
  })

  return (
    <section data-tour="approvals">
      <PageHeader
        icon={Scales}
        title="Approvals"
        description="Blocks proposed by an administrator wait here. An analyst approves or rejects each one, and nothing is blocked until then. No one can approve their own proposal."
      />

      {error && <ErrorNotice error={error} />}
      {decide.error && <ErrorNotice error={decide.error} />}

      {isLoading && <p className="text-ink-dim">Loading queue...</p>}

      {data && data.length === 0 && (
        <p className="panel p-6 text-[0.9375rem] text-ink-dim">
          Nothing is waiting for a decision. When an administrator proposes a block, it appears
          here until an analyst approves or rejects it.
        </p>
      )}

      {data && data.length > 0 && (
        <ul className="space-y-4">
          {data.map((action) => (
            <ActionCard
              key={action.action_id}
              action={action}
              pending={decide.isPending}
              canDecide={canDecide}
              onDecide={(decision, comment) =>
                decide.mutate({ actionId: action.action_id, decision, comment })
              }
            />
          ))}
        </ul>
      )}
    </section>
  )
}
