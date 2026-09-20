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
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'

import { api } from '../api/client'
import { PERMISSIONS } from '../api/types'
import { useAuth } from '../auth/AuthContext'
import { ErrorNotice } from '../components/ErrorNotice'

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
    <li
      className="rounded border border-[var(--color-line)] bg-[var(--color-panel)] p-4"
      data-testid={`action-${action.action_id}`}
    >
      <div className="flex flex-wrap items-baseline gap-2">
        <span className="text-sm font-semibold">
          {ACTION_LABEL[action.action_type] ?? action.action_type}
        </span>
        <code className="numeric rounded bg-[var(--color-panel-raised)] px-1.5 py-0.5 text-xs">
          {action.target}
        </code>
        <a
          href={`/alerts/${action.alert_id}`}
          className="ml-auto text-xs text-[var(--color-accent)] hover:underline"
        >
          alert {action.alert_id}
        </a>
      </div>

      {canDecide ? (
        <div className="mt-3 space-y-2">
          <label className="block">
            <span className="text-[11px] uppercase tracking-wide text-[var(--color-ink-faint)]">
              Comment (required to reject)
            </span>
            <textarea
              value={comment}
              onChange={(event) => setComment(event.target.value)}
              rows={2}
              placeholder="Why is this the right call?"
              className="mt-1 w-full rounded border border-[var(--color-line)] bg-[var(--color-surface)] p-2 text-sm"
              aria-label={`Comment on action ${action.action_id}`}
            />
          </label>

          <div className="flex gap-2">
            <button
              type="button"
              disabled={pending}
              onClick={() => onDecide('approved', comment.trim() || null)}
              className="rounded bg-[var(--color-sev-high)] px-3 py-1.5 text-xs font-semibold text-[#1b0d0c] disabled:opacity-50"
            >
              Approve
            </button>
            <button
              type="button"
              disabled={pending || !rejectionReady}
              title={rejectionReady ? undefined : 'A rejection requires a comment explaining it'}
              onClick={() => onDecide('rejected', comment.trim())}
              className="rounded border border-[var(--color-line)] px-3 py-1.5 text-xs disabled:opacity-40"
            >
              Reject
            </button>
          </div>
          <p className="text-[11px] text-[var(--color-ink-faint)]">
            Approving authorises this action. It is carried out by the response executor
            afterwards, not by this button.
          </p>
        </div>
      ) : (
        <p className="mt-3 text-xs text-[var(--color-ink-faint)]">
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
    <section>
      <h1 className="mb-3 text-lg font-semibold">Approval queue</h1>

      {error && <ErrorNotice error={error} />}
      {decide.error && <ErrorNotice error={decide.error} />}

      {isLoading && <p className="text-sm text-[var(--color-ink-dim)]">Loading queue...</p>}

      {data && data.length === 0 && (
        <p className="rounded border border-[var(--color-line)] bg-[var(--color-panel)] p-4 text-sm text-[var(--color-ink-dim)]">
          Nothing is waiting for a decision.
        </p>
      )}

      {data && data.length > 0 && (
        <ul className="space-y-3">
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
