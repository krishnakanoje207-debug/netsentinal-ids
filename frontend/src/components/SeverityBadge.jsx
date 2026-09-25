import { SEVERITY_MEANING, STATUS_MEANING } from '../lib/glossary'

/**
 * Severity as a filled plate, like the coloured tag on a departures board. The same
 * plate on the board, in the feed, on the detail page and in the approvals, so a
 * severity is recognised by shape and colour before it is read.
 */
const SEVERITY_CLASS = {
  critical: 'bg-fill-critical text-white',
  high: 'bg-fill-high text-[#0f141a]',
  medium: 'bg-fill-medium text-[#0f141a]',
  low: 'bg-fill-low text-[#0f141a]',
  info: 'bg-fill-info text-ink',
}

/** @param {{severity: import('../api/types').Severity, className?: string}} props */
export function SeverityBadge({ severity, className = '' }) {
  return (
    <span
      className={`inline-flex h-[1.375rem] min-w-[4.75rem] items-center justify-center rounded-[3px] px-1.5 text-[0.6875rem] font-bold uppercase tracking-[0.06em] ${SEVERITY_CLASS[severity]} ${className}`}
      data-testid="severity-badge"
      title={SEVERITY_MEANING[severity]}
    >
      {severity}
    </span>
  )
}

const STATUS_LABEL = {
  new: 'New',
  triaging: 'Triaging',
  escalated: 'Escalated',
  closed_true_positive: 'Closed - true positive',
  closed_false_positive: 'Closed - false positive',
}

/** Short enough for a board column; the full label is on hover. */
const STATUS_SHORT = {
  new: 'New',
  triaging: 'Triaging',
  escalated: 'Escalated',
  closed_true_positive: 'Confirmed',
  closed_false_positive: 'False alarm',
}

/** @param {import('../api/types').AlertStatus} status */
export function statusLabel(status) {
  return STATUS_LABEL[status] ?? status
}

/**
 * A lamp and a word. Open alerts light the lamp; closed ones leave it dark.
 *
 * @param {{status: import('../api/types').AlertStatus, onBoard?: boolean}} props
 */
export function StatusPill({ status, onBoard = false }) {
  const closed = status.startsWith('closed_')
  const lamp =
    status === 'new'
      ? 'bg-attention'
      : status === 'triaging'
        ? 'bg-sev-info'
        : status === 'escalated'
          ? 'bg-signal'
          : 'bg-transparent border border-current opacity-60'
  return (
    <span
      className={`inline-flex items-center gap-1.5 whitespace-nowrap text-[0.8125rem] ${
        onBoard ? (closed ? 'text-board-dim' : 'text-board-ink') : closed ? 'text-ink-faint' : 'text-ink-dim'
      }`}
      data-testid="status-pill"
      title={`${statusLabel(status)}: ${STATUS_MEANING[status]}`}
    >
      <span className={`inline-block size-2 shrink-0 rounded-full ${lamp}`} aria-hidden="true" />
      {STATUS_SHORT[status] ?? statusLabel(status)}
    </span>
  )
}
