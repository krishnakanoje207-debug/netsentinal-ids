import { SEVERITY_MEANING, STATUS_MEANING } from '../lib/glossary'

const SEVERITY_CLASS = {
  info: 'border-[var(--color-sev-info)] text-[var(--color-sev-info)]',
  low: 'border-[var(--color-sev-low)] text-[var(--color-sev-low)]',
  medium: 'border-[var(--color-sev-medium)] text-[var(--color-sev-medium)]',
  high: 'border-[var(--color-sev-high)] text-[var(--color-sev-high)]',
  // The only filled badge in the interface, so the worst case is the one thing that
  // draws the eye in a long feed.
  critical: 'border-[var(--color-sev-critical)] bg-[var(--color-sev-critical)] text-[#1b0d0c]',
}

/** @param {{severity: import('../api/types').Severity}} props */
export function SeverityBadge({ severity }) {
  return (
    <span
      className={`inline-block rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${SEVERITY_CLASS[severity]}`}
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

/** @param {import('../api/types').AlertStatus} status */
export function statusLabel(status) {
  return STATUS_LABEL[status] ?? status
}

/** @param {{status: import('../api/types').AlertStatus}} props */
export function StatusPill({ status }) {
  const closed = status.startsWith('closed_')
  return (
    <span
      className={`whitespace-nowrap text-xs ${closed ? 'text-[var(--color-ink-faint)]' : 'text-[var(--color-ink-dim)]'}`}
      data-testid="status-pill"
      title={STATUS_MEANING[status]}
    >
      {statusLabel(status)}
    </span>
  )
}
