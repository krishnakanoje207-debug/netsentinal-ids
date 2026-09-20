import type { AlertStatus, Severity } from '../api/types'

const SEVERITY_CLASS: Record<Severity, string> = {
  info: 'border-[var(--color-sev-info)] text-[var(--color-sev-info)]',
  low: 'border-[var(--color-sev-low)] text-[var(--color-sev-low)]',
  medium: 'border-[var(--color-sev-medium)] text-[var(--color-sev-medium)]',
  high: 'border-[var(--color-sev-high)] text-[var(--color-sev-high)]',
  // The only filled badge in the interface, so the worst case is the one thing that
  // draws the eye in a long feed.
  critical: 'border-[var(--color-sev-critical)] bg-[var(--color-sev-critical)] text-[#1b0d0c]',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-block rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${SEVERITY_CLASS[severity]}`}
      data-testid="severity-badge"
    >
      {severity}
    </span>
  )
}

const STATUS_LABEL: Record<AlertStatus, string> = {
  new: 'New',
  triaging: 'Triaging',
  escalated: 'Escalated',
  closed_true_positive: 'Closed - true positive',
  closed_false_positive: 'Closed - false positive',
}

export function statusLabel(status: AlertStatus): string {
  return STATUS_LABEL[status] ?? status
}

export function StatusPill({ status }: { status: AlertStatus }) {
  const closed = status.startsWith('closed_')
  return (
    <span
      className={`whitespace-nowrap text-xs ${closed ? 'text-[var(--color-ink-faint)]' : 'text-[var(--color-ink-dim)]'}`}
      data-testid="status-pill"
    >
      {statusLabel(status)}
    </span>
  )
}
