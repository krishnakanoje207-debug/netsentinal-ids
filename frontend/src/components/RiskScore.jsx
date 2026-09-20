/**
 * Rendering a risk score, and rendering the absence of one.
 *
 * This component exists because of a single rule that runs through the whole system:
 * *undecided is not benign*. The fusion scorer returns no score when only shadow models
 * voted, and the API sends no explanation for alerts that came from Suricata or Wazuh.
 * Painting either as 0% - low, green, reassuring - would invent a conclusion nobody
 * reached. Both render as a dash in neutral grey, with a reason on hover.
 */

/** @typedef {'undecided' | 'low' | 'medium' | 'high' | 'critical'} RiskTone */

/**
 * How a decided score is coloured.
 *
 * @param {number | null | undefined} score
 * @returns {RiskTone}
 */
export function toneFor(score) {
  if (score === null || score === undefined || Number.isNaN(score)) return 'undecided'
  if (score >= 0.9) return 'critical'
  if (score >= 0.7) return 'high'
  if (score >= 0.4) return 'medium'
  return 'low'
}

const TONE_CLASS = {
  undecided: 'text-[var(--color-undecided)]',
  low: 'text-[var(--color-sev-low)]',
  medium: 'text-[var(--color-sev-medium)]',
  high: 'text-[var(--color-sev-high)]',
  critical: 'text-[var(--color-sev-critical)]',
}

/** @param {number | null | undefined} score */
export function formatRisk(score) {
  if (score === null || score === undefined || Number.isNaN(score)) return '--'
  return `${(score * 100).toFixed(0)}%`
}

/**
 * @param {{score: number | null | undefined, shadow?: boolean,
 *   undecidedReason?: string}} props
 */
export function RiskScore({ score, shadow = false, undecidedReason }) {
  const tone = toneFor(score)
  const undecided = tone === 'undecided'

  const title = undecided
    ? (undecidedReason ?? 'No active model scored this flow, so no risk was determined.')
    : shadow
      ? 'Scored in shadow mode: logged for comparison, not acted on.'
      : undefined

  return (
    <span className="inline-flex items-center gap-1.5" title={title}>
      <span
        className={`numeric font-semibold ${TONE_CLASS[tone]}`}
        data-testid="risk-value"
        data-tone={tone}
      >
        {formatRisk(score)}
      </span>
      {undecided && (
        <span className="text-[10px] uppercase tracking-wide text-[var(--color-ink-faint)]">
          undecided
        </span>
      )}
      {!undecided && shadow && (
        <span
          className="rounded border border-[var(--color-line)] px-1 text-[10px] uppercase tracking-wide text-[var(--color-ink-dim)]"
          data-testid="shadow-badge"
        >
          shadow
        </span>
      )}
    </span>
  )
}
