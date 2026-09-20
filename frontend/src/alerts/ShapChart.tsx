/**
 * Why the model said what it said.
 *
 * A diverging horizontal bar chart: bars to the right pushed the verdict toward
 * "attack", bars to the left toward "benign". Ordering is by absolute contribution, so
 * a strong exculpatory feature ranks alongside a strong incriminating one - an analyst
 * needs to see what argued *against* the alert as much as what argued for it.
 *
 * Feature names come from the API, which takes them from the contract, so this chart
 * can never display a feature that does not exist.
 */

import { Bar, BarChart, Cell, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

export interface Contribution {
  feature: string
  value: number
}

/** Default number of features shown; the rest are summarised as a remainder. */
export const DEFAULT_LIMIT = 10

/**
 * Rank contributions by absolute magnitude, strongest first.
 *
 * Ties break on the feature name so the order is stable between renders - a chart that
 * reshuffles on every poll is unreadable.
 */
export function rankContributions(
  contributions: Record<string, number>,
  limit: number = DEFAULT_LIMIT,
): Contribution[] {
  return Object.entries(contributions)
    .map(([feature, value]) => ({ feature, value }))
    .sort((a, b) => {
      const byMagnitude = Math.abs(b.value) - Math.abs(a.value)
      return byMagnitude !== 0 ? byMagnitude : a.feature.localeCompare(b.feature)
    })
    .slice(0, limit)
}

/** Total absolute weight left out of a truncated chart, so nothing is hidden silently. */
export function remainingWeight(
  contributions: Record<string, number>,
  limit: number = DEFAULT_LIMIT,
): number {
  const all = Object.values(contributions).map(Math.abs)
  if (all.length <= limit) return 0
  const shown = rankContributions(contributions, limit).map((c) => Math.abs(c.value))
  const total = all.reduce((sum, v) => sum + v, 0)
  const visible = shown.reduce((sum, v) => sum + v, 0)
  return total - visible
}

const TOWARD_ATTACK = 'var(--color-sev-high)'
const TOWARD_BENIGN = 'var(--color-sev-info)'

export function ShapChart({
  contributions,
  limit = DEFAULT_LIMIT,
}: {
  contributions: Record<string, number>
  limit?: number
}) {
  const data = rankContributions(contributions, limit)
  const omitted = remainingWeight(contributions, limit)

  if (data.length === 0) {
    return (
      <p className="text-sm text-[var(--color-ink-faint)]">
        No feature contributions were recorded for this detection.
      </p>
    )
  }

  return (
    <div data-testid="shap-chart">
      <div className="mb-2 flex items-center gap-4 text-[11px] text-[var(--color-ink-dim)]">
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2 w-3" style={{ background: TOWARD_ATTACK }} />
          pushed toward attack
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2 w-3" style={{ background: TOWARD_BENIGN }} />
          pushed toward benign
        </span>
      </div>

      <ResponsiveContainer width="100%" height={Math.max(160, data.length * 26)}>
        <BarChart data={data} layout="vertical" margin={{ left: 8, right: 16, top: 4, bottom: 4 }}>
          <XAxis
            type="number"
            tick={{ fill: 'var(--color-ink-faint)', fontSize: 11 }}
            axisLine={false}
            tickLine={false}
          />
          <YAxis
            type="category"
            dataKey="feature"
            width={150}
            tick={{ fill: 'var(--color-ink-dim)', fontSize: 11 }}
            axisLine={false}
            tickLine={false}
          />
          {/* Zero is the reference an analyst reads everything against. */}
          <ReferenceLine x={0} stroke="var(--color-line)" />
          <Tooltip
            contentStyle={{
              background: 'var(--color-panel-raised)',
              border: '1px solid var(--color-line)',
              borderRadius: 6,
              fontSize: 12,
            }}
            formatter={(value) => [Number(value ?? 0).toFixed(4), 'SHAP value']}
          />
          <Bar dataKey="value" radius={2} isAnimationActive={false}>
            {data.map((entry) => (
              <Cell
                key={entry.feature}
                fill={entry.value >= 0 ? TOWARD_ATTACK : TOWARD_BENIGN}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>

      {omitted > 0 && (
        <p className="mt-1 text-[11px] text-[var(--color-ink-faint)]" data-testid="shap-omitted">
          {Object.keys(contributions).length - data.length} further features account for{' '}
          {omitted.toFixed(3)} of absolute contribution.
        </p>
      )}
    </div>
  )
}
