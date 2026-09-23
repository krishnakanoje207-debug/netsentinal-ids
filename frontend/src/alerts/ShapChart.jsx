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

import { FEATURES, featureLabel } from '../lib/glossary'

/**
 * @typedef {object} Contribution
 * @property {string} feature
 * @property {number} value
 */

/** Default number of features shown; the rest are summarised as a remainder. */
export const DEFAULT_LIMIT = 10

/**
 * Rank contributions by absolute magnitude, strongest first.
 *
 * Ties break on the feature name so the order is stable between renders - a chart that
 * reshuffles on every poll is unreadable.
 */
export function rankContributions(contributions, limit = DEFAULT_LIMIT) {
  return Object.entries(contributions)
    .map(([feature, value]) => ({ feature, value }))
    .sort((a, b) => {
      const byMagnitude = Math.abs(b.value) - Math.abs(a.value)
      return byMagnitude !== 0 ? byMagnitude : a.feature.localeCompare(b.feature)
    })
    .slice(0, limit)
}

/** Total absolute weight left out of a truncated chart, so nothing is hidden silently. */
export function remainingWeight(contributions, limit = DEFAULT_LIMIT) {
  const all = Object.values(contributions).map(Math.abs)
  if (all.length <= limit) return 0
  const shown = rankContributions(contributions, limit).map((c) => Math.abs(c.value))
  const total = all.reduce((sum, v) => sum + v, 0)
  const visible = shown.reduce((sum, v) => sum + v, 0)
  return total - visible
}

const TOWARD_ATTACK = 'var(--color-sev-high)'
const TOWARD_BENIGN = 'var(--color-sev-info)'

/** @param {{contributions: Record<string, number>, limit?: number}} props */
export function ShapChart({ contributions, limit = DEFAULT_LIMIT }) {
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
          made it look more like an attack
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2 w-3" style={{ background: TOWARD_BENIGN }} />
          made it look more normal
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
            width={180}
            tickFormatter={featureLabel}
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
            labelFormatter={(feature) =>
              FEATURES[feature] ? `${FEATURES[feature].label}: ${FEATURES[feature].hint}` : feature
            }
            formatter={(value) => [Number(value ?? 0).toFixed(3), 'Influence (SHAP)']}
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
          {Object.keys(contributions).length - data.length} smaller factors not shown (combined
          influence {omitted.toFixed(3)}).
        </p>
      )}
    </div>
  )
}
