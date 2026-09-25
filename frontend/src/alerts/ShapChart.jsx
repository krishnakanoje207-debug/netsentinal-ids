/**
 * Why the model said what it said, drawn as opposing pulls.
 *
 * At the top, a tug of war: everything that pulled the verdict toward "attack" against
 * everything that pulled it toward "normal". Below, each measurement's own pull, growing
 * out from one centre line - to the right toward attack, to the left toward normal.
 * Ordering is by absolute contribution, so a strong exculpatory measurement ranks
 * alongside a strong incriminating one: an analyst needs to see what argued against the
 * alert as much as what argued for it.
 *
 * Feature names come from the API, which takes them from the contract, so this chart can
 * never display a feature that does not exist. Every row carries its exact value and
 * meaning on hover and on focus.
 */

import { HoverCard } from '../components/HoverCard'
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

/** The two sides of the tug of war. */
export function pulls(contributions) {
  let toward = 0
  let against = 0
  for (const value of Object.values(contributions)) {
    if (value >= 0) toward += value
    else against -= value
  }
  return { toward, against }
}

/** @param {{contributions: Record<string, number>, limit?: number}} props */
export function ShapChart({ contributions, limit = DEFAULT_LIMIT }) {
  const data = rankContributions(contributions, limit)
  const omitted = remainingWeight(contributions, limit)

  if (data.length === 0) {
    return <p className="text-ink-faint">No feature contributions were recorded for this detection.</p>
  }

  const largest = Math.max(...data.map((entry) => Math.abs(entry.value)))
  const { toward, against } = pulls(contributions)
  const total = toward + against || 1

  return (
    <div data-testid="shap-chart">
      <div className="mb-6">
        <div className="mb-1.5 flex justify-between text-[0.8125rem] font-semibold">
          <span className="text-sev-info">Toward normal {against.toFixed(2)}</span>
          <span className="text-sev-critical">Toward attack {toward.toFixed(2)}</span>
        </div>
        <div
          className="flex h-3.5 overflow-hidden rounded-full bg-sunk"
          role="img"
          aria-label={`Overall, the measurements pulled ${toward.toFixed(2)} toward attack and ${against.toFixed(2)} toward normal.`}
        >
          <span className="h-full bg-sev-info" style={{ width: `${(against / total) * 100}%` }} />
          <span className="h-full w-[3px] bg-panel" aria-hidden="true" />
          <span className="h-full flex-1 bg-fill-critical" />
        </div>
      </div>

      <div className="mb-2 grid grid-cols-[minmax(7rem,11rem)_1fr_1fr] gap-x-2 text-xs font-semibold text-ink-faint" aria-hidden="true">
        <span />
        <span className="text-right">← made it look normal</span>
        <span>made it look like an attack →</span>
      </div>

      <ul className="space-y-1">
        {data.map((entry, index) => {
          const width = largest === 0 ? 0 : (Math.abs(entry.value) / largest) * 100
          const attack = entry.value >= 0
          const meaning = FEATURES[entry.feature]
          return (
            <li key={entry.feature}>
              <HoverCard
                as="div"
                width={280}
                content={() => (
                  <div className="space-y-1">
                    <p className="font-bold">{featureLabel(entry.feature)}</p>
                    {meaning && <p className="text-ink-dim">{meaning.hint}</p>}
                    <p className={`numeric font-semibold ${attack ? 'text-sev-critical' : 'text-sev-info'}`}>
                      Influence {entry.value >= 0 ? '+' : ''}
                      {entry.value.toFixed(3)} {attack ? 'toward attack' : 'toward normal'}
                    </p>
                  </div>
                )}
              >
                <div
                  tabIndex={0}
                  className="grid grid-cols-[minmax(7rem,11rem)_1fr_1fr] items-center gap-x-2 rounded-md py-1 outline-offset-2 transition-colors duration-150 hover:bg-sunk"
                  aria-label={`${featureLabel(entry.feature)}: ${entry.value.toFixed(3)}, ${attack ? 'toward attack' : 'toward normal'}`}
                >
                  <span className="truncate pl-1 text-[0.875rem]">{featureLabel(entry.feature)}</span>
                  <span className="flex h-4 justify-end border-r-2 border-line-strong">
                    {!attack && (
                      <span
                        className="pull-row h-full origin-right rounded-l-[3px] bg-sev-info"
                        style={{ width: `${width}%`, animationDelay: `${index * 40}ms` }}
                      />
                    )}
                  </span>
                  <span className="flex h-4">
                    {attack && (
                      <span
                        className="pull-row h-full origin-left rounded-r-[3px] bg-fill-critical"
                        style={{ width: `${width}%`, animationDelay: `${index * 40}ms` }}
                      />
                    )}
                  </span>
                </div>
              </HoverCard>
            </li>
          )
        })}
      </ul>

      {omitted > 0 && (
        <p className="mt-2 text-[0.8125rem] text-ink-faint" data-testid="shap-omitted">
          {Object.keys(contributions).length - data.length} smaller factors not shown (combined
          influence {omitted.toFixed(3)}).
        </p>
      )}
    </div>
  )
}
