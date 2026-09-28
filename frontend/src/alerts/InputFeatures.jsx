/**
 * The exact values the verdict was computed from, so the explanation above can be checked
 * against the traffic it explains.
 *
 * Collapsed by default: seventy-odd numbers are evidence to consult, not to read first.
 * Detections stored before the values were recorded have none, and say so rather than
 * showing an empty table.
 */

import { featureLabel } from '../lib/glossary'

/** A value as an analyst would read it: whole numbers whole, fractions to three places. */
export function formatValue(value) {
  if (value !== 0 && Math.abs(value) < 0.001) return value.toExponential(2)
  return value.toLocaleString(undefined, { maximumFractionDigits: 3 })
}

/** @param {{features: Record<string, number> | null | undefined}} props */
export function InputFeatures({ features }) {
  if (!features) {
    return (
      <p className="text-[0.9375rem] text-ink-dim" data-testid="features-not-recorded">
        Input values were not recorded for this alert: it was stored before the system kept them.
      </p>
    )
  }
  // The contract order does not survive JSONB, so sort by name, numbers read as numbers.
  const rows = Object.entries(features).sort(([a], [b]) => a.localeCompare(b, undefined, { numeric: true }))
  return (
    <details data-testid="input-features">
      <summary className="cursor-pointer text-sm font-bold text-ink-dim">
        Input features ({rows.length} values the models were given)
      </summary>
      <table className="mt-3 w-full text-[0.875rem]">
        <tbody className="divide-y divide-line">
          {rows.map(([name, value]) => (
            <tr key={name}>
              <th scope="row" className="py-1 pr-3 text-left font-normal">
                {featureLabel(name)} <span className="data text-ink-faint">{name}</span>
              </th>
              <td className="numeric py-1 text-right">{formatValue(value)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </details>
  )
}
