/**
 * Ranking is the part of the chart that carries meaning, so it is tested apart from the
 * rendering. The ordering rule is by *absolute* contribution: a feature arguing strongly
 * against the alert matters as much to an analyst as one arguing for it.
 */

import { describe, expect, it } from 'vitest'

import { rankContributions, remainingWeight } from './ShapChart'

describe('rankContributions', () => {
  it('orders by absolute magnitude, not by signed value', () => {
    const ranked = rankContributions({ weak: 0.01, negative: -0.8, positive: 0.4 })
    expect(ranked.map((c) => c.feature)).toEqual(['negative', 'positive', 'weak'])
  })

  it('keeps the sign, because direction is the whole point', () => {
    const ranked = rankContributions({ exculpatory: -0.9 })
    expect(ranked[0].value).toBe(-0.9)
  })

  it('breaks ties on the feature name so the order is stable between polls', () => {
    const first = rankContributions({ beta: 0.5, alpha: 0.5, gamma: 0.5 })
    const second = rankContributions({ gamma: 0.5, alpha: 0.5, beta: 0.5 })
    expect(first.map((c) => c.feature)).toEqual(['alpha', 'beta', 'gamma'])
    expect(second.map((c) => c.feature)).toEqual(first.map((c) => c.feature))
  })

  it('truncates to the limit', () => {
    const many = Object.fromEntries(
      Array.from({ length: 30 }, (_, i) => [`feature_${i}`, (i + 1) / 100]),
    )
    expect(rankContributions(many, 5)).toHaveLength(5)
    expect(rankContributions(many, 5)[0].feature).toBe('feature_29')
  })

  it('handles an empty explanation', () => {
    expect(rankContributions({})).toEqual([])
  })
})

describe('remainingWeight', () => {
  it('is zero when everything is shown', () => {
    expect(remainingWeight({ a: 0.5, b: -0.5 }, 10)).toBe(0)
  })

  it('reports the absolute weight left out, so truncation is never silent', () => {
    const omitted = remainingWeight({ a: 1, b: -1, c: 0.25, d: -0.25 }, 2)
    expect(omitted).toBeCloseTo(0.5)
  })
})
