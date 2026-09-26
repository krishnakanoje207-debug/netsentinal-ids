/** Score keys read as the detectors' plain names, including models kept in shadow. */

import { describe, expect, it } from 'vitest'

import { isWatchingOnly, tierName } from './glossary'

describe('tierName', () => {
  it('names a tier by what it does', () => {
    expect(tierName('tier_a')).toBe('Pattern classifier')
    expect(tierName('tier_d')).toBe('Anomaly detector')
  })

  it('names a second model of a tier in plain words, not by its identifier', () => {
    expect(tierName('tier_d_isolation_forest')).toBe('Anomaly detector (isolation forest)')
  })

  it('leaves a key it does not recognise as it is', () => {
    expect(tierName('suricata')).toBe('suricata')
  })
})

describe('isWatchingOnly', () => {
  it('is false for the tier key, which the deciding model is scored under', () => {
    expect(isWatchingOnly('tier_a')).toBe(false)
  })

  it('is true for a model scored under its own name beside the deciding one', () => {
    expect(isWatchingOnly('tier_d_isolation_forest')).toBe(true)
  })
})
