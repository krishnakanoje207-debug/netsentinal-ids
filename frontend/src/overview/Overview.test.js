/**
 * The overview's opening sentence is the one thing on the page everybody reads, so what
 * it may and may not claim is pinned here.
 */

import { describe, expect, it } from 'vitest'

import { headline } from './Overview'

const SUMMARY = {
  total: 135,
  by_severity: { critical: 134, low: 1 },
  by_status: { new: 130, triaging: 2, closed_true_positive: 3 },
  top_sources: [],
}

describe('headline', () => {
  it('counts threats, the critical ones and the ones still open', () => {
    expect(headline(SUMMARY, undefined)).toBe(
      '135 threats have been detected, 134 of them critical. 132 alerts are still open.',
    )
  })

  it('says how many blocks wait for a decision when it knows', () => {
    expect(headline(SUMMARY, 2)).toContain('2 blocks are waiting for an analyst to approve or reject.')
    expect(headline(SUMMARY, 1)).toContain('1 block is waiting')
    expect(headline(SUMMARY, 0)).toContain('No blocks are waiting for a decision.')
  })

  it('never reads an empty database as all clear', () => {
    const sentence = headline({ total: 0, by_severity: {}, by_status: {}, top_sources: [] }, 0)
    expect(sentence).toContain('No threats have been detected yet')
    expect(sentence).not.toMatch(/safe|clear|secure/i)
  })

  it('leaves out the critical clause when there are none', () => {
    expect(headline({ ...SUMMARY, by_severity: { low: 135 } }, undefined)).toBe(
      '135 threats have been detected. 132 alerts are still open.',
    )
  })
})
