/**
 * The registry row is where a promotion decision is read off the screen, so the
 * rules it has to keep are tested directly: a metric with nothing behind it is a
 * dash rather than a zero, a refusal is shown as the sentence the API wrote, and
 * without models:deploy there is no button at all.
 */

import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { ModelRow, metric } from './ModelsPage'

const EVIDENCE = {
  scored: 420,
  labelled: 60,
  unlabelled: 360,
  true_positives: 20,
  false_positives: 0,
  false_negatives: 0,
  precision: 1,
  recall: 1,
  f1: 1,
  average_precision: 1,
  false_positives_per_day: 0,
  days: 8,
}

const CANDIDATE = {
  model_id: 2,
  name: 'tier-a-lgbm',
  tier: 'A',
  version: '1.1.0',
  threshold: 0.5,
  mode: 'shadow',
  pr_auc: 0.94,
  deployed_at: null,
  evidence: EVIDENCE,
  blocked_by: null,
}

function setup(model = CANDIDATE, canDeploy = true) {
  const onPromote = vi.fn()
  render(
    <table>
      <tbody>
        <ModelRow model={model} canDeploy={canDeploy} pending={false} onPromote={onPromote} />
      </tbody>
    </table>,
  )
  return { onPromote, user: userEvent.setup() }
}

describe('metric', () => {
  it('renders a dash when there is nothing behind the number', () => {
    // "No evidence" and "came out at zero" are different findings, and a page that
    // renders both as 0.000 makes an argument the data does not support.
    expect(metric(null)).toBe('--')
    expect(metric(undefined)).toBe('--')
    expect(metric(0)).toBe('0.000')
  })
})

describe('ModelRow', () => {
  it('names the model, its tier and what it is doing', () => {
    setup()
    expect(screen.getByText('tier-a-lgbm')).toBeInTheDocument()
    expect(screen.getByText('1.1.0')).toBeInTheDocument()
    expect(screen.getByTestId('mode-badge')).toHaveTextContent('shadow')
  })

  it('shows unlabelled volume beside precision', () => {
    setup()
    // A tier that fires constantly on flows no one opens reads as perfect precision
    // and is not, so the count that exposes that must be on the row.
    expect(screen.getByText('360')).toBeInTheDocument()
    expect(screen.getByText('60')).toBeInTheDocument()
  })

  it('promotes a candidate that has earned it', async () => {
    const { user, onPromote } = setup()
    const promote = screen.getByRole('button', { name: 'Promote' })

    expect(promote).toBeEnabled()
    await user.click(promote)
    expect(onPromote).toHaveBeenCalled()
  })

  it('says why a candidate cannot be promoted, rather than only disabling', async () => {
    const reason = '19 labelled detection(s), and 50 are required'
    setup({ ...CANDIDATE, blocked_by: reason })

    expect(screen.getByRole('button', { name: 'Promote' })).toBeDisabled()
    // The sentence, not a tooltip alone: it tells the engineer to keep triaging
    // rather than to go looking for a flag to override.
    expect(screen.getByTestId('blocked-reason')).toHaveTextContent(reason)
  })

  it('offers nothing to an account that cannot deploy', () => {
    setup(CANDIDATE, false)
    // Rendering a button that can only ever return 403 teaches people to ignore
    // errors.
    expect(screen.queryByRole('button', { name: 'Promote' })).not.toBeInTheDocument()
  })

  it('does not offer to promote the model that is already deciding', () => {
    setup({ ...CANDIDATE, model_id: 1, mode: 'active', blocked_by: 'already active' })

    expect(screen.queryByRole('button', { name: 'Promote' })).not.toBeInTheDocument()
    // Nor does it report the incumbent as having failed an evidential bar.
    expect(screen.queryByTestId('blocked-reason')).not.toBeInTheDocument()
  })

  it('renders a model nobody could compute metrics for without inventing zeros', () => {
    setup({
      ...CANDIDATE,
      evidence: {
        ...EVIDENCE,
        labelled: 0,
        precision: null,
        recall: null,
        average_precision: null,
        false_positives_per_day: null,
      },
    })

    expect(screen.getAllByText('--')).toHaveLength(4)
  })
})
