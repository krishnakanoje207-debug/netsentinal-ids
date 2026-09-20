/**
 * The approval card is the interface to the human gate, so its rules are tested directly:
 * a rejection cannot be submitted without a comment, the controls are absent entirely
 * without permission, and the approve button never claims the block has happened.
 */

import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import type { ResponseAction } from '../api/types'
import { ActionCard } from './ApprovalQueue'

const ACTION: ResponseAction = {
  action_id: 500,
  alert_id: 100,
  action_type: 'block_ip',
  target: '203.0.113.9',
  status: 'pending_approval',
  executed_at: null,
  approval: null,
}

function setup(canDecide = true) {
  const onDecide = vi.fn()
  render(
    <ActionCard action={ACTION} onDecide={onDecide} pending={false} canDecide={canDecide} />,
  )
  return { onDecide, user: userEvent.setup() }
}

describe('ActionCard', () => {
  it('shows what would be done and to what', () => {
    setup()
    expect(screen.getByText('Block IP address')).toBeInTheDocument()
    expect(screen.getByText('203.0.113.9')).toBeInTheDocument()
  })

  it('cannot reject without a comment', async () => {
    setup()
    const reject = screen.getByRole('button', { name: 'Reject' })
    expect(reject).toBeDisabled()
    expect(reject).toHaveAttribute('title', 'A rejection requires a comment explaining it')
  })

  it('enables rejection once a reason is written', async () => {
    const { user, onDecide } = setup()
    await user.type(screen.getByLabelText('Comment on action 500'), 'known scanner')

    const reject = screen.getByRole('button', { name: 'Reject' })
    expect(reject).toBeEnabled()
    await user.click(reject)
    expect(onDecide).toHaveBeenCalledWith('rejected', 'known scanner')
  })

  it('treats whitespace as no comment at all', async () => {
    const { user } = setup()
    await user.type(screen.getByLabelText('Comment on action 500'), '   ')
    expect(screen.getByRole('button', { name: 'Reject' })).toBeDisabled()
  })

  it('allows approval without a comment', async () => {
    const { user, onDecide } = setup()
    await user.click(screen.getByRole('button', { name: 'Approve' }))
    // An approval can stand on the evidence in the alert; a rejection cannot.
    expect(onDecide).toHaveBeenCalledWith('approved', null)
  })

  it('passes a trimmed comment along with an approval', async () => {
    const { user, onDecide } = setup()
    await user.type(screen.getByLabelText('Comment on action 500'), '  confirmed scan  ')
    await user.click(screen.getByRole('button', { name: 'Approve' }))
    expect(onDecide).toHaveBeenCalledWith('approved', 'confirmed scan')
  })

  it('does not claim the action has been carried out', () => {
    setup()
    // The API only marks it approved; an executor acts afterwards. A button saying
    // "Block now" would describe something that has not happened.
    expect(screen.queryByRole('button', { name: /block now/i })).not.toBeInTheDocument()
    expect(screen.getByText(/carried out by the response executor/i)).toBeInTheDocument()
  })

  it('renders no decision controls without permission', () => {
    setup(false)
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Reject' })).not.toBeInTheDocument()
    expect(screen.getByText('Your role cannot decide on responses.')).toBeInTheDocument()
  })

  it('disables both buttons while a decision is in flight', () => {
    render(
      <ActionCard action={ACTION} onDecide={vi.fn()} pending canDecide />,
    )
    expect(screen.getByRole('button', { name: 'Approve' })).toBeDisabled()
  })
})
