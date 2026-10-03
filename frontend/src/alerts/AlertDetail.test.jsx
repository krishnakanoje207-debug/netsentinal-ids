/**
 * The alert page has to be readable by someone who has never seen the system, and has
 * to offer each account exactly the actions it holds - no buttons that would only come
 * back as a 403, and a sentence instead of an empty space for an account that holds none.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { AlertDetail, whatHappened } from './AlertDetail'
import { AuthProvider } from '../auth/AuthContext'

const ALERT = {
  alert_id: 7,
  source: 'nf-replay',
  severity: 'critical',
  status: 'new',
  src_ip: '175.45.176.0',
  dst_ip: '149.171.126.12',
  mitre_technique: null,
  created_at: '2026-09-23T11:38:05Z',
  detection_id: 7,
  ioc_values: [],
  corroborated_by_alert_id: null,
  explanation: {
    risk_score: 0.994,
    model_scores: { tier_a: 0.99, tier_d: 0.96 },
    feature_contributions: { l4_dst_port: 8.0, pkt_rate: 5.5, duration_ms: 2.3, proto: -0.1 },
    top_features: ['l4_dst_port', 'pkt_rate', 'duration_ms', 'proto'],
    shadow: false,
  },
}

const ROLES = {
  analyst: { role: 'soc_analyst', permissions: ['alerts:read', 'alerts:triage', 'approvals:decide'] },
  admin: { role: 'administrator', permissions: ['alerts:read', 'response:propose'] },
  viewer: { role: 'viewer', permissions: ['alerts:read', 'models:read'] },
}

const EXECUTED_BLOCK = {
  action_id: 31,
  alert_id: 7,
  action_type: 'block_ip',
  target: '175.45.176.0',
  status: 'executed',
  executed_at: '2026-09-23T11:45:00Z',
  undoable: true,
  approval: { approval_id: 4, approver_id: 2, decision: 'approved', comment: 'confirmed scan', decided_at: '2026-09-23T11:40:00Z' },
}

/** @param {{status: number, body: object}} [rollback] what the rollback endpoint answers */
function renderAs(account, alert = ALERT, summary = null, actions = [], rollback = undefined) {
  const me = { user_id: 1, username: account, email: 'x@example.test', is_active: true, ...ROLES[account] }
  vi.mocked(fetch).mockImplementation(async (input) => {
    const url = String(input)
    if (url.endsWith('/rollback')) {
      const { status, body } = rollback ?? { status: 200, body: { ...actions[0], status: 'rollback_requested' } }
      return { ok: status < 400, status, statusText: String(status), json: async () => body }
    }
    if (url.endsWith('/actions')) {
      return { ok: true, status: 200, statusText: 'OK', json: async () => actions }
    }
    if (url.endsWith('/summary')) {
      return summary
        ? { ok: true, status: 200, statusText: 'OK', json: async () => summary }
        : { ok: false, status: 404, statusText: 'Not Found', json: async () => ({ detail: 'no summary yet' }) }
    }
    const body = url.includes('/auth/me') ? me : alert
    return { ok: true, status: 200, statusText: 'OK', json: async () => body }
  })
  render(
    <QueryClientProvider client={new QueryClient()}>
      <AuthProvider>
        <MemoryRouter initialEntries={['/alerts/7']}>
          <Routes>
            <Route path="/alerts/:alertId" element={<AlertDetail />} />
          </Routes>
        </MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>,
  )
}

describe('whatHappened', () => {
  it('says who talked to whom, how sure the model was, and why, in words', () => {
    const sentence = whatHappened(ALERT)
    expect(sentence).toContain('traffic from 175.45.176.0 to 149.171.126.12')
    expect(sentence).toContain('99% likely to be an attack')
    expect(sentence).toContain('destination port, packets per second and connection length')
  })

  it('does not invent a score for an alert no model scored', () => {
    const sentence = whatHappened({ ...ALERT, explanation: null })
    expect(sentence).toContain('the nf-replay sensor raised an alert')
    expect(sentence).not.toContain('%')
  })
})

describe('AlertDetail actions', () => {
  beforeEach(() => {
    sessionStorage.setItem('netsentinel.token', 'good-token')
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    sessionStorage.clear()
    vi.unstubAllGlobals()
  })

  it('offers an analyst triage and escalation, but not a block', async () => {
    renderAs('analyst')
    expect(await screen.findByRole('button', { name: /Confirm attack/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /False alarm/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Escalate to incident/ })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Propose blocking/ })).not.toBeInTheDocument()
  })

  it('offers an administrator a block proposal, and no triage', async () => {
    renderAs('admin')
    expect(
      await screen.findByRole('button', { name: /Propose blocking 175.45.176.0/ }),
    ).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Confirm attack/ })).not.toBeInTheDocument()
  })

  it('names the signature alert that confirmed this one, as a link', async () => {
    renderAs('viewer', { ...ALERT, corroborated_by_alert_id: 250 })
    const link = await screen.findByRole('link', { name: 'Signature alert 250' })
    expect(link).toHaveAttribute('href', '/alerts/250')
    expect(screen.getByText('Confirmed by a signature')).toBeInTheDocument()
  })

  it('shows no signature panel when no rule agreed', async () => {
    renderAs('viewer')
    await screen.findByText('Your account can read this alert but not act on it.')
    expect(screen.queryByText('Confirmed by a signature')).not.toBeInTheDocument()
  })

  it('tells a viewer it can read but not act, instead of showing nothing', async () => {
    renderAs('viewer')
    expect(await screen.findByText('Your account can read this alert but not act on it.')).toBeInTheDocument()
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })

  it('names the models in words', async () => {
    renderAs('viewer')
    expect(await screen.findByText('Pattern classifier')).toBeInTheDocument()
    expect(screen.getByText('Anomaly detector')).toBeInTheDocument()
  })

  it('names a technique and says the family model suggested it', async () => {
    renderAs('viewer', { ...ALERT, mitre_technique: 'T1046' })
    expect(await screen.findByText('Network Service Discovery')).toBeInTheDocument()
    expect(screen.getByText('Suggested by the attack-family model')).toBeInTheDocument()
  })

  it('says why there is no technique rather than leaving a bare dash', async () => {
    renderAs('viewer')
    expect(
      await screen.findByText(/not sure enough which kind of attack this is/),
    ).toBeInTheDocument()
  })

  it('shows a valid AI summary, labelled as a model that can be wrong', async () => {
    renderAs('viewer', ALERT, {
      headline: 'Service scan against a web server',
      what_happened: 'One address contacted many ports on one server within seconds.',
      why_it_scored: 'Short, fast connections to the destination port drove the score.',
      assessment: 'likely_malicious',
      next_steps: ['Check whether any probed port answered.'],
      llm_model: 'llama3.2:3b',
    })
    expect(await screen.findByText('Service scan against a web server')).toBeInTheDocument()
    expect(screen.getByText('Likely malicious')).toBeInTheDocument()
    expect(screen.getByText(/It can be wrong/)).toBeInTheDocument()
  })

  it('says plainly when no summary exists', async () => {
    renderAs('viewer')
    expect(await screen.findByText('No AI summary has been written for this alert yet.')).toBeInTheDocument()
  })

  it('lists what was done about the alert, in words, with who approved it', async () => {
    renderAs('viewer', ALERT, null, [EXECUTED_BLOCK])
    const row = await screen.findByTestId('alert-action-31')
    expect(row).toHaveTextContent('Block an address')
    expect(row).toHaveTextContent('In force')
    expect(row).toHaveTextContent('confirmed scan')
    // A viewer reads the history but is offered nothing to do with it.
    expect(screen.queryByRole('button', { name: /Ask to lift/ })).not.toBeInTheDocument()
  })

  it('says so when nothing was proposed, rather than showing an empty panel', async () => {
    renderAs('viewer')
    expect(await screen.findByText('No response has been proposed for this alert.')).toBeInTheDocument()
  })

  it('offers a lift only on an executed action that can be undone', async () => {
    renderAs('analyst', ALERT, null, [
      EXECUTED_BLOCK,
      { ...EXECUTED_BLOCK, action_id: 32, status: 'pending_approval', executed_at: null, approval: null },
      { ...EXECUTED_BLOCK, action_id: 33, action_type: 'kill_process', target: 'agent-1', undoable: false },
    ])
    await screen.findByTestId('alert-action-33')
    expect(screen.getAllByRole('button', { name: /Ask to lift/ })).toHaveLength(1)
    expect(screen.getByTestId('alert-action-33')).toHaveTextContent('This kind of action cannot be undone.')
  })

  it('does not offer a lift to an account that cannot decide on responses', async () => {
    renderAs('admin', ALERT, null, [EXECUTED_BLOCK])
    await screen.findByTestId('alert-action-31')
    expect(screen.queryByRole('button', { name: /Ask to lift/ })).not.toBeInTheDocument()
  })

  it('will not send a lift without a reason, and says it is queued once sent', async () => {
    const user = userEvent.setup()
    renderAs('analyst', ALERT, null, [EXECUTED_BLOCK])
    await user.click(await screen.findByRole('button', { name: /Ask to lift/ }))
    const submit = screen.getByRole('button', { name: 'Request the lift' })
    expect(submit).toBeDisabled()

    await user.type(screen.getByLabelText('Reason for lifting action 31'), 'blocked a partner')
    await user.click(submit)

    expect(await screen.findByRole('status')).toHaveTextContent(
      'Lift requested. It stays in force until the responder lifts it',
    )
    const call = vi.mocked(fetch).mock.calls.find(([url]) => String(url).endsWith('/actions/31/rollback'))
    expect(JSON.parse(call[1].body)).toEqual({ reason: 'blocked a partner' })
  })

  it("shows the API's sentence when the lift is refused", async () => {
    const user = userEvent.setup()
    renderAs('analyst', ALERT, null, [EXECUTED_BLOCK], {
      status: 422,
      body: { detail: 'action 31 is rolled_back, so there is nothing to roll back' },
    })
    await user.click(await screen.findByRole('button', { name: /Ask to lift/ }))
    await user.type(screen.getByLabelText('Reason for lifting action 31'), 'wrong host')
    await user.click(screen.getByRole('button', { name: 'Request the lift' }))
    expect(await screen.findByText(/nothing to roll back/)).toBeInTheDocument()
  })
})
