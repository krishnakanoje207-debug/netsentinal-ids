/**
 * The alert page has to be readable by someone who has never seen the system, and has
 * to offer each account exactly the actions it holds - no buttons that would only come
 * back as a 403, and a sentence instead of an empty space for an account that holds none.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
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

function renderAs(account, alert = ALERT, summary = null) {
  const me = { user_id: 1, username: account, email: 'x@example.test', is_active: true, ...ROLES[account] }
  vi.mocked(fetch).mockImplementation(async (input) => {
    const url = String(input)
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
})
