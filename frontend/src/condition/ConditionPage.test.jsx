import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { ConditionPage } from './ConditionPage'

vi.mock('../auth/AuthContext', () => ({ useAuth: () => ({ token: 'test', user: { role: 'administrator', user_id: 1 } }) }))
vi.mock('@tanstack/react-query', () => ({ useQuery: ({ queryKey }) => queryKey[0] === 'endpoint-status'
  ? { dataUpdatedAt: Date.now(), data: { freshness: 'stale', defender: { status: { real_time_enabled: true, reboot_required: false } }, monitoring: { freshness: 'unavailable', latest_capture_at: null }, scans: {} } }
  : { data: { status: 'available', profiles: [{ browser: 'Brave', profile: 'Default', status: 'available', visits: [{ domain: 'example.test', risk: 'No exact URL match; safety remains unassessed' }], downloads: [] }] } }
}))

describe('condition evidence', () => {
  it('keeps stale capture and unknown reputation visible after dashboard refresh', () => {
    render(<ConditionPage />)
    expect(screen.getByText(/Endpoint snapshot: stale/)).toBeInTheDocument()
    expect(screen.getByText(/successful refresh does not mean/)).toBeInTheDocument()
    expect(screen.getByText(/No exact URL match; safety remains unassessed/)).toBeInTheDocument()
    expect(screen.getByText(/Safe Browsing explicit setting: unknown/)).toBeInTheDocument()
  })

  it('shows nested protection settings as readable values', () => {
    render(<ConditionPage />)
    expect(screen.getByText('real time enabled')).toBeInTheDocument()
    expect(screen.getByText('Yes')).toBeInTheDocument()
    expect(screen.getByText('reboot required')).toBeInTheDocument()
    expect(screen.getByText('No')).toBeInTheDocument()
    expect(screen.queryByText(/\{"real_time_enabled"/)).not.toBeInTheDocument()
  })
})
