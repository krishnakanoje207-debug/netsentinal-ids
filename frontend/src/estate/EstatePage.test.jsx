/**
 * The estate lists each host with what a scan reported, worst first, and never lets a
 * host with no findings read as a clean one.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { api } from '../api/client'
import { EstatePage, cvssBand } from './EstatePage'

vi.mock('../auth/AuthContext', () => ({ useAuth: () => ({ token: 'a-token' }) }))

const SCANNED = '2026-09-20T10:00:00Z'
const HOSTS = [
  { asset_id: 1, hostname: 'web-01', ip_address: '172.30.0.10', os: 'Ubuntu 24.04', criticality: 'high', last_scanned_at: SCANNED },
  { asset_id: 2, hostname: 'ssh-01', ip_address: '172.30.0.11', os: null, criticality: 'medium', last_scanned_at: SCANNED },
  { asset_id: 3, hostname: 'db-01', ip_address: '172.30.0.12', os: null, criticality: 'low', last_scanned_at: null },
]
const FINDINGS = {
  1: [
    { vuln_id: 1, cve_id: 'CVE-2021-0001', cvss: 5.3, detected_at: '2026-09-20T10:00:00Z' },
    { vuln_id: 2, cve_id: 'CVE-2024-6387', cvss: 9.8, detected_at: '2026-09-20T10:00:00Z' },
    { vuln_id: 3, cve_id: 'CVE-2019-0003', cvss: null, detected_at: '2026-09-20T10:00:00Z' },
  ],
  2: [],
  3: [],
}

function renderPage(onFilter = vi.fn()) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <EstatePage onFilter={onFilter} />
      </MemoryRouter>
    </QueryClientProvider>,
  )
  return onFilter
}

describe('cvssBand', () => {
  it('follows the NVD bands and keeps an unscored finding apart from a zero', () => {
    expect([9.8, 7, 4, 0.1, 0].map(cvssBand)).toEqual(['critical', 'high', 'medium', 'low', 'info'])
    expect(cvssBand(null)).toBeNull()
  })
})

describe('EstatePage', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.spyOn(api, 'assets').mockResolvedValue(HOSTS)
    vi.spyOn(api, 'vulnerabilities').mockImplementation(async (_token, id) => FINDINGS[id])
  })

  it('counts hosts and findings', async () => {
    renderPage()
    expect(await screen.findByTestId('estate-summary')).toHaveTextContent('3 hosts, 3 findings reported.')
  })

  it('says nothing found in the last scan, not clean, for a scanned host with no findings', async () => {
    renderPage()
    const [, ssh] = await screen.findAllByTestId('estate-host')
    expect(await within(ssh).findByText('Nothing found in the last scan')).toBeInTheDocument()
    expect(within(ssh).getByTestId('last-scan')).toHaveTextContent('Last scan')
    expect(within(ssh).getByText('OS not recorded')).toBeInTheDocument()
    expect(screen.queryByText(/clean/i, { selector: 'span' })).not.toBeInTheDocument()
  })

  it('tells an unscanned host apart from a clean one', async () => {
    renderPage()
    const [, , db] = await screen.findAllByTestId('estate-host')
    expect(await within(db).findByText('Not yet scanned')).toBeInTheDocument()
    expect(within(db).queryByText('Nothing found in the last scan')).not.toBeInTheDocument()
    expect(within(db).queryByTestId('last-scan')).not.toBeInTheDocument()
  })

  it('lists findings worst first, with an unscored one as a dash', async () => {
    renderPage()
    const [web] = await screen.findAllByTestId('estate-host')
    await userEvent.setup().click(await within(web).findByRole('button', { name: /3 findings/ }))

    const cves = within(web).getAllByText(/^CVE-/).map((node) => node.textContent)
    expect(cves).toEqual(['CVE-2024-6387', 'CVE-2021-0001', 'CVE-2019-0003'])
    expect(within(web).getByText('not scored by the scan')).toBeInTheDocument()
  })

  it('opens the alerts that name a host', async () => {
    const onFilter = renderPage()
    const [web] = await screen.findAllByTestId('estate-host')
    await userEvent.setup().click(within(web).getByRole('button', { name: /Alerts involving it/ }))

    expect(onFilter).toHaveBeenCalledWith({ status: '', severity: '', q: '172.30.0.10' })
  })
})
