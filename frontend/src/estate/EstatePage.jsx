/**
 * The estate: the hosts this deployment protects, and what a vulnerability scan found
 * on each.
 *
 * Decisions that shaped this screen:
 *
 * - Findings hang off their host, as they do in the API. "What else is open on this
 *   machine" is the question asked during triage; a flat list of every CVE answers nobody.
 * - A host with no findings says "none reported", never "clean". The scan import does not
 *   record which hosts a scan covered, so an unscanned host and a clean one look the same
 *   here, and the page says so rather than letting one pass for the other.
 * - A finding the scan did not score shows a dash, not a zero, for the reason a missing
 *   risk score is "undecided" elsewhere in the console.
 * - Every host links to the alerts that name its address.
 */

import { useQueries, useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'

import { api } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { ErrorNotice } from '../components/ErrorNotice'
import { ArrowRight, HardDrives } from '../components/icons'
import { PageHeader } from '../components/PageHeader'
import { SeverityBadge } from '../components/SeverityBadge'

/** NVD's CVSS v3 bands, drawn with the console's severity plates. */
export function cvssBand(score) {
  if (score === null || score === undefined) return null
  if (score >= 9) return 'critical'
  if (score >= 7) return 'high'
  if (score >= 4) return 'medium'
  if (score > 0) return 'low'
  return 'info'
}

const CRITICALITY = {
  high: { label: 'High', meaning: 'Losing this host would hurt most. Its alerts come first.' },
  medium: { label: 'Medium', meaning: 'The default when nobody has assessed it.' },
  low: { label: 'Low', meaning: 'Losing this host would matter least.' },
}

function worstFirst(findings) {
  return [...findings].sort((a, b) => (b.cvss ?? -1) - (a.cvss ?? -1))
}

/** @param {{asset: import('../api/types').Asset, findings: import('@tanstack/react-query').UseQueryResult,
 *   onAlerts: (address: string) => void}} props */
function HostRow({ asset, findings, onAlerts }) {
  const [open, setOpen] = useState(false)
  const list = findings.data ? worstFirst(findings.data) : null
  const worst = list?.[0]
  const panelId = `findings-${asset.asset_id}`

  return (
    <li className="border-t border-line first:border-t-0" data-testid="estate-host">
      <div className="grid grid-cols-1 items-center gap-x-4 gap-y-2 px-4 py-3.5 md:grid-cols-[minmax(0,2fr)_minmax(0,1.3fr)_7rem_minmax(0,1.6fr)_auto]">
        <div className="min-w-0">
          <p className="truncate font-semibold">{asset.hostname}</p>
          <p className="numeric text-[0.8125rem] text-ink-dim">{asset.ip_address}</p>
        </div>
        <p className="text-[0.9375rem] text-ink-dim">{asset.os ?? 'OS not recorded'}</p>
        <p className="text-[0.9375rem]" title={CRITICALITY[asset.criticality]?.meaning}>
          <span className="text-[0.75rem] font-bold tracking-[0.06em] text-ink-faint uppercase md:hidden">
            Criticality{' '}
          </span>
          {CRITICALITY[asset.criticality]?.label ?? asset.criticality}
        </p>
        <div className="min-w-0">
          {findings.isLoading && <span className="text-sm text-ink-faint">Reading findings...</span>}
          {findings.error && <span className="text-sm text-sev-critical">Findings could not be read.</span>}
          {list && list.length === 0 && (
            <span className="text-[0.9375rem] text-ink-dim">None reported by a scan</span>
          )}
          {list && list.length > 0 && (
            <button
              type="button"
              aria-expanded={open}
              aria-controls={panelId}
              onClick={() => setOpen((value) => !value)}
              className="press inline-flex items-center gap-2 rounded-md text-left text-[0.9375rem] font-semibold hover:text-accent"
            >
              {worst.cvss !== null && <SeverityBadge severity={cvssBand(worst.cvss)} />}
              <span>
                {list.length} {list.length === 1 ? 'finding' : 'findings'}
                <span className="font-normal text-ink-dim">{open ? ', hide' : ', show'}</span>
              </span>
            </button>
          )}
        </div>
        <button
          type="button"
          onClick={() => onAlerts(asset.ip_address)}
          className="press inline-flex items-center gap-1 justify-self-start text-[0.8125rem] font-semibold text-accent hover:underline md:justify-self-end"
        >
          Alerts involving it <ArrowRight size={14} weight="bold" aria-hidden="true" />
        </button>
      </div>
      {open && list && (
        <ul id={panelId} className="mx-4 mb-4 divide-y divide-line rounded-md border border-line bg-sunk/60">
          {list.map((finding) => (
            <li key={finding.vuln_id} className="flex flex-wrap items-center gap-x-4 gap-y-1 px-3 py-2 text-[0.9375rem]">
              <span className="numeric w-36 font-semibold">{finding.cve_id}</span>
              <span className="numeric w-14 text-right" title="CVSS base score, 0 to 10">
                {finding.cvss === null ? '--' : finding.cvss.toFixed(1)}
              </span>
              {finding.cvss === null ? (
                <span className="text-[0.8125rem] text-ink-faint">not scored by the scan</span>
              ) : (
                <SeverityBadge severity={cvssBand(finding.cvss)} />
              )}
              <span className="text-[0.8125rem] text-ink-dim md:ml-auto">
                seen {new Date(finding.detected_at).toLocaleDateString()}
              </span>
            </li>
          ))}
        </ul>
      )}
    </li>
  )
}

/** @param {{onFilter: (filters: {status: string, severity: string, q: string}) => void}} props */
export function EstatePage({ onFilter }) {
  const { token } = useAuth()
  const navigate = useNavigate()

  const assets = useQuery({
    queryKey: ['assets'],
    queryFn: () => api.assets(token),
    enabled: token !== null,
  })
  const hosts = assets.data ?? []
  const findings = useQueries({
    queries: hosts.map((asset) => ({
      queryKey: ['vulnerabilities', asset.asset_id],
      queryFn: () => api.vulnerabilities(token, asset.asset_id),
      enabled: token !== null,
    })),
  })

  const reported = findings.reduce((sum, result) => sum + (result.data?.length ?? 0), 0)
  const openAlerts = (address) => {
    onFilter({ status: '', severity: '', q: address })
    navigate('/alerts', { viewTransition: true })
  }

  return (
    <section>
      <PageHeader
        icon={HardDrives}
        title="Estate"
        description="The machines this deployment protects, and the known weaknesses a vulnerability scan reported on each. Blocks aimed at these addresses are refused: a host of your own is isolated, not blocked."
      />

      {assets.error && <ErrorNotice error={assets.error} />}
      {assets.isLoading && <p className="text-ink-dim">Loading the estate...</p>}

      {assets.data && hosts.length === 0 && (
        <p className="panel p-6 text-[0.9375rem] text-ink-dim">
          No hosts are recorded yet. Import the inventory with{' '}
          <code className="numeric">netsentinel-import-assets --csv inventory.csv</code>.
        </p>
      )}

      {hosts.length > 0 && (
        <>
          <p className="mb-3 text-[0.9375rem]" data-testid="estate-summary">
            {hosts.length} {hosts.length === 1 ? 'host' : 'hosts'}, {reported}{' '}
            {reported === 1 ? 'finding' : 'findings'} reported.
          </p>
          <div className="panel overflow-hidden" data-tour="estate">
            <div className="hidden grid-cols-[minmax(0,2fr)_minmax(0,1.3fr)_7rem_minmax(0,1.6fr)_auto] gap-x-4 bg-sunk px-4 py-2.5 text-[0.6875rem] font-bold tracking-[0.08em] text-ink-dim uppercase md:grid">
              <span>Host</span>
              <span>Operating system</span>
              <span title="How much losing this host would hurt">Criticality</span>
              <span title="CVEs from the latest Greenbone import, worst first">Scan findings</span>
              <span className="w-32" />
            </div>
            <ul>
              {hosts.map((asset, index) => (
                <HostRow key={asset.asset_id} asset={asset} findings={findings[index]} onAlerts={openAlerts} />
              ))}
            </ul>
          </div>
          <p className="mt-3 max-w-3xl text-[0.8125rem] leading-relaxed text-ink-dim">
            "None reported" is not "clean". Findings come from Greenbone scans, and the import
            does not record which hosts a scan covered, so a host that was never scanned also
            shows none.
          </p>
        </>
      )}
    </section>
  )
}
