import { useQuery } from '@tanstack/react-query'
import { request } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { ErrorNotice } from '../components/ErrorNotice'
import { PageHeader } from '../components/PageHeader'

const when = (value) => value ? new Date(value).toLocaleString() : 'Unavailable'

function EvidenceValues({ value }) {
  if (value == null) return 'Unknown'
  if (typeof value === 'boolean') return value ? 'Yes' : 'No'
  if (Array.isArray(value)) return value.length
    ? <ul className="space-y-3">{value.map((item, index) => <li key={index}><EvidenceValues value={item} /></li>)}</ul>
    : 'No records'
  if (typeof value !== 'object') return String(value)
  return <dl className="space-y-2 text-sm">{Object.entries(value).map(([key, item]) =>
    <div key={key} className="flex flex-wrap justify-between gap-2 border-b border-line pb-2">
      <dt className="text-ink-dim">{key.replaceAll('_', ' ')}</dt>
      <dd className="max-w-full break-words">{key.endsWith('_at') && item
        ? when(item) : <EvidenceValues value={item} />}</dd>
    </div>)}</dl>
}

function Evidence({ title, value }) {
  return <section className="rounded-lg border border-line bg-panel p-5">
    <h2 className="mb-3 text-lg font-bold">{title}</h2>
    {value ? <EvidenceValues value={value} /> : <p className="text-ink-dim">No observation available.</p>}
  </section>
}

export function ConditionPage() {
  const { token, user } = useAuth()
  const isAdmin = user?.role === 'administrator'
  const endpoint = useQuery({ queryKey: ['endpoint-status', user?.user_id], queryFn: () => request('/endpoint/status', { token }), refetchInterval: 10000 })
  const browser = useQuery({ queryKey: ['browser-audit', user?.user_id], queryFn: () => request('/browser-audit', { token }), enabled: isAdmin, refetchInterval: 30000, gcTime: 0 })
  const data = endpoint.data
  return <>
    <PageHeader title="This PC · current condition" description="Local protection, capture freshness, and browser observations with their evidence and limits." />
    <p className="mb-5 text-sm text-ink-dim">Dashboard fetched: {when(endpoint.dataUpdatedAt)}. A successful refresh does not mean the sensor has captured new traffic.</p>
    {endpoint.error && <ErrorNotice error={endpoint.error} />}
    {endpoint.isPending && <p role="status">Loading endpoint observations…</p>}
    {data && <>
      <div className="mb-5 rounded-lg border border-line p-4">
        <p className="font-bold">Endpoint snapshot: {data.freshness} · collected {when(data.collected_at)}</p>
        <p className="mt-2 text-sm text-ink-dim">{data.limitation}</p>
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        <Evidence title="Windows Defender" value={data.defender} />
        <Evidence title="Browser warning settings · SmartScreen" value={data.smart_screen} />
        <Evidence title="Network capture" value={data.monitoring} />
        <Evidence title="Download folder scan" value={data.scans?.downloads} />
        <Evidence title="Defender quick scan" value={data.scans?.quick} />
        <Evidence title="Defender threat observations" value={data.threats} />
        <Evidence title="Configured download folders" value={data.download_locations} />
        <Evidence title="Configured download folder scans" value={data.scans?.configured_downloads} />
      </div>
    </>}
    <section className="mt-8">
      <h2 className="text-xl font-bold">Browser history and downloads</h2>
      <p className="mt-2 text-sm text-ink-dim">A local audit of recorded activity. Pre-transfer decisions remain with your browser and Windows protection. Files are not uploaded for analysis.</p>
      {!isAdmin && <p className="mt-4">Personal browser observations require a local administrator account.</p>}
      {isAdmin && browser.isPending && <p role="status">Reading local browser metadata…</p>}
      {browser.error && <ErrorNotice error={browser.error} />}
      {browser.data && <>
        <p className="my-3 text-sm">Audit: {browser.data.status} · observed {when(browser.data.observed_at)}. {browser.data.reason}</p>
        <p className="text-sm text-ink-dim">{browser.data.scope}</p>
        <p className="mt-2 text-sm">Default HTTPS browser: {browser.data.default_https_browser ?? 'Unknown'}</p>
        <p className="my-3 text-sm text-ink-dim">{browser.data.limitations}</p>
        <Evidence title="Local phishing comparison source" value={browser.data.site_risk_feed} />
        {browser.data.profiles.map((profile) => <article key={`${profile.browser}:${profile.profile}`} className="mb-4 rounded-lg border border-line bg-panel p-5">
          <h3 className="font-bold">{profile.browser} · {profile.profile} · {profile.status}</h3>
          <p className="my-2 text-xs text-ink-dim">Observed {when(profile.observed_at)}. {profile.provenance}</p>
          <p className="my-2 text-xs text-ink-dim">Safe Browsing explicit setting: {profile.safe_browsing?.enabled_preference == null ? 'unknown' : String(profile.safe_browsing.enabled_preference)}. {profile.safe_browsing?.meaning}</p>
          {profile.error && <p className="mt-2">{profile.error}</p>}
          <div className="mt-4 grid gap-6 lg:grid-cols-2">
            <div><h4 className="font-semibold">Recently recorded sites</h4>
              {!profile.visits.length && <p className="mt-2 text-sm text-ink-dim">No readable recent site records.</p>}
              <ul className="mt-2 max-h-96 space-y-3 overflow-y-auto">{profile.visits.map((visit, i) => <li key={i} className="border-b border-line pb-2 text-sm">
                <p className="break-all font-semibold">{visit.domain}</p><p>{when(visit.visited_at)}</p><p className="text-ink-dim">{visit.evidence}</p><p className={visit.risk?.startsWith('WARNING') ? 'font-bold text-sev-critical' : 'text-ink-dim'}>{visit.risk}</p>
              </li>)}</ul>
            </div>
            <div><h4 className="font-semibold">Recorded downloads</h4><p className="mt-1 text-xs text-ink-dim">{profile.download_status}</p>
              {!profile.downloads.length && <p className="mt-2 text-sm text-ink-dim">No readable recent download records.</p>}
              <ul className="mt-2 max-h-96 space-y-3 overflow-y-auto">{profile.downloads.map((download, i) => <li key={i} className="border-b border-line pb-2 text-sm">
                <p className="break-all font-semibold">{download.filename}</p><p>{when(download.started_at)}</p><p className="text-ink-dim">{download.evidence}</p>
              </li>)}</ul>
            </div>
          </div>
        </article>)}
      </>}
    </section>
  </>
}
