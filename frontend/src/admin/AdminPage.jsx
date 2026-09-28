/**
 * The administrator's three jobs: accounts, sensors and the audit trail.
 *
 * Decisions that shaped this screen:
 *
 * - A section is offered only to an account holding its permission, as the navigation
 *   offers pages. A tab that can only ever return 403 teaches people to ignore errors.
 * - Disabling an account and revoking a sensor ask first, in place, and say what will
 *   happen: a disabled account's sessions end at once, and a revoked sensor's stream
 *   stops being ingested. Enabling again is not asked about; it undoes nothing.
 * - Your own row has no disable button and no role picker. The API refuses both with a
 *   409 so the system can never be left without an administrator; the page does not
 *   offer what the API will refuse.
 * - The audit filters are submitted, like the alert search box, so a half-typed actor
 *   is not searched for on every keystroke.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'

import { api } from '../api/client'
import { PERMISSIONS } from '../api/types'
import { useAuth } from '../auth/AuthContext'
import { boardTime } from '../components/Board'
import { ErrorNotice } from '../components/ErrorNotice'
import { UserGear } from '../components/icons'
import { PageHeader } from '../components/PageHeader'
import { roleName } from '../lib/glossary'
import { ago, useNow } from '../lib/useNow'

/** Rows per audit page; "Older" asks for the next one. */
export const AUDIT_PAGE = 50

const SECTIONS = [
  { id: 'accounts', label: 'Accounts', permission: PERMISSIONS.usersManage },
  { id: 'sensors', label: 'Sensors', permission: PERMISSIONS.sensorsManage },
  { id: 'audit', label: 'Audit log', permission: PERMISSIONS.auditRead },
]

const TABLE_HEAD =
  'bg-sunk text-left text-[0.6875rem] font-bold tracking-[0.08em] text-ink-dim uppercase [&>th]:px-3 [&>th]:py-2.5 [&>th:first-child]:pl-4'
const ROW = 'border-t border-line align-middle transition-colors duration-150 hover:bg-sunk [&>td]:px-3 [&>td]:py-3 [&>td:first-child]:pl-4'

/**
 * A destructive button that asks before it acts: the first press turns into the
 * question and a Yes/Cancel pair, with focus on the answer.
 *
 * @param {{label: string, question: string, confirmLabel: string, pending: boolean,
 *   onConfirm: () => void}} props
 */
export function ConfirmButton({ label, question, confirmLabel, pending, onConfirm }) {
  const [asking, setAsking] = useState(false)
  const yes = useRef(/** @type {HTMLButtonElement | null} */ (null))
  useEffect(() => {
    if (asking) yes.current?.focus()
  }, [asking])

  if (!asking) {
    return (
      <button type="button" disabled={pending} onClick={() => setAsking(true)} className="control press font-semibold disabled:opacity-40">
        {label}
      </button>
    )
  }
  return (
    <div role="group" aria-label={question} className="flex flex-wrap items-center gap-2">
      <span className="text-[0.8125rem] text-ink-dim">{question}</span>
      <button
        ref={yes}
        type="button"
        disabled={pending}
        onClick={() => {
          setAsking(false)
          onConfirm()
        }}
        className="press h-9 rounded-md bg-fill-critical px-3 text-sm font-bold text-white hover:brightness-110 disabled:opacity-50"
      >
        {confirmLabel}
      </button>
      <button type="button" onClick={() => setAsking(false)} className="control press">
        Cancel
      </button>
    </div>
  )
}

function Accounts() {
  const { token, user: me } = useAuth()
  const queryClient = useQueryClient()
  const users = useQuery({ queryKey: ['admin', 'users'], queryFn: () => api.users(token), enabled: token !== null })
  const roles = useQuery({ queryKey: ['admin', 'roles'], queryFn: () => api.roles(token), enabled: token !== null })
  const refresh = () => queryClient.invalidateQueries({ queryKey: ['admin'] })

  const update = useMutation({
    mutationFn: ({ userId, change }) => api.updateUser(token, userId, change),
    onSuccess: refresh,
  })
  const blank = { username: '', email: '', password: '', role: '' }
  const [draft, setDraft] = useState(blank)
  const create = useMutation({
    mutationFn: (account) => api.createUser(token, account),
    onSuccess: () => {
      setDraft(blank)
      return refresh()
    },
  })
  const roleNames = (roles.data ?? []).map((role) => role.name)
  const field = (key) => ({ value: draft[key], onChange: (event) => setDraft({ ...draft, [key]: event.target.value }) })

  return (
    <div className="space-y-6">
      {(users.error || update.error) && <ErrorNotice error={users.error || update.error} />}
      {users.isLoading && <p className="text-ink-dim">Loading accounts...</p>}
      {users.data && (
        <div className="panel overflow-x-auto">
          <table className="w-full border-collapse text-[0.9375rem]">
            <thead>
              <tr className={TABLE_HEAD}>
                <th>Account</th>
                <th>Role</th>
                <th>State</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {users.data.map((account) => {
                const self = account.user_id === me?.user_id
                return (
                  <tr key={account.user_id} className={ROW} data-testid={`account-${account.user_id}`}>
                    <td>
                      <span className="block font-bold">
                        {account.username}
                        {self && <span className="ml-2 text-[0.8125rem] font-semibold text-ink-faint">you</span>}
                      </span>
                      <span className="text-[0.8125rem] text-ink-dim">{account.email}</span>
                    </td>
                    <td>
                      {self ? (
                        <span title="Your own role is changed by another administrator">{roleName(account.role)}</span>
                      ) : (
                        <select
                          aria-label={`Role of ${account.username}`}
                          value={account.role ?? ''}
                          disabled={update.isPending}
                          onChange={(event) => update.mutate({ userId: account.user_id, change: { role: event.target.value } })}
                          className="control"
                        >
                          {roleNames.map((name) => (
                            <option key={name} value={name}>
                              {roleName(name)}
                            </option>
                          ))}
                        </select>
                      )}
                    </td>
                    <td className={account.is_active ? 'font-semibold text-sev-low' : 'font-semibold text-sev-critical'}>
                      {account.is_active ? 'Active' : 'Disabled'}
                    </td>
                    <td className="text-right">
                      {self ? null : account.is_active ? (
                        <ConfirmButton
                          label="Disable"
                          question={`Disable ${account.username}? Their sessions end at once.`}
                          confirmLabel="Yes, disable"
                          pending={update.isPending}
                          onConfirm={() => update.mutate({ userId: account.user_id, change: { is_active: false } })}
                        />
                      ) : (
                        <button
                          type="button"
                          disabled={update.isPending}
                          onClick={() => update.mutate({ userId: account.user_id, change: { is_active: true } })}
                          className="control press font-semibold disabled:opacity-40"
                        >
                          Enable
                        </button>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      <form
        className="panel space-y-3 p-5"
        onSubmit={(event) => {
          event.preventDefault()
          create.mutate(draft)
        }}
      >
        <h2 className="text-lg font-extrabold tracking-tight">New account</h2>
        {create.error && <ErrorNotice error={create.error} />}
        <div className="flex flex-wrap items-end gap-3">
          {[
            ['username', 'Username', 'text', 'username'],
            ['email', 'Email', 'email', 'email'],
            ['password', 'Password', 'password', 'new-password'],
          ].map(([key, label, type, autoComplete]) => (
            <label key={key} className="flex flex-col gap-1 text-[0.8125rem] font-semibold text-ink-dim">
              {label}
              <input type={type} required autoComplete={autoComplete} className="control" {...field(key)} />
            </label>
          ))}
          <label className="flex flex-col gap-1 text-[0.8125rem] font-semibold text-ink-dim">
            Role
            <select required className="control" {...field('role')}>
              <option value="">Choose a role</option>
              {roleNames.map((name) => (
                <option key={name} value={name}>
                  {roleName(name)}
                </option>
              ))}
            </select>
          </label>
          <button type="submit" disabled={create.isPending} className="control press font-semibold disabled:opacity-40">
            Create account
          </button>
        </div>
      </form>
    </div>
  )
}

function Sensors() {
  const { token } = useAuth()
  const now = useNow(10_000)
  const queryClient = useQueryClient()
  const sensors = useQuery({ queryKey: ['admin', 'sensors'], queryFn: () => api.sensors(token), enabled: token !== null })
  const revoke = useMutation({
    mutationFn: ({ sensorId, revoked }) => api.setSensorRevoked(token, sensorId, revoked),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['admin', 'sensors'] }),
  })

  return (
    <div>
      {(sensors.error || revoke.error) && <ErrorNotice error={sensors.error || revoke.error} />}
      {sensors.isLoading && <p className="text-ink-dim">Loading sensors...</p>}
      {sensors.data && sensors.data.length === 0 && (
        <p className="panel p-6 text-[0.9375rem] text-ink-dim">
          No sensors are registered. Register one with lab/replay/register_sensor.py before the writer can ingest.
        </p>
      )}
      {sensors.data && sensors.data.length > 0 && (
        <div className="panel overflow-x-auto">
          <table className="w-full border-collapse text-[0.9375rem]">
            <thead>
              <tr className={TABLE_HEAD}>
                <th>Sensor</th>
                <th>Host</th>
                <th>Status</th>
                <th>Last seen</th>
                <th>Trust</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {sensors.data.map((sensor) => (
                <tr key={sensor.sensor_id} className={ROW} data-testid={`sensor-${sensor.sensor_id}`}>
                  <td>
                    <span className="block font-bold">#{sensor.sensor_id}</span>
                    <span className="data text-ink-dim">{sensor.type}</span>
                  </td>
                  <td className="data">{sensor.hostname}</td>
                  <td className="capitalize">{sensor.status}</td>
                  <td className="numeric text-ink-dim" title={sensor.last_seen ?? undefined}>
                    {sensor.last_seen ? ago(Date.parse(sensor.last_seen), now) : 'never'}
                  </td>
                  <td className={sensor.revoked ? 'font-semibold text-sev-critical' : 'font-semibold text-sev-low'}>
                    {sensor.revoked ? 'Revoked' : 'Trusted'}
                  </td>
                  <td className="text-right">
                    {sensor.revoked ? (
                      <button
                        type="button"
                        disabled={revoke.isPending}
                        onClick={() => revoke.mutate({ sensorId: sensor.sensor_id, revoked: false })}
                        className="control press font-semibold disabled:opacity-40"
                      >
                        Re-enable
                      </button>
                    ) : (
                      <ConfirmButton
                        label="Revoke"
                        question={`Revoke sensor #${sensor.sensor_id}? Its stream is no longer ingested.`}
                        confirmLabel="Yes, revoke"
                        pending={revoke.isPending}
                        onConfirm={() => revoke.mutate({ sensorId: sensor.sensor_id, revoked: true })}
                      />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function AuditLog() {
  const { token } = useAuth()
  const now = useNow(60_000)
  const empty = { actor: '', action: '', from: '', to: '' }
  const [draft, setDraft] = useState(empty)
  const [filters, setFilters] = useState(empty)
  const [offset, setOffset] = useState(0)
  const audit = useQuery({
    queryKey: ['admin', 'audit', filters, offset],
    queryFn: () => api.audit(token, { ...filters, offset }, AUDIT_PAGE),
    enabled: token !== null,
  })
  const field = (key) => ({ value: draft[key], onChange: (event) => setDraft({ ...draft, [key]: event.target.value }) })

  return (
    <div className="space-y-4">
      <form
        role="search"
        aria-label="Filter the audit log"
        className="flex flex-wrap items-end gap-3"
        onSubmit={(event) => {
          event.preventDefault()
          setFilters({ ...draft, actor: draft.actor.trim(), action: draft.action.trim() })
          setOffset(0)
        }}
      >
        {[
          ['actor', 'Actor', 'text', 'username'],
          ['action', 'Action', 'text', 'user. or auth.login'],
          ['from', 'From', 'datetime-local', undefined],
          ['to', 'To', 'datetime-local', undefined],
        ].map(([key, label, type, placeholder]) => (
          <label key={key} className="flex flex-col gap-1 text-[0.8125rem] font-semibold text-ink-dim">
            {label}
            <input type={type} placeholder={placeholder} className="control data" {...field(key)} />
          </label>
        ))}
        <button type="submit" className="control press font-semibold">
          Apply
        </button>
      </form>

      {audit.error && <ErrorNotice error={audit.error} />}
      {audit.isLoading && <p className="text-ink-dim">Loading the audit log...</p>}
      {audit.data && audit.data.length === 0 && (
        <p className="panel p-6 text-[0.9375rem] text-ink-dim">Nothing in the audit log matches these filters.</p>
      )}
      {audit.data && audit.data.length > 0 && (
        <div className="panel overflow-x-auto">
          <table className="w-full border-collapse text-[0.9375rem]">
            <thead>
              <tr className={TABLE_HEAD}>
                <th>Time</th>
                <th>Actor</th>
                <th>Action</th>
                <th>On</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {audit.data.map((entry) => (
                <tr key={entry.log_id} className={ROW} data-testid="audit-row">
                  <td className="data whitespace-nowrap" title={entry.ts}>{boardTime(entry.ts, now)}</td>
                  <td>{entry.username ?? <span className="text-ink-faint">system</span>}</td>
                  <td className="data font-semibold">{entry.action}</td>
                  <td className="data text-ink-dim">{entry.entity}</td>
                  <td className="data max-w-[24rem] truncate text-[0.8125rem] text-ink-dim" title={JSON.stringify(entry.details)}>
                    {Object.keys(entry.details).length ? JSON.stringify(entry.details) : '--'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="flex gap-2">
        <button type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - AUDIT_PAGE))} className="control press disabled:opacity-40">
          Newer
        </button>
        <button
          type="button"
          disabled={!audit.data || audit.data.length < AUDIT_PAGE}
          onClick={() => setOffset(offset + AUDIT_PAGE)}
          className="control press disabled:opacity-40"
        >
          Older
        </button>
      </div>
    </div>
  )
}

const PANELS = { accounts: Accounts, sensors: Sensors, audit: AuditLog }

export function AdminPage() {
  const { can } = useAuth()
  const offered = SECTIONS.filter((section) => can(section.permission))
  const [chosen, setChosen] = useState(offered[0]?.id)
  const Panel = PANELS[chosen]

  return (
    <section>
      <PageHeader
        icon={UserGear}
        title="Admin"
        description="Who can sign in and with which role, which sensors are trusted to send traffic, and the record of everything changed here and elsewhere."
      >
        <div role="group" aria-label="Admin sections" className="flex gap-1">
          {offered.map((section) => (
            <button
              key={section.id}
              type="button"
              aria-pressed={section.id === chosen}
              onClick={() => setChosen(section.id)}
              className={`control press font-semibold ${section.id === chosen ? 'border-ink bg-sunk' : 'text-ink-dim'}`}
            >
              {section.label}
            </button>
          ))}
        </div>
      </PageHeader>
      {Panel ? <Panel /> : <p className="text-ink-dim">Your role has no administration to do.</p>}
    </section>
  )
}
