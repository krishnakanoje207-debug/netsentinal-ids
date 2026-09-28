/**
 * The admin page: sections follow permissions, disabling and revoking ask first, your
 * own account cannot be disabled or re-roled from here, and the audit filters reach
 * the API as the feed's do.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError, api } from '../api/client'
import { AdminPage } from './AdminPage'

const auth = vi.hoisted(() => ({
  granted: ['users:manage', 'sensors:manage', 'audit:read'],
}))
vi.mock('../auth/AuthContext', () => ({
  useAuth: () => ({
    token: 'a-token',
    user: { user_id: 3, username: 'admin' },
    can: (permission) => auth.granted.includes(permission),
  }),
}))

const ROLES = [
  { name: 'administrator', permissions: ['users:manage'] },
  { name: 'soc_analyst', permissions: ['alerts:read'] },
  { name: 'viewer', permissions: ['alerts:read'] },
]
const USERS = [
  { user_id: 3, username: 'admin', email: 'admin@example.test', is_active: true, role: 'administrator', created_at: null },
  { user_id: 1, username: 'analyst', email: 'analyst@example.test', is_active: true, role: 'soc_analyst', created_at: null },
]
const SENSORS = [
  { sensor_id: 1, type: 'early_flow', hostname: 'dataset-replay', status: 'online', last_seen: null, revoked: false },
]
const ENTRIES = [
  { log_id: 2, ts: '2026-09-20T10:00:00Z', user_id: 3, username: 'admin', action: 'user.created', entity: 'username:noc', details: { role: 'viewer' } },
  { log_id: 1, ts: '2026-09-20T09:00:00Z', user_id: null, username: null, action: 'model.registered', entity: 'm:1', details: {} },
]

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <AdminPage />
    </QueryClientProvider>,
  )
  return userEvent.setup()
}

describe('AdminPage', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    auth.granted = ['users:manage', 'sensors:manage', 'audit:read']
    vi.spyOn(api, 'roles').mockResolvedValue(ROLES)
    vi.spyOn(api, 'users').mockResolvedValue(USERS)
    vi.spyOn(api, 'sensors').mockResolvedValue(SENSORS)
    vi.spyOn(api, 'audit').mockResolvedValue(ENTRIES)
  })

  it('offers only the sections the account may use', () => {
    auth.granted = ['audit:read']
    renderPage()
    const sections = within(screen.getByRole('group', { name: 'Admin sections' })).getAllByRole('button')
    expect(sections.map((button) => button.textContent)).toEqual(['Audit log'])
    expect(sections[0]).toHaveAttribute('aria-pressed', 'true')
  })

  it('asks before disabling an account, and can be cancelled', async () => {
    const update = vi.spyOn(api, 'updateUser').mockResolvedValue({ ...USERS[1], is_active: false })
    const user = renderPage()
    const row = await screen.findByTestId('account-1')

    await user.click(within(row).getByRole('button', { name: 'Disable' }))
    expect(update).not.toHaveBeenCalled()
    expect(within(row).getByRole('button', { name: 'Yes, disable' })).toHaveFocus()
    await user.click(within(row).getByRole('button', { name: 'Cancel' }))
    expect(update).not.toHaveBeenCalled()

    await user.click(within(row).getByRole('button', { name: 'Disable' }))
    await user.click(within(row).getByRole('button', { name: 'Yes, disable' }))
    expect(update).toHaveBeenCalledWith('a-token', 1, { is_active: false })
  })

  it('offers no disable button or role picker on your own account', async () => {
    renderPage()
    const own = await screen.findByTestId('account-3')
    expect(within(own).queryByRole('button', { name: 'Disable' })).not.toBeInTheDocument()
    expect(within(own).queryByRole('combobox')).not.toBeInTheDocument()
  })

  it('changes a role from the picker', async () => {
    const update = vi.spyOn(api, 'updateUser').mockResolvedValue({ ...USERS[1], role: 'viewer' })
    const user = renderPage()
    const picker = await screen.findByRole('combobox', { name: 'Role of analyst' })
    await waitFor(() => expect(within(picker).getAllByRole('option')).toHaveLength(3))

    await user.selectOptions(picker, 'viewer')
    expect(update).toHaveBeenCalledWith('a-token', 1, { role: 'viewer' })
  })

  it('creates an account and shows the refusal the API gives', async () => {
    const create = vi
      .spyOn(api, 'createUser')
      .mockRejectedValue(new ApiError('conflict', 409, 'that username or email already belongs to an account'))
    const user = renderPage()
    await screen.findByTestId('account-1')

    await user.type(screen.getByLabelText('Username'), 'analyst')
    await user.type(screen.getByLabelText('Email'), 'a@b.c')
    await user.type(screen.getByLabelText('Password'), 'pw')
    await user.selectOptions(screen.getByLabelText('Role'), 'viewer')
    await user.click(screen.getByRole('button', { name: 'Create account' }))

    expect(create).toHaveBeenCalledWith('a-token', {
      username: 'analyst',
      email: 'a@b.c',
      password: 'pw',
      role: 'viewer',
    })
    expect(await screen.findByText('that username or email already belongs to an account')).toBeInTheDocument()
  })

  it('asks before revoking a sensor', async () => {
    const revoke = vi.spyOn(api, 'setSensorRevoked').mockResolvedValue({ ...SENSORS[0], revoked: true })
    const user = renderPage()
    await user.click(screen.getByRole('button', { name: 'Sensors' }))
    const row = await screen.findByTestId('sensor-1')
    expect(row).toHaveTextContent('Trusted')
    expect(row).toHaveTextContent('never')

    await user.click(within(row).getByRole('button', { name: 'Revoke' }))
    expect(revoke).not.toHaveBeenCalled()
    await user.click(within(row).getByRole('button', { name: 'Yes, revoke' }))
    expect(revoke).toHaveBeenCalledWith('a-token', 1, true)
  })

  it('reads the audit log and sends its filters when applied', async () => {
    const user = renderPage()
    await user.click(screen.getByRole('button', { name: 'Audit log' }))
    expect(await screen.findAllByTestId('audit-row')).toHaveLength(2)
    expect(screen.getByText('system')).toBeInTheDocument()

    await user.type(screen.getByLabelText('Actor'), ' admin ')
    await user.type(screen.getByLabelText('Action'), 'user.')
    await user.click(screen.getByRole('button', { name: 'Apply' }))

    await waitFor(() =>
      expect(api.audit).toHaveBeenLastCalledWith(
        'a-token',
        { actor: 'admin', action: 'user.', from: '', to: '', offset: 0 },
        50,
      ),
    )
    // Fewer rows than a page: there is nothing older to ask for.
    expect(screen.getByRole('button', { name: 'Older' })).toBeDisabled()
  })

  it('shows a refused time range as the sentence the API wrote', async () => {
    vi.spyOn(api, 'audit').mockRejectedValue(new ApiError('invalid', 422, 'the range starts after it ends'))
    const user = renderPage()
    await user.click(screen.getByRole('button', { name: 'Audit log' }))
    expect(await screen.findByText('the range starts after it ends')).toBeInTheDocument()
  })
})
