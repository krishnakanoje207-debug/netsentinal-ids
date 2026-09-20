/**
 * The single place that talks to the API.
 *
 * Errors are mapped to a typed shape rather than thrown as bare strings, because the
 * dashboard must react differently to each: a 401 means the session is over and the
 * user has to log in again, a 403 means the account genuinely may not do this and
 * retrying is pointless, and a 422 carries a message worth showing verbatim.
 */

import type {
  Alert,
  AlertDetail,
  ApprovalDecision,
  CurrentUser,
  Health,
  ResponseAction,
  TokenResponse,
} from './types'

export const API_BASE = '/api/v1'

export type ApiErrorKind =
  | 'unauthenticated'
  | 'forbidden'
  | 'not_found'
  | 'conflict'
  | 'invalid'
  | 'server'
  | 'network'

export class ApiError extends Error {
  readonly kind: ApiErrorKind
  readonly status: number

  constructor(kind: ApiErrorKind, status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.kind = kind
    this.status = status
  }
}

function kindFor(status: number): ApiErrorKind {
  if (status === 401) return 'unauthenticated'
  if (status === 403) return 'forbidden'
  if (status === 404) return 'not_found'
  if (status === 409) return 'conflict'
  if (status === 422) return 'invalid'
  return 'server'
}

async function messageFrom(response: Response): Promise<string> {
  try {
    const body = await response.json()
    if (typeof body?.detail === 'string') return body.detail
    // FastAPI validation errors arrive as a list of objects.
    if (Array.isArray(body?.detail)) {
      return body.detail.map((d: { msg?: string }) => d.msg ?? '').filter(Boolean).join('; ')
    }
  } catch {
    // Not JSON. Fall through to the status text.
  }
  return response.statusText || `request failed with ${response.status}`
}

export interface RequestOptions {
  token?: string | null
  method?: string
  json?: unknown
  form?: Record<string, string>
  signal?: AbortSignal
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { token, method = 'GET', json, form, signal } = options

  const headers: Record<string, string> = {}
  if (token) headers.Authorization = `Bearer ${token}`

  let body: string | undefined
  if (form) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded'
    body = new URLSearchParams(form).toString()
  } else if (json !== undefined) {
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(json)
  }

  let response: Response
  try {
    response = await fetch(`${API_BASE}${path}`, { method, headers, body, signal })
  } catch {
    // A dropped SSH tunnel looks like this, and it is worth distinguishing from a
    // server that answered with an error.
    throw new ApiError('network', 0, 'cannot reach the API')
  }

  if (!response.ok) {
    throw new ApiError(kindFor(response.status), response.status, await messageFrom(response))
  }

  if (response.status === 204) return undefined as T
  return (await response.json()) as T
}

// --- endpoints -------------------------------------------------------------

export const api = {
  login: (username: string, password: string) =>
    request<TokenResponse>('/auth/token', { method: 'POST', form: { username, password } }),

  me: (token: string) => request<CurrentUser>('/auth/me', { token }),

  health: () => request<Health>('/health'),

  alerts: (
    token: string,
    params: { status?: string; severity?: string; limit?: number } = {},
  ) => {
    const query = new URLSearchParams()
    if (params.status) query.set('status', params.status)
    if (params.severity) query.set('severity', params.severity)
    query.set('limit', String(params.limit ?? 50))
    return request<Alert[]>(`/alerts?${query.toString()}`, { token })
  },

  alert: (token: string, alertId: number) =>
    request<AlertDetail>(`/alerts/${alertId}`, { token }),

  setAlertStatus: (token: string, alertId: number, status: string) =>
    request<Alert>(`/alerts/${alertId}/status`, { token, method: 'PATCH', json: { status } }),

  pendingActions: (token: string) =>
    request<ResponseAction[]>('/actions/pending', { token }),

  decide: (
    token: string,
    actionId: number,
    decision: ApprovalDecision,
    comment: string | null,
  ) =>
    request<ResponseAction>(`/actions/${actionId}/decision`, {
      token,
      method: 'POST',
      json: { decision, comment },
    }),
}
