/**
 * The single place that talks to the API.
 *
 * Errors carry a `kind` rather than being thrown as bare strings, because the dashboard
 * must react differently to each: a 401 means the session is over and the user has to
 * log in again, a 403 means the account genuinely may not do this and retrying is
 * pointless, and a 422 carries a message worth showing verbatim.
 */

export const API_BASE = '/api/v1'

/**
 * @typedef {'unauthenticated' | 'forbidden' | 'not_found' | 'conflict' | 'invalid'
 *   | 'server' | 'network'} ApiErrorKind
 */

export class ApiError extends Error {
  /**
   * @param {ApiErrorKind} kind
   * @param {number} status
   * @param {string} message
   */
  constructor(kind, status, message) {
    super(message)
    this.name = 'ApiError'
    this.kind = kind
    this.status = status
  }
}

/** @returns {ApiErrorKind} */
function kindFor(status) {
  if (status === 401) return 'unauthenticated'
  if (status === 403) return 'forbidden'
  if (status === 404) return 'not_found'
  if (status === 409) return 'conflict'
  if (status === 422) return 'invalid'
  return 'server'
}

async function messageFrom(response) {
  try {
    const body = await response.json()
    if (typeof body?.detail === 'string') return body.detail
    // FastAPI validation errors arrive as a list of objects.
    if (Array.isArray(body?.detail)) {
      return body.detail
        .map((entry) => entry.msg ?? '')
        .filter(Boolean)
        .join('; ')
    }
  } catch {
    // Not JSON. Fall through to the status text.
  }
  return response.statusText || `request failed with ${response.status}`
}

/**
 * @param {string} path
 * @param {{token?: string | null, method?: string, json?: unknown,
 *   form?: Record<string, string>, signal?: AbortSignal}} [options]
 */
export async function request(path, options = {}) {
  const { token, method = 'GET', json, form, signal } = options

  const headers = {}
  if (token) headers.Authorization = `Bearer ${token}`

  let body
  if (form) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded'
    body = new URLSearchParams(form).toString()
  } else if (json !== undefined) {
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(json)
  }

  let response
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

  if (response.status === 204) return undefined
  return await response.json()
}

/**
 * The same request, stopping at the response.
 *
 * `request` assumes JSON. A file download needs the headers and the raw body, and
 * having one function guess which it is would make both harder to read.
 *
 * @param {string} path
 * @param {{token?: string | null}} [options]
 */
export async function rawRequest(path, options = {}) {
  const headers = {}
  if (options.token) headers.Authorization = `Bearer ${options.token}`

  let response
  try {
    response = await fetch(`${API_BASE}${path}`, { headers })
  } catch {
    throw new ApiError('network', 0, 'cannot reach the API')
  }

  if (!response.ok) {
    throw new ApiError(kindFor(response.status), response.status, await messageFrom(response))
  }
  return response
}

const FILENAME = /filename="([^"]+)"/

/**
 * The name the server chose, so a truncated export keeps saying so once it is on
 * disk. Falls back to something recognisable rather than to the browser's default,
 * which would be the word "export" with no date on it.
 *
 * @param {string | null} disposition
 */
export function filenameFrom(disposition) {
  const match = disposition ? FILENAME.exec(disposition) : null
  return match ? match[1] : 'netsentinel-alerts.csv'
}

// --- endpoints -------------------------------------------------------------

export const api = {
  /** @returns {Promise<import('./types').TokenResponse>} */
  login: (username, password) =>
    request('/auth/token', { method: 'POST', form: { username, password } }),

  /** @returns {Promise<import('./types').CurrentUser>} */
  me: (token) => request('/auth/me', { token }),

  /** @returns {Promise<import('./types').Health>} */
  health: () => request('/health'),

  /** @returns {Promise<import('./types').Alert[]>} */
  alerts: (token, params = {}) => {
    const query = new URLSearchParams()
    if (params.status) query.set('status', params.status)
    if (params.severity) query.set('severity', params.severity)
    query.set('limit', String(params.limit ?? 50))
    return request(`/alerts?${query.toString()}`, { token })
  },

  /** @returns {Promise<import('./types').AlertDetail>} */
  alert: (token, alertId) => request(`/alerts/${alertId}`, { token }),

  /**
   * The feed as a CSV file. Returns the body and the two things the caller needs to
   * save it honestly: the name the server chose, and whether the file is partial.
   *
   * Not a plain link, because the API needs a bearer token and an anchor cannot
   * carry one. The response is small by construction - the server caps the rows -
   * so reading it into a blob is safe.
   *
   * @returns {Promise<{blob: Blob, filename: string, truncated: boolean}>}
   */
  exportAlerts: async (token, params = {}) => {
    const query = new URLSearchParams()
    if (params.status) query.set('status', params.status)
    if (params.severity) query.set('severity', params.severity)

    const response = await rawRequest(`/alerts/export?${query.toString()}`, { token })
    return {
      blob: await response.blob(),
      filename: filenameFrom(response.headers.get('content-disposition')),
      truncated: response.headers.get('x-export-truncated') === 'true',
    }
  },

  /** @returns {Promise<import('./types').Alert>} */
  setAlertStatus: (token, alertId, status) =>
    request(`/alerts/${alertId}/status`, { token, method: 'PATCH', json: { status } }),

  /** @returns {Promise<import('./types').ResponseAction[]>} */
  pendingActions: (token) => request('/actions/pending', { token }),

  /** @returns {Promise<import('./types').MLModel[]>} */
  models: (token, since = '7d') => request(`/models?since=${encodeURIComponent(since)}`, { token }),

  /** @returns {Promise<import('./types').MLModel>} */
  promoteModel: (token, modelId, since) =>
    request(`/models/${modelId}/promote`, { token, method: 'POST', json: { since } }),

  /** @returns {Promise<import('./types').ResponseAction>} */
  decide: (token, actionId, decision, comment) =>
    request(`/actions/${actionId}/decision`, {
      token,
      method: 'POST',
      json: { decision, comment },
    }),
}
