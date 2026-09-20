/**
 * One place that turns an API failure into something an analyst can act on.
 *
 * Each kind needs a different instruction, and "something went wrong" is the one message
 * that helps nobody. A forbidden response in particular must not invite a retry: the
 * account genuinely may not do this, and trying again will fail identically.
 */

import { ApiError } from '../api/client'

const GUIDANCE = {
  unauthenticated: 'Your session has ended. Sign in again.',
  forbidden: 'Your role does not permit this. Ask an administrator if you need it.',
  not_found: 'That record no longer exists. It may have been closed or merged.',
  conflict: 'Someone else already acted on this. Reload to see the current state.',
  invalid: 'The request was rejected as invalid.',
  server: 'The API failed to handle this. Check its logs.',
  network: 'Cannot reach the API. If you are on the SSH tunnel, check it is still up.',
}

/** @param {{error: unknown}} props */
export function ErrorNotice({ error }) {
  const apiError = error instanceof ApiError ? error : null
  const guidance = apiError ? GUIDANCE[apiError.kind] : null
  const detail = error instanceof Error ? error.message : String(error)

  return (
    <div
      role="alert"
      className="mb-3 rounded border border-[var(--color-sev-high)]/60 bg-[var(--color-sev-high)]/10 p-3 text-sm"
      data-testid="error-notice"
      data-kind={apiError?.kind ?? 'unknown'}
    >
      {guidance && <p className="font-medium">{guidance}</p>}
      <p className={guidance ? 'mt-0.5 text-[var(--color-ink-dim)]' : 'font-medium'}>{detail}</p>
    </div>
  )
}
