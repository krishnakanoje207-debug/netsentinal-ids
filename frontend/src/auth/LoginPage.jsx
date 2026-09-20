import { useState } from 'react'

import { useAuth } from './AuthContext'

export function LoginPage() {
  const { signIn, error } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)

  async function submit(event) {
    event.preventDefault()
    setSubmitting(true)
    try {
      await signIn(username, password)
    } catch {
      // The context holds the message; nothing more to do here.
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <main className="flex min-h-full items-center justify-center p-6">
      <form
        onSubmit={submit}
        className="w-full max-w-sm rounded-lg border border-[var(--color-line)] bg-[var(--color-panel)] p-6"
      >
        <h1 className="text-base font-semibold">NetSentinel-AI</h1>
        <p className="mt-0.5 mb-5 text-xs text-[var(--color-ink-dim)]">
          Security operations console
        </p>

        {error && (
          <p
            role="alert"
            className="mb-4 rounded border border-[var(--color-sev-high)]/60 bg-[var(--color-sev-high)]/10 p-2 text-sm"
          >
            {error}
          </p>
        )}

        <label className="block">
          <span className="text-[11px] uppercase tracking-wide text-[var(--color-ink-faint)]">
            Username
          </span>
          <input
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            autoComplete="username"
            required
            className="mt-1 w-full rounded border border-[var(--color-line)] bg-[var(--color-surface)] px-2 py-1.5 text-sm"
          />
        </label>

        <label className="mt-3 block">
          <span className="text-[11px] uppercase tracking-wide text-[var(--color-ink-faint)]">
            Password
          </span>
          <input
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="current-password"
            required
            className="mt-1 w-full rounded border border-[var(--color-line)] bg-[var(--color-surface)] px-2 py-1.5 text-sm"
          />
        </label>

        <button
          type="submit"
          disabled={submitting}
          className="mt-5 w-full rounded bg-[var(--color-accent)] px-3 py-2 text-sm font-semibold text-white disabled:opacity-50"
        >
          {submitting ? 'Signing in...' : 'Sign in'}
        </button>
      </form>
    </main>
  )
}
