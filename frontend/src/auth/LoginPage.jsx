import { useState } from 'react'

import { Mark } from '../components/Mark'
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
    <main className="flex min-h-full items-center justify-center bg-[radial-gradient(ellipse_at_top,var(--color-panel-raised),var(--color-surface)_60%)] p-6">
      <form
        onSubmit={submit}
        className="w-full max-w-sm rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] p-7 shadow-[0_24px_48px_-12px_rgb(0_0_0/0.55)]"
      >
        <Mark size={32} className="mb-4 text-[var(--color-accent)]" />
        <h1 className="text-xl font-semibold tracking-tight">NetSentinel-AI</h1>
        <p className="mt-1 mb-6 text-sm text-[var(--color-ink-dim)]">
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
          <span className="text-xs font-medium text-[var(--color-ink-dim)]">
            Username
          </span>
          <input
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            autoComplete="username"
            required
            className="mt-1.5 w-full rounded-md border border-[var(--color-line)] bg-[var(--color-surface)] px-3 py-2 text-sm"
          />
        </label>

        <label className="mt-4 block">
          <span className="text-xs font-medium text-[var(--color-ink-dim)]">
            Password
          </span>
          <input
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="current-password"
            required
            className="mt-1.5 w-full rounded-md border border-[var(--color-line)] bg-[var(--color-surface)] px-3 py-2 text-sm"
          />
        </label>

        <button
          type="submit"
          disabled={submitting}
          className="mt-6 w-full rounded-md bg-[var(--color-accent)] px-3 py-2.5 text-sm font-semibold text-white transition-[filter,transform] duration-150 hover:brightness-110 active:scale-[0.99] disabled:opacity-50"
        >
          {submitting ? 'Signing in...' : 'Sign in'}
        </button>
      </form>
    </main>
  )
}
