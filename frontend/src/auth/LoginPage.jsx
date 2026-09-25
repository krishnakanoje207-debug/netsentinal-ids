/**
 * The way in. The name is posted on the board as the station would post it, and the
 * board says in three lines what this console does - no numbers, because nothing has
 * been measured for this visitor yet.
 */

import { useState } from 'react'

import { FlapText } from '../components/FlapText'
import { Mark } from '../components/Mark'
import { ThemeToggle } from '../theme/theme'
import { useAuth } from './AuthContext'

const DOES = [
  ['Watch', 'Every network conversation is scored by AI detectors as it happens.'],
  ['Explain', 'Every alert shows which measurements made it look like an attack.'],
  ['Decide', 'Nothing is blocked until a person approves it.'],
]

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
    <main className="grid min-h-screen lg:grid-cols-[minmax(0,7fr)_minmax(0,5fr)]">
      <section className="board m-3 flex flex-col justify-between rounded-xl p-6 md:m-4 md:p-10 lg:mr-0">
        <div className="flex items-center gap-3">
          <span className="grid size-10 place-items-center rounded-md bg-white text-board" aria-hidden="true">
            <Mark size={24} />
          </span>
          <span className="text-sm font-bold tracking-[0.08em] text-board-dim uppercase">Security operations console</span>
        </div>

        <div className="my-10 lg:my-0">
          <h1 className="text-[clamp(1.5rem,4.2vw,3.75rem)] leading-none">
            <FlapText text="NetSentinel AI" />
          </h1>
          <p className="mt-6 max-w-xl text-[1.0625rem] leading-relaxed text-board-dim md:text-lg">
            Watches your network, explains every alert in plain words, and waits for a person
            before anything is blocked.
          </p>
        </div>

        <ol className="grid gap-px overflow-hidden rounded-lg bg-board-line/60 md:grid-cols-3">
          {DOES.map(([name, text], index) => (
            <li key={name} className="rise-in bg-board-deep p-4" style={{ animationDelay: `${700 + index * 120}ms` }}>
              <p className="font-bold">{name}</p>
              <p className="mt-1 text-[0.9375rem] leading-snug text-board-dim">{text}</p>
            </li>
          ))}
        </ol>
      </section>

      <section className="relative flex items-center justify-center p-6 md:p-10">
        <div className="absolute top-4 right-4 md:top-6 md:right-6">
          <ThemeToggle />
        </div>
        <form onSubmit={submit} className="rise-in w-full max-w-sm">
          <h2 className="text-[1.75rem] font-extrabold tracking-tight">Sign in</h2>
          <p className="mt-1 mb-7 text-[0.9375rem] text-ink-dim">
            Use the account your administrator gave you.
          </p>

          {error && (
            <p role="alert" className="mb-5 rounded-md border border-sev-critical/50 bg-fill-critical/10 p-3 text-[0.9375rem]">
              {error}
            </p>
          )}

          <label className="block">
            <span className="text-sm font-semibold text-ink-dim">Username</span>
            <input
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              autoComplete="username"
              required
              className="control mt-1.5 h-11 w-full text-base"
            />
          </label>

          <label className="mt-5 block">
            <span className="text-sm font-semibold text-ink-dim">Password</span>
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="current-password"
              required
              className="control mt-1.5 h-11 w-full text-base"
            />
          </label>

          <button
            type="submit"
            disabled={submitting}
            className="press btn-primary mt-7 h-11 w-full rounded-md text-base font-bold disabled:opacity-50"
          >
            {submitting ? 'Signing in...' : 'Sign in'}
          </button>
        </form>
      </section>
    </main>
  )
}
