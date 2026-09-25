/**
 * Day and night.
 *
 * Day is the default: the console is shown in lit rooms and on projectors, where a dark
 * page washes out. Night is a choice the viewer makes, remembered in this browser only -
 * it is a preference, not something the server needs to know.
 *
 * The theme is applied as `data-theme` on <html>, and index.html sets it before the
 * first paint, so a night viewer never sees a white flash on load.
 */

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'

import { Moon, Sun } from '../components/icons'

export const THEME_KEY = 'netsentinel.theme'

/** @typedef {'light' | 'dark'} Theme */

/** @returns {Theme} */
export function storedTheme() {
  try {
    return localStorage.getItem(THEME_KEY) === 'dark' ? 'dark' : 'light'
  } catch {
    return 'light'
  }
}

function persist(theme) {
  try {
    localStorage.setItem(THEME_KEY, theme)
  } catch {
    // A private window can refuse storage; the switch still works for this visit.
  }
}

const ThemeContext = createContext(null)

export function ThemeProvider({ children }) {
  const [theme, setTheme] = useState(storedTheme)

  useEffect(() => {
    document.documentElement.dataset.theme = theme
  }, [theme])

  /**
   * Switch, revealing the new theme as a circle grown from the point that was clicked.
   * Browsers without view transitions, and viewers who asked for reduced motion, get
   * the switch without the reveal.
   *
   * @param {{x: number, y: number}} [origin] viewport coordinates of the control
   */
  const toggle = useCallback((origin) => {
    const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'
    const apply = () => {
      document.documentElement.dataset.theme = next
      setTheme(next)
      persist(next)
    }
    const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
    if (!document.startViewTransition || reduced) {
      apply()
      return
    }
    if (origin) {
      document.documentElement.style.setProperty('--vt-x', `${origin.x}px`)
      document.documentElement.style.setProperty('--vt-y', `${origin.y}px`)
    }
    document.startViewTransition(apply)
  }, [])

  const value = useMemo(() => ({ theme, toggle }), [theme, toggle])
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export function useTheme() {
  const context = useContext(ThemeContext)
  if (context === null) throw new Error('useTheme must be used inside a ThemeProvider')
  return context
}

/**
 * The day/night sign. Says what it will switch to, because an icon alone is a guess.
 *
 * @param {{className?: string}} props
 */
export function ThemeToggle({ className = '' }) {
  const { theme, toggle } = useTheme()
  const toNight = theme === 'light'
  const label = toNight ? 'Switch to night mode' : 'Switch to day mode'
  return (
    <button
      type="button"
      onClick={(event) => {
        const box = event.currentTarget.getBoundingClientRect()
        toggle({ x: box.left + box.width / 2, y: box.top + box.height / 2 })
      }}
      aria-label={label}
      title={label}
      data-tour="theme"
      className={`press group flex h-9 items-center gap-2 rounded-md border border-line px-2.5 text-sm text-ink-dim hover:border-line-strong hover:text-ink ${className}`}
    >
      <span className="relative block size-4" aria-hidden="true">
        <Sun
          size={16}
          weight="bold"
          className={`absolute inset-0 transition-[transform,opacity] duration-500 ease-[var(--ease-out-expo)] ${
            toNight ? 'rotate-0 opacity-100' : '-rotate-90 scale-50 opacity-0'
          }`}
        />
        <Moon
          size={16}
          weight="bold"
          className={`absolute inset-0 transition-[transform,opacity] duration-500 ease-[var(--ease-out-expo)] ${
            toNight ? 'rotate-90 scale-50 opacity-0' : 'rotate-0 opacity-100'
          }`}
        />
      </span>
      <span className="hidden xl:inline">{toNight ? 'Day' : 'Night'}</span>
    </button>
  )
}
