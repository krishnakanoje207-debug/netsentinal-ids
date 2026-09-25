/**
 * The guided tour: a spotlight that travels between the real parts of the console, and
 * a card that says what each one is.
 *
 * - It points at live elements, never at screenshots, so what the tour shows is what the
 *   viewer will use. A stop whose element is missing is skipped.
 * - The spotlighted element stays usable: the dimmed area blocks clicks, the hole does not,
 *   so "hover a row" can be tried on the spot.
 * - Keyboard: Escape leaves, the arrow keys move, and focus sits in the card.
 * - First visit: a quiet invitation, not an ambush. It is shown once per browser, and
 *   the tour can be taken again from the header.
 */

import { useQueryClient } from '@tanstack/react-query'
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from 'react'
import { createPortal } from 'react-dom'
import { useLocation, useNavigate } from 'react-router-dom'

import { api } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { ArrowLeft, ArrowRight, Signpost, X } from '../components/icons'
import { TOUR_STEPS } from './steps'

export const SEEN_KEY = 'netsentinel.tour.seen'
const PAD = 8
const FIND_TIMEOUT_MS = 2500

function markSeen() {
  try {
    localStorage.setItem(SEEN_KEY, '1')
  } catch {
    // Without storage the invitation may show again next visit; nothing worse.
  }
}

function hasSeen() {
  try {
    return localStorage.getItem(SEEN_KEY) === '1'
  } catch {
    return true
  }
}

/** Wait for an element to appear, since a page may still be loading its data. */
function waitFor(selector, timeoutMs) {
  return new Promise((resolve) => {
    const found = document.querySelector(selector)
    if (found) {
      resolve(found)
      return
    }
    const observer = new MutationObserver(() => {
      const element = document.querySelector(selector)
      if (element) {
        observer.disconnect()
        window.clearTimeout(timer)
        resolve(element)
      }
    })
    observer.observe(document.body, { childList: true, subtree: true })
    const timer = window.setTimeout(() => {
      observer.disconnect()
      resolve(null)
    }, timeoutMs)
  })
}

const TourContext = createContext(null)

export function TourProvider({ children }) {
  const { token, can } = useAuth()
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const location = useLocation()

  const [active, setActive] = useState(false)
  const [index, setIndex] = useState(0)
  const [target, setTarget] = useState(null)
  const [invited, setInvited] = useState(() => !hasSeen())
  const direction = useRef(1)
  const firstAlertId = useRef(null)

  const steps = useMemo(
    () => TOUR_STEPS.filter((step) => !step.requires || can(step.requires)),
    [can],
  )

  const stop = useCallback(() => {
    setActive(false)
    setTarget(null)
    markSeen()
    setInvited(false)
  }, [])

  const start = useCallback(async () => {
    setInvited(false)
    // The detail stops need a real alert to open; the newest one, if there is any.
    try {
      const newest = await queryClient.fetchQuery({
        queryKey: ['alerts', 'tour-newest'],
        queryFn: () => api.alerts(token, { limit: 1 }),
        staleTime: 10_000,
      })
      firstAlertId.current = newest[0]?.alert_id ?? null
    } catch {
      firstAlertId.current = null
    }
    direction.current = 1
    setIndex(0)
    setActive(true)
  }, [queryClient, token])

  const go = useCallback(
    (delta) => {
      direction.current = delta
      setIndex((current) => {
        const next = current + delta
        if (next >= steps.length) {
          stop()
          return current
        }
        return Math.max(0, next)
      })
    },
    [steps.length, stop],
  )

  // Arrive at the step: route there if needed, find the element, bring it into view.
  const step = active ? steps[index] : null
  useEffect(() => {
    if (!step) return undefined
    let cancelled = false
    const route =
      typeof step.route === 'function' ? step.route({ firstAlertId: firstAlertId.current }) : step.route
    if (route === null) {
      go(direction.current)
      return undefined
    }
    if (location.pathname !== route) {
      navigate(route)
      return undefined
    }
    setTarget(null)
    waitFor(`[data-tour="${step.target}"]`, FIND_TIMEOUT_MS).then((element) => {
      if (cancelled) return
      if (element === null) {
        go(direction.current)
        return
      }
      const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
      element.scrollIntoView({ block: 'center', behavior: reduced ? 'auto' : 'smooth' })
      setTarget(element)
    })
    return () => {
      cancelled = true
    }
  }, [step, location.pathname, navigate, go])

  const value = useMemo(
    () => ({ start, stop, active, invited, dismissInvite: stop }),
    [start, stop, active, invited],
  )

  return (
    <TourContext.Provider value={value}>
      {children}
      {active && step && (
        <Spotlight
          target={target}
          step={step}
          index={index}
          total={steps.length}
          onNext={() => go(1)}
          onBack={() => go(-1)}
          onClose={stop}
        />
      )}
      {!active && invited && token && <Invitation onStart={start} onDismiss={stop} />}
    </TourContext.Provider>
  )
}

export function useTour() {
  const context = useContext(TourContext)
  if (context === null) throw new Error('useTour must be used inside a TourProvider')
  return context
}

/** Follows the element as the page scrolls or reflows. */
function useRect(element) {
  const [rect, setRect] = useState(null)
  useLayoutEffect(() => {
    if (!element) return undefined
    let frame = 0
    const read = () => {
      const box = element.getBoundingClientRect()
      setRect((previous) =>
        previous &&
        previous.top === box.top &&
        previous.left === box.left &&
        previous.width === box.width &&
        previous.height === box.height
          ? previous
          : { top: box.top, left: box.left, width: box.width, height: box.height },
      )
      frame = requestAnimationFrame(read)
    }
    read()
    return () => cancelAnimationFrame(frame)
  }, [element])
  // A rect read for an element that has since gone is not where anything is.
  return element ? rect : null
}

/**
 * @param {{target: Element | null, step: import('./steps').TourStep, index: number,
 *   total: number, onNext: () => void, onBack: () => void, onClose: () => void}} props
 */
function Spotlight({ target, step, index, total, onNext, onBack, onClose }) {
  const rect = useRect(target)
  const cardRef = useRef(null)
  const [cardBox, setCardBox] = useState(null)

  useEffect(() => {
    const onKey = (event) => {
      if (event.key === 'Escape') onClose()
      else if (event.key === 'ArrowRight') onNext()
      else if (event.key === 'ArrowLeft') onBack()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onNext, onBack, onClose])

  // Focus the card's heading at each stop, so a screen reader announces it.
  const ready = rect !== null
  useEffect(() => {
    if (ready) cardRef.current?.querySelector('h2')?.focus()
  }, [step.id, ready])

  useLayoutEffect(() => {
    if (!cardRef.current) return
    const box = cardRef.current.getBoundingClientRect()
    setCardBox({ width: box.width, height: box.height })
  }, [step.id])

  const hole = rect && {
    top: rect.top - PAD,
    left: rect.left - PAD,
    width: rect.width + PAD * 2,
    height: rect.height + PAD * 2,
  }

  // Below the element if there is room, above if not, and docked at the bottom on a
  // phone, where a card beside the element would cover it.
  let cardStyle = { left: '50%', bottom: 24, transform: 'translateX(-50%)' }
  if (hole && cardBox && window.innerWidth >= 640) {
    const spaceBelow = window.innerHeight - (hole.top + hole.height)
    const top =
      spaceBelow >= cardBox.height + 16
        ? hole.top + hole.height + 12
        : hole.top >= cardBox.height + 16
          ? hole.top - cardBox.height - 12
          : Math.max(16, window.innerHeight - cardBox.height - 16)
    const left = Math.min(
      Math.max(16, hole.left + hole.width / 2 - cardBox.width / 2),
      window.innerWidth - cardBox.width - 16,
    )
    cardStyle = { top, left }
  }

  const progress = total > 1 ? index / (total - 1) : 1

  return createPortal(
    <div className="tour" data-testid="tour">
      {/* Four panes around the hole block the page; the hole itself lets the pointer through. */}
      {hole ? (
        <>
          <div className="tour-shade" style={{ top: 0, left: 0, right: 0, height: Math.max(0, hole.top) }} />
          <div
            className="tour-shade"
            style={{ top: hole.top + hole.height, left: 0, right: 0, bottom: 0 }}
          />
          <div
            className="tour-shade"
            style={{ top: hole.top, left: 0, width: Math.max(0, hole.left), height: hole.height }}
          />
          <div
            className="tour-shade"
            style={{ top: hole.top, left: hole.left + hole.width, right: 0, height: hole.height }}
          />
          <div
            className="tour-ring"
            style={{ top: hole.top, left: hole.left, width: hole.width, height: hole.height }}
            aria-hidden="true"
          />
        </>
      ) : (
        <div className="tour-shade" style={{ inset: 0 }} />
      )}

      <div
        ref={cardRef}
        role="dialog"
        aria-modal="false"
        aria-labelledby="tour-title"
        className="tour-card panel fixed z-[61] w-[min(24rem,calc(100vw-2rem))] p-5"
        style={cardStyle}
      >
        <div className="mb-4 flex items-center justify-between gap-3">
          <div className="tour-line" aria-hidden="true">
            <span className="tour-line-track" />
            <span className="tour-line-done" style={{ scale: `${progress} 1` }} />
            {Array.from({ length: total }, (_, stop) => (
              <span
                key={stop}
                className={`tour-stop ${stop <= index ? 'tour-stop-done' : ''}`}
                style={{ left: `${total > 1 ? (stop / (total - 1)) * 100 : 0}%` }}
              />
            ))}
            <span className="tour-train" style={{ left: `${progress * 100}%` }} />
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Leave the tour"
            className="press -mr-1 rounded p-1 text-ink-faint hover:bg-sunk hover:text-ink"
          >
            <X size={16} weight="bold" aria-hidden="true" />
          </button>
        </div>
        <p className="text-xs font-semibold tracking-wide text-ink-faint" aria-live="polite">
          Stop {index + 1} of {total}
        </p>
        <h2 id="tour-title" tabIndex={-1} className="mt-1 text-lg font-bold outline-none">
          {step.title}
        </h2>
        <p className="mt-1.5 text-[0.9375rem] leading-relaxed text-ink-dim">{step.body}</p>
        <div className="mt-5 flex items-center gap-2">
          <button
            type="button"
            onClick={onBack}
            disabled={index === 0}
            className="control press inline-flex items-center gap-1.5 disabled:opacity-40"
          >
            <ArrowLeft size={14} weight="bold" aria-hidden="true" /> Back
          </button>
          <button
            type="button"
            onClick={onNext}
            className="press btn-primary ml-auto inline-flex h-9 items-center gap-1.5 rounded-md px-4 text-sm font-semibold"
          >
            {index === total - 1 ? 'Finish' : 'Next'}
            <ArrowRight size={14} weight="bold" aria-hidden="true" />
          </button>
        </div>
      </div>
    </div>,
    document.body,
  )
}

/** @param {{onStart: () => void, onDismiss: () => void}} props */
function Invitation({ onStart, onDismiss }) {
  return (
    <aside
      className="tour-invite panel fixed right-4 bottom-4 z-40 w-[min(22rem,calc(100vw-2rem))] p-5"
      aria-labelledby="tour-invite-title"
      data-testid="tour-invite"
    >
      <div className="flex items-start gap-3">
        <span className="sign-square sign-square-lit mt-0.5 shrink-0" aria-hidden="true">
          <Signpost size={18} weight="bold" />
        </span>
        <div>
          <h2 id="tour-invite-title" className="font-bold">
            New here? Follow the line.
          </h2>
          <p className="mt-1 text-sm leading-relaxed text-ink-dim">
            A two-minute walk through what this console shows, what the alerts mean, and what
            you can do about them.
          </p>
          <div className="mt-4 flex gap-2">
            <button
              type="button"
              onClick={onStart}
              className="press btn-primary inline-flex h-9 items-center rounded-md px-4 text-sm font-semibold"
            >
              Start the tour
            </button>
            <button type="button" onClick={onDismiss} className="control press">
              Not now
            </button>
          </div>
        </div>
      </div>
    </aside>
  )
}

/** The header's Tour sign. */
export function TourButton() {
  const { start, active } = useTour()
  return (
    <button
      type="button"
      onClick={start}
      disabled={active}
      className="press flex h-9 items-center gap-2 rounded-md border border-line px-2.5 text-sm text-ink-dim hover:border-line-strong hover:text-ink disabled:opacity-50"
      title="Take the guided tour"
    >
      <Signpost size={16} weight="bold" aria-hidden="true" />
      <span className="hidden xl:inline">Tour</span>
      <span className="sr-only xl:hidden">Take the guided tour</span>
    </button>
  )
}
