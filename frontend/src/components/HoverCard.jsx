/**
 * Detail that appears on hover, and on keyboard focus.
 *
 * The console's numbers and rows each carry more than fits in them - a severity's share
 * of everything, an alert's reasons. This shows that detail beside the thing without a
 * click. Everything it shows is also reachable by opening the item, so it adds speed,
 * never information that only a mouse can reach; and keyboard focus opens it too.
 *
 * The card is informational (role="tooltip"), ignores the pointer so it never flickers
 * under the cursor, renders in a portal so a scrolling board cannot clip it, and closes
 * on Escape, on scroll, and when the pointer or focus leaves.
 */

import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'

const GAP = 10
const MARGIN = 12

/**
 * @param {{content: () => import('react').ReactNode, children: import('react').ReactNode,
 *   as?: keyof JSX.IntrinsicElements, className?: string, delay?: number,
 *   width?: number}} props
 */
export function HoverCard({ content, children, as: Tag = 'span', className = '', delay = 140, width = 320 }) {
  const [open, setOpen] = useState(false)
  const [position, setPosition] = useState(null)
  const anchorRef = useRef(null)
  const cardRef = useRef(null)
  const timer = useRef(0)
  const id = useId()

  const show = useCallback(() => {
    window.clearTimeout(timer.current)
    timer.current = window.setTimeout(() => setOpen(true), delay)
  }, [delay])
  const hide = useCallback(() => {
    window.clearTimeout(timer.current)
    setOpen(false)
    setPosition(null)
  }, [])

  useEffect(() => () => window.clearTimeout(timer.current), [])

  useEffect(() => {
    if (!open) return undefined
    const onKey = (event) => {
      if (event.key === 'Escape') hide()
    }
    window.addEventListener('keydown', onKey)
    window.addEventListener('scroll', hide, true)
    window.addEventListener('resize', hide)
    return () => {
      window.removeEventListener('keydown', onKey)
      window.removeEventListener('scroll', hide, true)
      window.removeEventListener('resize', hide)
    }
  }, [open, hide])

  // Placed below the anchor when it fits, above when it does not, and never off-screen.
  useLayoutEffect(() => {
    if (!open || !anchorRef.current || !cardRef.current) return
    const anchor = anchorRef.current.getBoundingClientRect()
    const card = cardRef.current.getBoundingClientRect()
    const below = anchor.bottom + GAP + card.height <= window.innerHeight - MARGIN
    const top = below ? anchor.bottom + GAP : Math.max(MARGIN, anchor.top - GAP - card.height)
    const left = Math.min(
      Math.max(MARGIN, anchor.left + anchor.width / 2 - card.width / 2),
      window.innerWidth - card.width - MARGIN,
    )
    setPosition({ top, left, below })
  }, [open])

  return (
    <Tag
      ref={anchorRef}
      className={className}
      onPointerEnter={(event) => event.pointerType === 'mouse' && show()}
      onPointerLeave={hide}
      onFocus={show}
      onBlur={hide}
      aria-describedby={open ? id : undefined}
    >
      {children}
      {open &&
        createPortal(
          <div
            ref={cardRef}
            id={id}
            role="tooltip"
            className="hover-card panel pointer-events-none fixed z-50 p-4 text-sm"
            data-side={position?.below === false ? 'top' : 'bottom'}
            style={{
              width: `min(${width}px, calc(100vw - ${MARGIN * 2}px))`,
              top: position?.top ?? -9999,
              left: position?.left ?? -9999,
              visibility: position ? 'visible' : 'hidden',
            }}
          >
            {content()}
          </div>,
          document.body,
        )}
    </Tag>
  )
}
