/**
 * The NetSentinel mark: a shield around one watched flow - two hosts and the link
 * between them. Drawn on the currentColor stroke so it takes the colour of wherever it
 * sits.
 *
 * @param {{size?: number, className?: string}} props
 */
export function Mark({ size = 20, className = '' }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className={className}
    >
      <path d="M12 2.75 4.5 5.6v5.9c0 4.6 3.1 8.2 7.5 9.75 4.4-1.55 7.5-5.15 7.5-9.75V5.6L12 2.75Z" />
      <circle cx="8.9" cy="13.4" r="1.55" />
      <circle cx="15.1" cy="9.6" r="1.55" />
      <path d="m10.25 12.55 3.5-2.1" />
    </svg>
  )
}
