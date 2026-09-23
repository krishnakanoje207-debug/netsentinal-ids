/**
 * Every page opens by saying what it is for, in one sentence anyone can read.
 *
 * The description is visible text rather than a tooltip: the person who needs it most
 * is the one who does not know there is something to hover.
 *
 * @param {{title: string, description: string, children?: import('react').ReactNode}} props
 */
export function PageHeader({ title, description, children }) {
  return (
    <header className="mb-6 flex flex-wrap items-end justify-between gap-x-6 gap-y-3">
      <div className="max-w-2xl">
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        <p className="mt-1 text-sm text-[var(--color-ink-dim)]">{description}</p>
      </div>
      {children && <div className="flex flex-wrap items-center gap-2">{children}</div>}
    </header>
  )
}
