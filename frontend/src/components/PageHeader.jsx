/**
 * Every page opens with its sign and says what it is for, in one sentence anyone can
 * read. The description is visible text rather than a tooltip: the person who needs it
 * most is the one who does not know there is something to hover.
 *
 * @param {{title: string, description: string, icon?: import('react').ComponentType<any>,
 *   children?: import('react').ReactNode}} props
 */
export function PageHeader({ title, description, icon: Icon, children }) {
  return (
    <header className="rise-in mb-7 flex flex-wrap items-end justify-between gap-x-6 gap-y-4">
      <div className="flex max-w-3xl items-start gap-4">
        {Icon && (
          <span className="sign-square sign-square-lit mt-1 size-11 shrink-0" aria-hidden="true">
            <Icon size={24} weight="bold" />
          </span>
        )}
        <div>
          <h1 className="text-[1.75rem] leading-tight font-extrabold md:text-[2rem]">{title}</h1>
          <p className="mt-1.5 text-[0.9375rem] leading-relaxed text-ink-dim">{description}</p>
        </div>
      </div>
      {children && <div className="flex flex-wrap items-center gap-2">{children}</div>}
    </header>
  )
}
