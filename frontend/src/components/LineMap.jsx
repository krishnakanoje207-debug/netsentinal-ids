/**
 * How NetSentinel works, drawn as a transit line: Watch, Score, Explain, Decide.
 *
 * Each stop is a place in the console, and hovering it shows what is happening there
 * right now, from the same queries the rest of the page uses. When the live feed pushes
 * an alert, a marker runs the line once - so movement on this diagram always means a
 * real alert just passed through, and a quiet line means nothing did.
 */

import { Link } from 'react-router-dom'

import { useStream } from '../stream/StreamContext'
import { HoverCard } from './HoverCard'
import { Brain, ChartBar, Eye, Scales } from './icons'

/**
 * @typedef {object} LineStats
 * @property {number | null} flows flows checked in the last hour, null when unknown
 * @property {number | null} alerts every alert raised
 * @property {number | null} deciding models deciding, null when the role cannot see them
 * @property {number | null} watching models in shadow
 * @property {number | null} pending blocks waiting for a decision
 */

/** @param {number | null} value @param {string} unit */
function count(value, unit) {
  return value === null ? 'not available' : `${value.toLocaleString()} ${unit}`
}

/** @param {LineStats} stats */
function stopsFor(stats) {
  return [
    {
      id: 'watch',
      icon: Eye,
      name: 'Watch',
      to: '/alerts',
      text: 'Every network conversation is summarised into a few numbers: how long, how fast, how much data.',
      detail: [
        ['Flows checked, last hour', count(stats.flows, 'flows')],
        ['Read by', 'the flow sensor, Suricata and Zeek'],
      ],
    },
    {
      id: 'score',
      icon: Brain,
      name: 'Score',
      to: '/models',
      text: 'AI detectors rate each conversation. One knows known attacks; another objects to anything unusual.',
      detail: [
        ['Detectors deciding', stats.deciding === null ? 'your role cannot see the registry' : String(stats.deciding)],
        ['Watching in shadow', stats.watching === null ? '--' : String(stats.watching)],
      ],
    },
    {
      id: 'explain',
      icon: ChartBar,
      name: 'Explain',
      to: '/alerts',
      text: 'Each alert shows which measurements made it look like an attack, so a person can check the reasoning.',
      detail: [['Alerts raised so far', count(stats.alerts, 'alerts')]],
    },
    {
      id: 'decide',
      icon: Scales,
      name: 'Decide',
      to: '/approvals',
      text: 'Blocking an address always needs a person to approve it. The AI never acts alone.',
      detail: [['Blocks waiting for a person', count(stats.pending, 'waiting')]],
    },
  ]
}

/** @param {{stats: LineStats}} props */
export function LineMap({ stats }) {
  const { lastMessageAt } = useStream()
  const stops = stopsFor(stats)

  return (
    <section className="panel px-4 pt-5 pb-6 md:px-6" data-tour="line" aria-labelledby="line-heading">
      <h2 id="line-heading" className="text-lg font-extrabold tracking-tight">
        How NetSentinel works
      </h2>
      <p className="mt-1 text-[0.9375rem] text-ink-dim">
        Every alert travels this line. Hover a stop to see what is happening there now.
      </p>

      <ol className="line-map relative mt-6 grid gap-6 md:grid-cols-4 md:gap-4">
        <span className="line-track" aria-hidden="true">
          {lastMessageAt && <span key={lastMessageAt} className="line-traveller" />}
        </span>
        {stops.map(({ id, icon: Icon, name, to, text, detail }, index) => (
          <li key={id} className="relative">
            {index < stops.length - 1 && <span className="line-seg" aria-hidden="true" />}
            <HoverCard
              as="div"
              width={290}
              content={() => (
                <div>
                  <p className="font-bold">{name}</p>
                  <dl className="mt-2 grid grid-cols-[1fr_auto] gap-x-4 gap-y-1 text-[0.8125rem]">
                    {detail.map(([label, value]) => (
                      <div key={label} className="contents">
                        <dt className="text-ink-faint">{label}</dt>
                        <dd className="numeric text-right font-semibold">{value}</dd>
                      </div>
                    ))}
                  </dl>
                </div>
              )}
            >
              <Link to={to} viewTransition className="group flex gap-4 rounded-md outline-offset-4 md:block">
                <span className="line-stop" aria-hidden="true">
                  <Icon size={20} weight="bold" />
                </span>
                <span className="block md:mt-4">
                  <span className="block text-base font-bold group-hover:underline">{name}</span>
                  <span className="mt-1 block text-[0.9375rem] leading-relaxed text-ink-dim">{text}</span>
                </span>
              </Link>
            </HoverCard>
          </li>
        ))}
      </ol>
    </section>
  )
}
