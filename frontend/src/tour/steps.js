/**
 * The guided tour, stop by stop.
 *
 * Written for someone who has never seen a security console: what the thing on screen
 * is, and why it matters to them. Each stop points at a real element (its `data-tour`
 * value) on a real page; a stop whose element is not there - a role that cannot see the
 * page, a board with nothing on it yet - is skipped rather than pointed at empty space.
 */

import { PERMISSIONS } from '../api/types'

/**
 * @typedef {object} TourStep
 * @property {string} id
 * @property {string | ((context: {firstAlertId: number | null}) => string | null)} route
 * @property {string} target the element's data-tour value
 * @property {string} title
 * @property {string} body
 * @property {string} [requires] a permission the viewer must hold
 */

/** @type {TourStep[]} */
export const TOUR_STEPS = [
  {
    id: 'clock',
    route: '/',
    target: 'clock',
    title: 'Is it working?',
    body:
      "The station clock's red hand sweeps only while the live alert feed is connected. " +
      'If it stops at twelve, the feed has stopped, and the page says so. Silence never means safe.',
  },
  {
    id: 'headline',
    route: '/',
    target: 'headline',
    title: 'How things stand',
    body:
      'One sentence, counted across every alert the system has raised, not only the ones on screen. ' +
      'The numbers flip when they change.',
  },
  {
    id: 'severity',
    route: '/',
    target: 'severity',
    title: 'How serious',
    body:
      'Five levels, from Critical (look now) to Info (for context). Hover a level to see its share; ' +
      'click it to open exactly those alerts.',
  },
  {
    id: 'board',
    route: '/',
    target: 'board',
    title: 'The live board',
    body:
      'The newest alerts, posted as they arrive. Each row is one network connection the detectors ' +
      'flagged: when, how serious, from where to where. Hover a row for its reasons, click to open it.',
  },
  {
    id: 'activity',
    route: '/',
    target: 'activity',
    title: 'Real time, drawn to scale',
    body:
      'Each column is one minute. Bars are traffic the detectors checked; red marks are alerts. ' +
      'A gap is a minute when nothing arrived, shown as a gap.',
  },
  {
    id: 'line',
    route: '/',
    target: 'line',
    title: 'How NetSentinel works',
    body:
      'Watch, score, explain, decide. Every alert passes these four stops. Hover a stop to see what ' +
      'is happening there right now.',
  },
  {
    id: 'filters',
    route: '/alerts',
    target: 'filters',
    title: 'Find anything',
    body:
      'Search an address, a whole network such as 10.0.0.0/8, or an attack technique. ' +
      'An export always contains exactly what the filters show.',
  },
  {
    id: 'reasons',
    route: ({ firstAlertId }) => (firstAlertId === null ? null : `/alerts/${firstAlertId}`),
    target: 'reasons',
    title: 'Why it was flagged',
    body:
      "Bars to the right pulled the verdict toward 'attack', bars to the left toward 'normal'. " +
      'The model shows its working so a person can check it.',
  },
  {
    id: 'actions',
    route: ({ firstAlertId }) => (firstAlertId === null ? null : `/alerts/${firstAlertId}`),
    target: 'actions',
    title: 'What you can do',
    body:
      'Confirm it, dismiss it as a false alarm, open an incident, or propose blocking the address. ' +
      'Nothing is blocked until an analyst approves it.',
  },
  {
    id: 'responses',
    route: ({ firstAlertId }) => (firstAlertId === null ? null : `/alerts/${firstAlertId}`),
    target: 'responses',
    title: 'What was done about it',
    body:
      'Every block proposed for this alert, and where it stands: waiting, approved, in force or lifted. ' +
      'It updates by itself while the responder is still working.',
  },
  {
    id: 'approvals',
    route: '/approvals',
    target: 'approvals',
    title: 'A person decides',
    body:
      'Proposed blocks wait here. Approving authorises the block and the response system carries it ' +
      'out afterwards. Nobody can approve their own proposal.',
  },
  {
    id: 'estate',
    route: '/estate',
    target: 'estate',
    title: 'What is being protected',
    body:
      'Your own machines, and the known weaknesses a vulnerability scan found on each. The system ' +
      'refuses to block these addresses: a machine of your own is isolated instead.',
    requires: PERMISSIONS.assetsRead,
  },
  {
    id: 'models',
    route: '/models',
    target: 'models',
    title: 'Who is deciding',
    body:
      'The detectors that decide, and the ones still watching in shadow mode. A watching model is ' +
      'promoted only when the evidence says it has earned it.',
    requires: PERMISSIONS.modelsRead,
  },
  {
    id: 'theme',
    route: '/',
    target: 'theme',
    title: 'Day or night',
    body:
      'Switch to night mode when the room is dark. You can take this tour again at any time from ' +
      'the Tour sign at the top.',
  },
]
