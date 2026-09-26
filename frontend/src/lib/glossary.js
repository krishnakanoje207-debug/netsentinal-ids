/**
 * Plain-language names for everything the system measures and decides.
 *
 * One place, so a feature is called the same thing on every screen, and so a person
 * who has never seen a NetFlow record can read an explanation without a manual. Keys
 * are the contract names the API sends; anything missing here falls back to the raw
 * name rather than being hidden.
 */

/** What each model input measures, in words. */
export const FEATURES = {
  proto: { label: 'Protocol', hint: 'TCP, UDP or ICMP: the kind of connection' },
  l4_src_port: { label: 'Source port', hint: 'The port the connection came from' },
  l4_dst_port: { label: 'Destination port', hint: 'The service being contacted, e.g. 22 is SSH, 80 is web' },
  duration_ms: { label: 'Connection length', hint: 'How long the conversation lasted' },
  in_pkts: { label: 'Packets sent', hint: 'Packets from the initiator' },
  out_pkts: { label: 'Packets returned', hint: 'Packets sent back by the target' },
  in_bytes: { label: 'Data sent', hint: 'Bytes from the initiator' },
  out_bytes: { label: 'Data returned', hint: 'Bytes sent back by the target' },
  pkt_rate: { label: 'Packets per second', hint: 'How fast packets flowed' },
  byte_rate: { label: 'Data per second', hint: 'How fast data flowed' },
  bytes_per_pkt_in: { label: 'Size of sent packets', hint: 'Average bytes per packet sent' },
  bytes_per_pkt_out: { label: 'Size of returned packets', hint: 'Average bytes per packet returned' },
  bytes_ratio_out_in: { label: 'Reply-to-request ratio', hint: 'Data returned for every byte sent' },
}

/** @param {string} name */
export function featureLabel(name) {
  return FEATURES[name]?.label ?? name.replace(/_/g, ' ')
}

/** What a severity asks of whoever is reading it. */
export const SEVERITY_MEANING = {
  critical: 'Almost certainly an attack. Look now.',
  high: 'Likely an attack. Look today.',
  medium: 'Suspicious. Worth a look.',
  low: 'Unusual but probably harmless.',
  info: 'Recorded for context only.',
}

/** Where an alert is in its life, and who moved it there. */
export const STATUS_MEANING = {
  new: 'Nobody has looked at it yet',
  triaging: 'An analyst is looking at it',
  escalated: 'Turned into an incident case',
  closed_true_positive: 'Confirmed as a real attack',
  closed_false_positive: 'Confirmed as a false alarm',
}

/** What each account can do, said the way a person would say it. */
export const ROLES = {
  soc_analyst: {
    name: 'Security analyst',
    can: 'Reviews alerts, confirms or dismisses them, and approves or rejects blocks.',
  },
  administrator: {
    name: 'Administrator',
    can: 'Proposes blocks and manages the system. Cannot approve its own proposals.',
  },
  ml_engineer: {
    name: 'ML engineer',
    can: 'Watches how the detection models perform and decides when a new one goes live.',
  },
  viewer: {
    name: 'Viewer',
    can: 'Sees everything the analysts see. Changes nothing.',
  },
}

/** @param {string | null | undefined} role */
export function roleName(role) {
  if (!role) return 'Signed in'
  return ROLES[role]?.name ?? role.replace(/_/g, ' ')
}

/** The four detection tiers of the design, and what each one is for. */
export const TIERS = {
  A: { name: 'Pattern classifier', does: 'Trained on labelled attacks; recognises the ones it has seen.' },
  B: { name: 'Sequence model', does: 'Reads the first packets of a connection.' },
  C: { name: 'Graph model', does: 'Looks at who talks to whom, for scans and lateral movement.' },
  D: { name: 'Anomaly detector', does: 'Trained only on normal traffic; objects to anything unfamiliar.' },
}

/**
 * A tier's deciding model is scored under "tier_a"; any further model of the same tier
 * (one kept in shadow beside it) under its own name, such as "tier_d_isolation_forest".
 *
 * @param {string} key
 */
export function tierName(key) {
  const match = /^tier_([a-z])(?:_(.+))?$/.exec(key)
  const tier = match ? TIERS[match[1].toUpperCase()] : undefined
  if (!tier) return key
  return match[2] ? `${tier.name} (${match[2].replace(/_/g, ' ')})` : tier.name
}

/** Whether a score key names a model scored beside its tier's deciding one. */
export function isWatchingOnly(key) {
  return !/^tier_[a-z]$/.test(key)
}

/** MITRE ATT&CK techniques this system can name, with their official titles. */
export const TECHNIQUES = {
  T1046: 'Network Service Discovery',
  T1190: 'Exploit Public-Facing Application',
  T1210: 'Exploitation of Remote Services',
  T1499: 'Endpoint Denial of Service',
  'T1595.002': 'Active Scanning: Vulnerability Scanning',
}

/** @param {string | null | undefined} id */
export function techniqueName(id) {
  if (!id) return null
  return TECHNIQUES[id.toUpperCase()] ?? null
}
