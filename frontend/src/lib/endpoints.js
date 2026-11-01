/** Names come from inventory or local network settings; address ranges never establish ownership. */
export function endpointName(address, assets = [], labels = {}) {
  if (!address) return { name: 'Unknown endpoint', hint: 'The sensor did not record an address.', known: false }
  if (labels[address]) return { name: labels[address], hint: 'Observed in this computer’s network settings or local DNS cache. A DNS name is not proof of ownership or location.', known: true }
  const asset = assets.find((item) => item.ip_address === address)
  if (asset?.hostname) {
    return { name: asset.hostname, hint: 'Name currently recorded in the local estate inventory. Older alerts may involve a different device at this address.', known: true }
  }
  const parts = address.split('.').map(Number)
  const ipv4 = parts.length === 4 && parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)
  const local = ipv4 && (parts[0] === 10 || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168))
  const loopback = address === '::1' || (ipv4 && parts[0] === 127)
  const linkLocal = (ipv4 && parts[0] === 169 && parts[1] === 254) || /^fe[89ab]/i.test(address)
  const privateV6 = /^f[cd]/i.test(address)
  const scope = loopback ? 'Loopback' : linkLocal ? 'Nearby device' : local || privateV6 ? 'Local device' : 'Network endpoint'
  return {
    name: `${scope} · ${address}`,
    hint: 'No device name is recorded for this address. Owner, service and location are unknown.',
    known: false,
  }
}
