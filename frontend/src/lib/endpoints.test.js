import { describe, expect, it } from 'vitest'

import { endpointName } from './endpoints'

describe('endpointName', () => {
  it('uses exact inventory matches and keeps unknown devices distinguishable', () => {
    expect(endpointName('10.0.0.5', [{ ip_address: '10.0.0.5', hostname: 'My laptop' }]).name).toBe('My laptop')
    expect(endpointName('10.0.0.6').name).toBe('Local device · 10.0.0.6')
    expect(endpointName('10.0.0.7').name).not.toBe(endpointName('10.0.0.6').name)
  })

  it('uses observed gateway and DNS labels without treating them as managed assets', () => {
    expect(endpointName('10.0.0.1', [], { '10.0.0.1': 'Network gateway / DNS server' }).name).toBe('Network gateway / DNS server')
  })

  it('does not invent a company or geography for a public or missing address', () => {
    const endpoint = endpointName('54.144.174.174')
    expect(endpoint.name).toBe('Network endpoint · 54.144.174.174')
    expect(endpoint.hint).toContain('Owner, service and location are unknown')
    expect(endpointName(null).name).toBe('Unknown endpoint')
    expect(endpointName('172.31.1.2').name).toContain('Local device')
    expect(endpointName('172.32.1.2').name).toContain('Network endpoint')
  })
})
