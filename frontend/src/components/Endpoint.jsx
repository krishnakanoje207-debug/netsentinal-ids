import { useQuery } from '@tanstack/react-query'

import { api } from '../api/client'
import { PERMISSIONS } from '../api/types'
import { useAuth } from '../auth/AuthContext'
import { endpointName } from '../lib/endpoints'

export function useEndpointInventory() {
  const { token, can } = useAuth()
  const { data } = useQuery({
    queryKey: ['assets'],
    queryFn: () => api.assets(token),
    enabled: token !== null && can(PERMISSIONS.assetsRead),
    staleTime: 60_000,
  })
  const labels = useQuery({
    queryKey: ['endpoint-labels'],
    queryFn: () => api.endpointLabels(token),
    enabled: token !== null && can(PERMISSIONS.alertsRead),
    staleTime: 60_000,
  })
  return { assets: data ?? [], labels: labels.data ?? {} }
}

export function Endpoint({ address, assets, onBoard = false }) {
  const endpoint = endpointName(address, assets.assets, assets.labels)
  return (
    <span className="block min-w-0 break-words" title={endpoint.hint}>
      <span className="block text-[0.8125rem] font-semibold">{endpoint.name}</span>
      {endpoint.known && <span className={`data block text-xs ${onBoard ? 'text-board-dim' : 'text-ink-dim'}`}>{address}</span>}
    </span>
  )
}
