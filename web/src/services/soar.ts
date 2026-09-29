import { message } from 'antd'
import { ApiError, DEMO, errorMessage, request } from './http'

export interface ConnectorStatus {
  name: string
  label: string
  status: 'unchecked' | 'ok' | 'error'
  last_checked?: string
  error?: string
  active_blocks: number
  experimental?: boolean
}

export interface SoarPolicy {
  dry_run: boolean
  allow_private: boolean
  protected_networks: string[]
  default_ttl_minutes: number
  max_ttl_minutes: number
  max_blocks_per_hour: number
}

export interface ConnectorsInfo {
  enabled: boolean
  connectors: ConnectorStatus[]
  policy: SoarPolicy
}

export interface BlockResult {
  connector: string
  ok: boolean
  ref?: string
  error?: string
  released?: boolean
}

export interface Block {
  id: string
  ip: string
  state: 'active' | 'released' | 'failed' | 'dry_run'
  reason?: string
  alert_id?: string
  operator?: string
  created_at: string
  expires_at: string
  results: BlockResult[]
  released_at?: string
  released_by?: string
}

const emptyInfo: ConnectorsInfo = {
  enabled: false, connectors: [],
  policy: { dry_run: false, allow_private: false, protected_networks: [], default_ttl_minutes: 60, max_ttl_minutes: 1440, max_blocks_per_hour: 30 },
}

async function read<T>(fn: () => Promise<T>, mock: () => T, empty: T): Promise<T> {
  if (DEMO) return mock()
  try {
    return await fn()
  } catch (err) {
    if (!(err instanceof ApiError && err.status === 401)) message.error(errorMessage(err))
    return empty
  }
}

// ─── Demo build state ───────────────────────────────────────────
// The static demo has no platform: blocks live in memory for the session and
// nothing is enforced anywhere.
const demoBlocks: Block[] = []
const demoConnectors: ConnectorStatus[] = [
  { name: 'simulator', label: '演示（模拟，不产生真实封禁）', status: 'unchecked', active_blocks: 0 },
]

const demoInfo = (): ConnectorsInfo => ({
  enabled: true,
  connectors: demoConnectors.map(c => ({ ...c, active_blocks: demoBlocks.filter(b => b.state === 'dry_run').length })),
  policy: { ...emptyInfo.policy, dry_run: true },
})

export const soarService = {
  connectors: () => read<ConnectorsInfo>(() => request('/soar/connectors'), demoInfo, emptyInfo),
  blocks: (activeOnly = false) => read<Block[]>(
    async () => (await request<{ items: Block[] }>(`/soar/blocks${activeOnly ? '?active=true' : ''}`)).items,
    () => demoBlocks.filter(b => !activeOnly || b.state === 'dry_run').slice().reverse(),
    [],
  ),
  // The three actions throw on failure so the page can show the platform's reason.
  test: async (name: string): Promise<ConnectorStatus> => {
    if (DEMO) {
      demoConnectors[0] = { ...demoConnectors[0], status: 'ok', last_checked: new Date().toISOString() }
      return demoConnectors[0]
    }
    return request<ConnectorStatus>(`/soar/connectors/${encodeURIComponent(name)}/test`, { method: 'POST', body: '{}' })
  },
  block: async (body: { ip: string; ttl_minutes?: number; reason?: string; alert_id?: string }): Promise<Block> => {
    if (DEMO) {
      const now = Date.now()
      const b: Block = {
        id: `blk-${now}`, ip: body.ip, state: 'dry_run', reason: body.reason, alert_id: body.alert_id, operator: '演示用户',
        created_at: new Date(now).toISOString(), expires_at: new Date(now + (body.ttl_minutes || 60) * 60000).toISOString(),
        results: [{ connector: 'simulator', ok: true, ref: 'dry-run' }],
      }
      demoBlocks.push(b)
      return b
    }
    return request<Block>('/soar/block', { method: 'POST', body: JSON.stringify(body) })
  },
  unblock: async (ip: string): Promise<Block> => {
    if (DEMO) {
      const b = demoBlocks.find(x => x.ip === ip && x.state === 'dry_run')
      if (!b) throw new ApiError(404, '该地址当前没有生效的封禁')
      b.state = 'released'
      b.results = b.results.map(r => ({ ...r, released: true }))
      b.released_at = new Date().toISOString()
      b.released_by = '演示用户'
      return b
    }
    return request<Block>('/soar/unblock', { method: 'POST', body: JSON.stringify({ ip }) })
  },
}
