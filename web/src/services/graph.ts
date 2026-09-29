import { message } from 'antd'
import type { GraphLink, GraphNode } from '../components/ForceGraph'
import { ApiError, DEMO, errorMessage, request } from './http'

export interface GraphStats {
  total_nodes: number
  total_edges: number
  shown_edges: number
  truncated: boolean
  dropped: number
}

export interface FlowGraph {
  nodes: GraphNode[]
  edges: GraphLink[]
  stats: GraphStats
}

export interface AttackStep {
  stage: string
  rank: number
  alert_id: string
  title: string
  severity: string
  time: string
}

export interface AttackPathSummary {
  actor: string
  accounts?: string[]
  zone: string
  steps: AttackStep[]
  severity: string
  escalating: boolean
}

export interface AttackGraph extends FlowGraph {
  paths: AttackPathSummary[]
}

export type FlowView = 'business' | 'service' | 'data'

const emptyStats: GraphStats = { total_nodes: 0, total_edges: 0, shown_edges: 0, truncated: false, dropped: 0 }

// A failed read shows an error and an empty graph; sample data appears only
// in the static demo build so it is never mistaken for real findings.
async function read<T>(fn: () => Promise<T>, mock: () => T, empty: T): Promise<T> {
  if (DEMO) return mock()
  try {
    return await fn()
  } catch (err) {
    if (!(err instanceof ApiError && err.status === 401)) message.error(errorMessage(err))
    return empty
  }
}

const qs = (params: Record<string, string | number | undefined>) => {
  const p = new URLSearchParams()
  Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== '') p.set(k, String(v)) })
  const s = p.toString()
  return s ? `?${s}` : ''
}

export const graphService = {
  flow: (view: FlowView, keyword?: string) => read<FlowGraph>(
    () => request<FlowGraph>(`/graph/flow${qs({ view, q: keyword?.trim() })}`),
    () => mockFlow(view, keyword),
    { nodes: [], edges: [], stats: emptyStats },
  ),
  attack: (alertId?: string) => read<AttackGraph>(
    () => request<AttackGraph>(`/graph/attack${qs({ alert_id: alertId })}`),
    () => mockAttack(alertId),
    { nodes: [], edges: [], stats: emptyStats, paths: [] },
  ),
}

// ─── Demo build samples ──────────────────────────────────────────

const HOST = 'api.example.com'
const ep = (m: string, p: string) => `endpoint:${HOST}|${m}|${p}`

function mockFlow(view: FlowView, keyword?: string): FlowGraph {
  const now = new Date().toISOString()
  const n = (id: string, kind: string, label: string, layer: number, calls: number, extra: Partial<GraphNode> = {}): GraphNode =>
    ({ id, kind, label, layer, calls, ...extra, last_seen: now } as GraphNode)
  const nodes: GraphNode[] = [
    n('client:10.20.1.15', 'client', '10.20.1.15', 0, 420, { zone: 'internal' }),
    n('client:10.20.1.16', 'client', '10.20.1.16', 0, 210, { zone: 'internal' }),
    n('client:118.24.3.7', 'client', '118.24.3.7', 0, 37, { zone: 'external' }),
    n('client:198.51.100.22', 'client', '198.51.100.22', 0, 72, { zone: 'external', risk: 'medium', errors: 68 }),
    n(`service:${HOST}`, 'service', HOST, 1, 739),
    n(ep('GET', '/api/v1/user/{id}'), 'endpoint', 'GET /api/v1/user/{id}', 2, 243, { risk: 'high', detail: '敏感字段: email, phone' }),
    n(ep('GET', '/api/v1/order/{id}'), 'endpoint', 'GET /api/v1/order/{id}', 2, 205, { risk: 'high', detail: '敏感字段: recipient_phone' }),
    n(ep('POST', '/api/v1/payment/checkout'), 'endpoint', 'POST /api/v1/payment/checkout', 2, 90, { risk: 'high', detail: '敏感字段: card_number' }),
    n(ep('POST', '/api/v1/auth/login'), 'endpoint', 'POST /api/v1/auth/login', 2, 69, { risk: 'medium', errors: 68 }),
    n(ep('POST', '/graphql'), 'endpoint', 'POST /graphql', 2, 120),
    n('field:phone', 'field', 'phone', 3, 243, { risk: 'high' }),
    n('field:email', 'field', 'email', 3, 243, { risk: 'high' }),
    n('field:recipient_phone', 'field', 'recipient_phone', 3, 205, { risk: 'high' }),
    n('field:card_number', 'field', 'card_number', 3, 90, { risk: 'high' }),
  ]
  const e = (source: string, target: string, calls: number, errors = 0): GraphLink => ({ source, target, kind: 'flow', calls, errors })
  const svc = `service:${HOST}`
  const edges: GraphLink[] = [
    e('client:10.20.1.15', svc, 420), e('client:10.20.1.16', svc, 210), e('client:118.24.3.7', svc, 37), e('client:198.51.100.22', svc, 72, 68),
    e(svc, ep('GET', '/api/v1/user/{id}'), 243), e(svc, ep('GET', '/api/v1/order/{id}'), 205), e(svc, ep('POST', '/api/v1/payment/checkout'), 90),
    e(svc, ep('POST', '/api/v1/auth/login'), 69, 68), e(svc, ep('POST', '/graphql'), 120),
    e(ep('GET', '/api/v1/user/{id}'), 'field:phone', 243), e(ep('GET', '/api/v1/user/{id}'), 'field:email', 243),
    e(ep('GET', '/api/v1/order/{id}'), 'field:recipient_phone', 205), e(ep('POST', '/api/v1/payment/checkout'), 'field:card_number', 90),
  ]
  const kw = (keyword || '').trim().toLowerCase()
  let keep = edges
  if (view === 'service') keep = edges.filter(x => x.source.startsWith('service:'))
  if (view === 'data') keep = edges.filter(x => x.target.startsWith('field:') || (x.source.startsWith('service:') && edges.some(f => f.source === x.target && f.target.startsWith('field:'))))
  if (kw) {
    const label = (id: string) => (nodes.find(x => x.id === id)?.label || '').toLowerCase()
    keep = keep.filter(x => label(x.source).includes(kw) || label(x.target).includes(kw))
  }
  const ids = new Set(keep.flatMap(x => [x.source as string, x.target as string]))
  return {
    nodes: nodes.filter(x => ids.has(x.id)), edges: keep,
    stats: { total_nodes: nodes.length, total_edges: edges.length, shown_edges: keep.length, truncated: false, dropped: 0 },
  }
}

function mockAttack(alertId?: string): AttackGraph {
  const t = (mins: number) => new Date(Date.now() - mins * 60000).toISOString()
  const n = (id: string, kind: string, label: string, layer: number, extra: Partial<GraphNode> = {}): GraphNode => ({ id, kind, label, layer, ...extra })
  const e = (source: string, target: string, label: string, calls = 1, kind = 'flow', errors = 0): GraphLink => ({ source, target, kind, label, calls, errors })

  const stuffing: AttackGraph = {
    nodes: [
      n('actor:198.51.100.22', 'actor', '198.51.100.22', 0, { zone: 'external', risk: 'critical' }),
      n('account:usr-30177', 'account', 'usr-30177', 1, { calls: 4 }),
      n(ep('POST', '/api/v1/auth/login'), 'endpoint', 'POST /api/v1/auth/login', 2, { calls: 69, errors: 68, risk: 'medium' }),
      n(ep('GET', '/api/v1/user/{id}'), 'endpoint', 'GET /api/v1/user/{id}', 2, { calls: 3, risk: 'high' }),
      n('field:phone', 'field', 'phone', 3, { risk: 'high' }),
      n('field:email', 'field', 'email', 3, { risk: 'high' }),
      n('alert:alt-002', 'alert', '撞库攻击：单 IP 尝试 68 个不同账号', 4, { risk: 'critical', detail: '凭据攻击 · 风险 96' }),
      n('alert:alt-005', 'alert', '未脱敏身份证号', 4, { risk: 'high', detail: '数据外泄 · 风险 82' }),
    ],
    edges: [
      e('actor:198.51.100.22', 'account:usr-30177', '登录使用', 4),
      e('actor:198.51.100.22', ep('POST', '/api/v1/auth/login'), '69 次 · 68 失败', 69, 'flow', 68),
      e('account:usr-30177', ep('GET', '/api/v1/user/{id}'), '3 次', 3),
      e(ep('GET', '/api/v1/user/{id}'), 'field:phone', '', 3), e(ep('GET', '/api/v1/user/{id}'), 'field:email', '', 3),
      e('actor:198.51.100.22', 'alert:alt-002', '触发·凭据攻击'), e('actor:198.51.100.22', 'alert:alt-005', '触发·数据外泄'),
      e('alert:alt-002', 'alert:alt-005', '后续', 1, 'sequence'),
    ],
    stats: emptyStats,
    paths: [{
      actor: '198.51.100.22', accounts: ['usr-30177'], zone: 'external', severity: 'critical', escalating: true,
      steps: [
        { stage: '凭据攻击', rank: 2, alert_id: 'alt-002', title: '撞库攻击：单 IP 尝试 68 个不同账号', severity: 'critical', time: t(30) },
        { stage: '数据外泄', rank: 5, alert_id: 'alt-005', title: '未脱敏身份证号', severity: 'high', time: t(19) },
      ],
    }],
  }
  const bola: AttackGraph = {
    nodes: [
      n('actor:203.0.113.18', 'actor', '203.0.113.18', 0, { zone: 'external', risk: 'high' }),
      n('account:usr-88213', 'account', 'usr-88213', 1, { calls: 146 }),
      n(ep('GET', '/api/v1/order/{id}'), 'endpoint', 'GET /api/v1/order/{id}', 2, { calls: 140, risk: 'high' }),
      n(ep('GET', '/api/v1/admin/users'), 'endpoint', 'GET /api/v1/admin/users', 2, { calls: 6, errors: 6 }),
      n('field:recipient_phone', 'field', 'recipient_phone', 3, { risk: 'high' }),
      n('alert:alt-001', 'alert', '疑似 BOLA 攻击：账号 usr-88213 高频遍历订单对象', 4, { risk: 'high', detail: '对象枚举 · 风险 91' }),
    ],
    edges: [
      e('actor:203.0.113.18', 'account:usr-88213', '登录使用', 146),
      e('account:usr-88213', ep('GET', '/api/v1/order/{id}'), '140 次', 140),
      e('account:usr-88213', ep('GET', '/api/v1/admin/users'), '6 次 · 6 失败', 6, 'flow', 6),
      e(ep('GET', '/api/v1/order/{id}'), 'field:recipient_phone', '', 140),
      e('actor:203.0.113.18', 'alert:alt-001', '触发·对象枚举'),
    ],
    stats: emptyStats,
    paths: [{
      actor: '203.0.113.18', accounts: ['usr-88213'], zone: 'external', severity: 'high', escalating: false,
      steps: [{ stage: '对象枚举', rank: 3, alert_id: 'alt-001', title: '疑似 BOLA 攻击：账号 usr-88213 高频遍历订单对象', severity: 'high', time: t(5) }],
    }],
  }
  const all = [stuffing, bola]
  const pick = alertId ? all.filter(g => g.paths[0].steps.some(s => s.alert_id === alertId)) : all
  const src = pick.length ? pick : all
  const nodes = new Map<string, GraphNode>()
  src.forEach(g => g.nodes.forEach(x => nodes.set(x.id, x)))
  const edges = src.flatMap(g => g.edges)
  return {
    nodes: Array.from(nodes.values()), edges, paths: src.flatMap(g => g.paths),
    stats: { total_nodes: nodes.size, total_edges: edges.length, shown_edges: edges.length, truncated: false, dropped: 0 },
  }
}
