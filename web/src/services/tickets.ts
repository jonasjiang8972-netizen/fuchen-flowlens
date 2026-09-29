import { message } from 'antd'
import { ApiError, DEMO, errorMessage, request } from './http'

export type TicketStatus = 'pending' | 'processing' | 'review' | 'done' | 'false_positive'

export interface TicketEvent {
  at: string
  actor: string
  type: 'created' | 'assigned' | 'transition' | 'comment' | 'alert_action' | 'repeat'
  from?: string
  to?: string
  detail?: string
}

export interface Ticket {
  ticket_id: string
  title: string
  description?: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  status: TicketStatus
  owner?: string
  action?: string
  alert_id?: string
  related_alerts?: string[]
  related_count?: number
  auto_created?: boolean
  created_by: string
  created_at: string
  updated_at: string
  due_at: string
  closed_at?: string
  submitted_by?: string
  reopened?: number
  timeline: TicketEvent[]
  open: boolean
  overdue: boolean
  sla_percent: number
}

export interface TicketSummary {
  total: number
  open: number
  overdue: number
  at_risk: number
  unassigned: number
  by_status: Record<string, number>
  closed_7d: number
  mean_hours_to_close: number
  owner_coverage: number
}

export interface TicketFilter {
  status?: string
  severity?: string
  q?: string
  alert_id?: string
  open?: boolean
}

const emptySummary: TicketSummary = {
  total: 0, open: 0, overdue: 0, at_risk: 0, unassigned: 0, by_status: {}, closed_7d: 0, mean_hours_to_close: 0, owner_coverage: 0,
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

const qs = (f: TicketFilter) => {
  const p = new URLSearchParams()
  if (f.status) p.set('status', f.status)
  if (f.severity) p.set('severity', f.severity)
  if (f.q) p.set('q', f.q)
  if (f.alert_id) p.set('alert_id', f.alert_id)
  if (f.open) p.set('open', 'true')
  const s = p.toString()
  return s ? `?${s}` : ''
}

// The actions, in the shape the platform expects. They throw on failure so
// the page can show the platform's reason (missing note, same reviewer, ...).
export const ticketService = {
  list: (f: TicketFilter = {}) => read<Ticket[]>(
    async () => (await request<{ items: Ticket[] }>(`/tickets${qs(f)}`)).items,
    () => demo.list(f), [],
  ),
  summary: () => read<TicketSummary>(() => request('/tickets/summary'), () => demo.summary(), emptySummary),
  get: (id: string) => (DEMO ? Promise.resolve(demo.get(id)) : request<Ticket>(`/tickets/${encodeURIComponent(id)}`)),
  create: (body: { title?: string; description?: string; severity?: string; owner?: string; action?: string; alert_id?: string }) =>
    (DEMO ? demo.create(body) : request<Ticket>('/tickets', { method: 'POST', body: JSON.stringify(body) })),
  transition: (id: string, to: TicketStatus, note?: string, owner?: string) =>
    (DEMO ? demo.transition(id, to, note, owner) : request<Ticket>(`/tickets/${encodeURIComponent(id)}/transition`, { method: 'POST', body: JSON.stringify({ to, note, owner }) })),
  assign: (id: string, owner: string) =>
    (DEMO ? demo.assign(id, owner) : request<Ticket>(`/tickets/${encodeURIComponent(id)}/assign`, { method: 'POST', body: JSON.stringify({ owner }) })),
  comment: (id: string, text: string) =>
    (DEMO ? demo.comment(id, text) : request<Ticket>(`/tickets/${encodeURIComponent(id)}/comment`, { method: 'POST', body: JSON.stringify({ text }) })),
}

// ─── Demo build ─────────────────────────────────────────────────
// The static demo has no platform, so the same rules run against in-memory
// tickets: the workflow can be tried, and nothing is saved.

const SLA_HOURS: Record<string, number> = { critical: 4, high: 24, medium: 72, low: 168 }
const NEXT: Record<string, string[]> = {
  pending: ['processing', 'false_positive'],
  processing: ['review', 'false_positive'],
  review: ['done', 'processing', 'false_positive'],
  done: ['processing'],
  false_positive: ['processing'],
}
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString()
const H = 3600_000

const store: Ticket[] = []
let seq = 0

function mk(t: Partial<Ticket> & Pick<Ticket, 'title' | 'severity' | 'status'>, ageH: number): Ticket {
  seq += 1
  const created = iso(ageH * H)
  const tk: Ticket = {
    ticket_id: `TKT-${String(seq).padStart(4, '0')}`, created_by: 'system', created_at: created, updated_at: created,
    due_at: new Date(Date.now() - ageH * H + SLA_HOURS[t.severity] * H).toISOString(), open: true, overdue: false, sla_percent: 0,
    timeline: [{ at: created, actor: t.created_by || 'system', type: 'created', detail: `SLA ${SLA_HOURS[t.severity]}h` }], ...t,
  }
  store.push(tk)
  return tk
}

function seed() {
  if (store.length) return
  mk({ title: '疑似 BOLA 攻击：账号 usr-88213 高频遍历订单对象', severity: 'high', status: 'processing', owner: '订单安全接口人', alert_id: 'alt-001', action: '限制该账号访问，核查对象级鉴权', auto_created: true }, 3)
  mk({ title: '撞库攻击：单 IP 尝试 68 个不同账号', severity: 'critical', status: 'pending', alert_id: 'alt-002', related_count: 2, related_alerts: ['alt-002b', 'alt-002c'], action: '封禁来源 IP，通知 IAM 对涉及账号强制改密', auto_created: true }, 3.5)
  mk({ title: '未脱敏身份证号', severity: 'high', status: 'review', owner: '用户服务 Owner', alert_id: 'alt-005', submitted_by: '张三', action: '修复响应字段脱敏并回归验证', auto_created: true }, 9)
  mk({ title: '支付接口撞库', severity: 'critical', status: 'processing', owner: '安全运营', alert_id: 'alt-006', action: '封禁来源 IP，通知 IAM 对涉及账号强制改密', auto_created: true }, 1)
  const done = mk({ title: 'legacy/export 影子 API 纳管', severity: 'medium', status: 'done', owner: '平台工程', action: '补 CMDB 与 Owner，接入网关策略' }, 60)
  done.open = false; done.closed_at = iso(20 * H); done.timeline.push({ at: iso(20 * H), actor: '李四', type: 'transition', from: 'review', to: 'done', detail: '已补登记' })
  const fp = mk({ title: '内部压测触发的遍历告警', severity: 'high', status: 'false_positive', owner: '安全运营' }, 30)
  fp.open = false; fp.closed_at = iso(28 * H); fp.timeline.push({ at: iso(28 * H), actor: '安全管理员', type: 'transition', from: 'pending', to: 'false_positive', detail: '压测平台 10.20.9.4 的定时任务' })
}

function derive(t: Ticket): Ticket {
  const open = t.status !== 'done' && t.status !== 'false_positive'
  const total = new Date(t.due_at).getTime() - new Date(t.created_at).getTime()
  const used = Date.now() - new Date(t.created_at).getTime()
  return { ...t, open, overdue: open && Date.now() > new Date(t.due_at).getTime(), sla_percent: open && total > 0 ? Math.round((used / total) * 100) : 0, timeline: [...t.timeline] }
}

const fail = (status: number, msg: string) => Promise.reject(new ApiError(status, msg))

const demo = {
  list(f: TicketFilter): Ticket[] {
    seed()
    const q = (f.q || '').toLowerCase()
    return store.map(derive)
      .filter(t => (!f.status || t.status === f.status) && (!f.severity || t.severity === f.severity) && (!f.alert_id || t.alert_id === f.alert_id) &&
        (!f.open || t.open) && (!q || `${t.title} ${t.ticket_id} ${t.owner || ''}`.toLowerCase().includes(q)))
      .reverse()
  },
  summary(): TicketSummary {
    seed()
    const all = store.map(derive)
    const open = all.filter(t => t.open)
    const by: Record<string, number> = {}
    all.forEach(t => { by[t.status] = (by[t.status] || 0) + 1 })
    return {
      total: all.length, open: open.length, overdue: open.filter(t => t.overdue).length,
      at_risk: open.filter(t => !t.overdue && t.sla_percent >= 80).length, unassigned: open.filter(t => !t.owner).length,
      by_status: by, closed_7d: all.filter(t => !t.open).length, mean_hours_to_close: 40,
      owner_coverage: open.length ? open.filter(t => t.owner).length / open.length : 0,
    }
  },
  get(id: string): Ticket {
    seed()
    const t = store.find(x => x.ticket_id === id)
    if (!t) throw new ApiError(404, '工单不存在')
    return derive(t)
  },
  create(body: { title?: string; description?: string; severity?: string; owner?: string; action?: string; alert_id?: string }): Promise<Ticket> {
    seed()
    if (body.alert_id) {
      const ex = store.find(t => t.alert_id === body.alert_id && t.status !== 'done' && t.status !== 'false_positive')
      if (ex) return fail(409, `该告警已有未关闭的工单 ${ex.ticket_id}`)
    }
    const title = (body.title || (body.alert_id ? `处置告警 ${body.alert_id}` : '')).trim()
    if (!title) return fail(400, '标题不能为空')
    const sev = (body.severity || 'high') as Ticket['severity']
    if (!SLA_HOURS[sev]) return fail(400, '等级必须是 critical、high、medium 或 low')
    const t = mk({ title, severity: sev, status: 'pending', owner: body.owner?.trim() || undefined, alert_id: body.alert_id, action: body.action, description: body.description, created_by: '演示用户' }, 0)
    return Promise.resolve(derive(t))
  },
  transition(id: string, to: TicketStatus, note?: string, owner?: string): Promise<Ticket> {
    seed()
    const t = store.find(x => x.ticket_id === id)
    if (!t) return fail(404, '工单不存在')
    if (!NEXT[t.status].includes(to)) return fail(409, `状态不能这样变更：${t.status} 不能直接变为 ${to}`)
    const n = (note || '').trim()
    const from = t.status
    if (owner?.trim()) t.owner = owner.trim()
    if (to === 'processing' && from === 'pending' && !t.owner) return fail(400, '开始处理前需要指定负责人')
    if (to === 'processing' && from !== 'pending' && !n) return fail(400, '请说明驳回或重新打开的原因')
    if (to === 'review' && !n) return fail(400, '提交复核时请填写处置说明')
    if (to === 'false_positive' && !n) return fail(400, '标记误报时请说明理由')
    const now = new Date().toISOString()
    if (to === 'review') t.submitted_by = '演示用户'
    if (to === 'processing' && (from === 'done' || from === 'false_positive')) {
      t.reopened = (t.reopened || 0) + 1
      t.closed_at = undefined
      t.due_at = new Date(Date.now() + SLA_HOURS[t.severity] * H).toISOString()
    }
    if (to === 'done' || to === 'false_positive') t.closed_at = now
    t.status = to
    t.updated_at = now
    t.timeline.push({ at: now, actor: '演示用户', type: 'transition', from, to, detail: n })
    return Promise.resolve(derive(t))
  },
  assign(id: string, owner: string): Promise<Ticket> {
    seed()
    const t = store.find(x => x.ticket_id === id)
    if (!t) return fail(404, '工单不存在')
    if (!owner.trim()) return fail(400, '负责人不能为空，且不超过 100 个字符')
    if (t.status === 'done' || t.status === 'false_positive') return fail(400, '已关闭的工单不能改派，请先重新打开')
    t.timeline.push({ at: new Date().toISOString(), actor: '演示用户', type: 'assigned', detail: t.owner ? `由 ${t.owner} 改派给 ${owner.trim()}` : `指派给 ${owner.trim()}` })
    t.owner = owner.trim()
    return Promise.resolve(derive(t))
  },
  comment(id: string, text: string): Promise<Ticket> {
    seed()
    const t = store.find(x => x.ticket_id === id)
    if (!t) return fail(404, '工单不存在')
    if (!text.trim()) return fail(400, '备注不能为空，且不超过 2000 个字符')
    t.timeline.push({ at: new Date().toISOString(), actor: '演示用户', type: 'comment', detail: text.trim() })
    return Promise.resolve(derive(t))
  },
}
