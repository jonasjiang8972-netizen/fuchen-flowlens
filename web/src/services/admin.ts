import { API_BASE, DEMO, request } from './http'
import type { Policy, Role, UserView } from './auth'
import { ROLE_NAMES, consoleOf } from './auth'

export interface RoleInfo {
  role: Role
  name: string
  console: 'admin' | 'security'
  description: string
  permissions: string[]
}

export interface AuditRecord {
  seq: number
  time: string
  user_id: string
  username: string
  role: string
  source_ip: string
  console: string
  event_type: string
  target: string
  result: 'success' | 'failure'
  reason?: string
  detail?: string
  method?: string
  path?: string
  prev_hash: string
  hash: string
}

export interface AuditQuery {
  username?: string
  event_type?: string
  result?: string
  console?: string
  from?: string
  to?: string
  limit?: number
  offset?: number
}

export interface VerifyResult {
  ok: boolean
  checked: number
  first_seq: number
  last_seq: number
  broken_at?: number
  reason?: string
}

export interface UserInput {
  username?: string
  display_name: string
  email: string
  role: Role
  expires_at?: string | null
  password?: string
}

function qs(q: Record<string, unknown>) {
  const p = new URLSearchParams()
  Object.entries(q).forEach(([k, v]) => { if (v !== undefined && v !== '' && v !== null) p.set(k, String(v)) })
  const s = p.toString()
  return s ? `?${s}` : ''
}

export const adminService = {
  users: () => (DEMO ? Promise.resolve(demoUsers()) : request<{ items: UserView[] }>('/admin/users').then(r => r.items)),
  createUser: (in_: UserInput) => request<UserView>('/admin/users', { method: 'POST', body: JSON.stringify(in_) }),
  updateUser: (id: string, in_: UserInput) => request<UserView>(`/admin/users/${id}`, { method: 'PUT', body: JSON.stringify(in_) }),
  userAction: (id: string, action: 'enable' | 'disable' | 'unlock') =>
    request<UserView>(`/admin/users/${id}/${action}`, { method: 'POST', body: '{}' }),
  resetPassword: (id: string, password: string) =>
    request<UserView>(`/admin/users/${id}/reset-password`, { method: 'POST', body: JSON.stringify({ password }) }),
  deleteUser: (id: string) => request(`/admin/users/${id}`, { method: 'DELETE' }),

  roles: () => (DEMO ? Promise.resolve(demoRoles()) : request<{ items: RoleInfo[] }>('/admin/roles').then(r => r.items)),

  policy: () => (DEMO ? Promise.resolve({ policy: demoPolicy(), defaults: demoPolicy() })
    : request<{ policy: Policy; defaults: Policy }>('/admin/security-policy')),
  updatePolicy: (p: Policy) => request<{ policy: Policy }>('/admin/security-policy', { method: 'PUT', body: JSON.stringify(p) }),

  audit: (q: AuditQuery) => (DEMO ? Promise.resolve(demoAudit(q))
    : request<{ total: number; items: AuditRecord[] }>(`/admin/audit-logs${qs(q as Record<string, unknown>)}`)),
  verifyAudit: () => (DEMO ? Promise.resolve({ ok: true, checked: 1284, first_seq: 1, last_seq: 1284 } as VerifyResult)
    : request<VerifyResult>('/admin/audit-logs/verify')),
  auditExportUrl: (q: AuditQuery) => `${API_BASE}/admin/audit-logs/export${qs({ ...q, limit: undefined, offset: undefined } as Record<string, unknown>)}`,

  systemInfo: () => (DEMO ? Promise.resolve({ version: '0.7.0', storage: 'postgresql', secure_cookie: true, demo_mode: false,
    ingest: { accepted: 1523000, dropped: 182, duplicates: 936, processed: 1522416, queue_depth: 584, queue_size: 20000 } })
    : request<any>('/admin/system/info')),
}

// ─── Demo data ───────────────────────────────────────────────────

function demoPolicy(): Policy {
  return {
    password_min_length: 8, password_min_classes: 3, password_history: 5, password_max_age_days: 90,
    lockout_threshold: 5, lockout_minutes: 30, session_idle_minutes: 15, session_max_hours: 8,
    account_inactive_days: 90, audit_retention_days: 180, login_rate_per_ip_minute: 20,
  }
}

function demoUsers(): UserView[] {
  const ago = (h: number) => new Date(Date.now() - h * 3600000).toISOString()
  const row = (id: string, username: string, display_name: string, role: Role, extra: Partial<UserView> = {}): UserView => ({
    id, username, display_name, email: `${username}@bank.example`, role, role_name: ROLE_NAMES[role], console: consoleOf(role),
    status: 'active', locked: false, must_change_password: false, password_changed_at: ago(24 * 20),
    last_login_at: ago(2), last_login_ip: '10.20.1.15', created_by: 'system', created_at: ago(24 * 60), ...extra,
  })
  return [
    row('u1', 'sysadmin', '系统管理员', 'sys_admin', { last_login_at: ago(0.1) }),
    row('u2', 'auditadmin', '审计管理员', 'audit_admin', { last_login_at: ago(20) }),
    row('u3', 'secadmin', '安全管理员', 'sec_admin', { last_login_at: ago(1) }),
    row('u4', 'zhang.wei', '张伟', 'analyst', { created_by: 'sysadmin' }),
    row('u5', 'li.na', '李娜', 'analyst', { created_by: 'sysadmin', locked: true, locked_until: new Date(Date.now() + 1200000).toISOString() }),
    row('u6', 'wang.qiang', '王强', 'viewer', { created_by: 'sysadmin', must_change_password: true, last_login_at: undefined }),
    row('u7', 'chen.jie', '陈杰（外包）', 'viewer', { created_by: 'sysadmin', status: 'disabled', expires_at: ago(24 * 3) }),
  ]
}

function demoRoles(): RoleInfo[] {
  return [
    { role: 'sys_admin', name: '系统管理员', console: 'admin', description: '管理账号、安全策略、采集器和系统设置；不能查看审计日志，也不能操作 API 安全业务', permissions: ['user.manage', 'policy.manage', 'agent.manage', 'system.manage'] },
    { role: 'audit_admin', name: '审计管理员', console: 'admin', description: '查询、校验和导出审计日志；不能做其他任何操作', permissions: ['audit.read'] },
    { role: 'sec_admin', name: '安全管理员', console: 'security', description: '配置检测策略、处置告警、管理资产归属', permissions: ['security.read', 'rule.manage', 'alert.handle', 'asset.manage'] },
    { role: 'analyst', name: '安全分析员', console: 'security', description: '研判和处置告警、认领资产；不能修改检测策略', permissions: ['security.read', 'alert.handle', 'asset.manage'] },
    { role: 'viewer', name: '只读用户', console: 'security', description: '查看 API 安全数据，不能做任何修改', permissions: ['security.read'] },
  ]
}

function demoAudit(q: AuditQuery): { total: number; items: AuditRecord[] } {
  const base = [
    ['sysadmin', 'sys_admin', '10.20.1.15', 'admin', 'user.create', 'zhang.wei', 'success', '', 'role=analyst'],
    ['li.na', 'analyst', '10.20.3.41', 'auth', 'auth.login', 'li.na', 'failure', '口令错误（连续第 5 次），账号已锁定', ''],
    ['system', '', '', 'system', 'user.lock', 'li.na', 'success', '', '连续 5 次登录失败，锁定 30 分钟'],
    ['secadmin', 'sec_admin', '10.20.2.8', 'security', 'rule.update', 'id=R-BOLA-001', 'success', '', ''],
    ['zhang.wei', 'analyst', '10.20.2.19', 'security', 'alert.action', 'id=alt-001 action=block_ip', 'success', '', ''],
    ['sysadmin', 'sys_admin', '10.20.1.15', 'admin', 'access.denied', '/api/v1/admin/audit-logs', 'failure', '缺少权限 audit.read', ''],
    ['sysadmin', 'sys_admin', '10.20.1.15', 'admin', 'policy.update', 'security_policy', 'success', '', 'password_min_length 8 -> 10'],
    ['wang.qiang', 'viewer', '10.20.4.2', 'auth', 'auth.login', 'wang.qiang', 'success', '', '须修改口令后才能操作'],
    ['agent', 'agent', '10.30.0.11', 'agent', 'agent.register', 'agent-prod-k8s-01', 'success', '', 'hostname=k8s-node-sh-prod-01 mode=ebpf'],
    ['auditadmin', 'audit_admin', '10.20.1.22', 'admin', 'audit.export', '', 'success', '', 'event_type=auth.'],
  ]
  let items: AuditRecord[] = base.map((r, i) => ({
    seq: 1284 - i, time: new Date(Date.now() - i * 540000).toISOString(), user_id: '', username: r[0], role: r[1], source_ip: r[2],
    console: r[3], event_type: r[4], target: r[5], result: r[6] as 'success' | 'failure', reason: r[7], detail: r[8],
    prev_hash: (0x9a3f + i).toString(16).padStart(64, 'e'), hash: (0x7b21 + i).toString(16).padStart(64, 'c'),
  }))
  if (q.username) items = items.filter(r => r.username.toLowerCase() === q.username!.toLowerCase())
  if (q.event_type) items = items.filter(r => r.event_type.startsWith(q.event_type!))
  if (q.result) items = items.filter(r => r.result === q.result)
  return { total: items.length, items }
}
