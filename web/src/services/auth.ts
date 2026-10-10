import { DEMO, request } from './http'

export type Role = 'sys_admin' | 'audit_admin' | 'sec_admin' | 'analyst' | 'viewer'
export type Console = 'admin' | 'security'
export type Permission =
  | 'user.manage' | 'policy.manage' | 'agent.manage' | 'system.manage' | 'audit.read'
  | 'security.read' | 'rule.manage' | 'alert.handle' | 'asset.manage'

export interface UserView {
  id: string
  username: string
  display_name: string
  email: string
  role: Role
  role_name: string
  console: Console
  status: 'active' | 'disabled'
  locked: boolean
  locked_until?: string
  must_change_password: boolean
  mfa_enabled?: boolean
  must_enroll_mfa?: boolean
  password_changed_at: string
  last_login_at?: string
  last_login_ip: string
  expires_at?: string
  created_by: string
  created_at: string
}

export interface Policy {
  password_min_length: number
  password_min_classes: number
  password_history: number
  password_max_age_days: number
  lockout_threshold: number
  lockout_minutes: number
  session_idle_minutes: number
  session_max_hours: number
  account_inactive_days: number
  audit_retention_days: number
  login_rate_per_ip_minute: number
  mfa_required_admins?: boolean
}

export interface Session {
  user: UserView
  console: Console
  permissions: Permission[]
  must_change_password: boolean
  must_enroll_mfa?: boolean
  policy?: Policy
}

// The password step either opens a session or, with two-factor
// authentication on, asks for the authenticator code.
export type LoginResponse = (Session & { expires_at: string; mfa_required?: false }) | { mfa_required: true; mfa_token: string }

export interface MFASetup {
  secret: string
  otpauth_uri: string
}

export const ROLE_NAMES: Record<Role, string> = {
  sys_admin: '系统管理员',
  audit_admin: '审计管理员',
  sec_admin: '安全管理员',
  analyst: '安全分析员',
  viewer: '只读用户',
}

const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  sys_admin: ['user.manage', 'policy.manage', 'agent.manage', 'system.manage'],
  audit_admin: ['audit.read'],
  sec_admin: ['security.read', 'rule.manage', 'alert.handle', 'asset.manage'],
  analyst: ['security.read', 'alert.handle', 'asset.manage'],
  viewer: ['security.read'],
}

export const consoleOf = (role: Role): Console => (role === 'sys_admin' || role === 'audit_admin' ? 'admin' : 'security')

// Demo identities for the static preview (no backend).
export function demoSession(role: Role): Session {
  const names: Record<Role, string> = { sys_admin: 'sysadmin', audit_admin: 'auditadmin', sec_admin: 'secadmin', analyst: 'zhang.wei', viewer: 'viewer' }
  return {
    user: {
      id: `demo-${role}`, username: names[role], display_name: ROLE_NAMES[role], email: '', role, role_name: ROLE_NAMES[role],
      console: consoleOf(role), status: 'active', locked: false, must_change_password: false,
      password_changed_at: new Date().toISOString(), last_login_ip: '10.0.0.8', created_by: 'system', created_at: new Date().toISOString(),
    },
    console: consoleOf(role),
    permissions: ROLE_PERMISSIONS[role],
    must_change_password: false,
  }
}

export const authService = {
  login: (username: string, password: string) =>
    request<LoginResponse>('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  loginMfa: (mfaToken: string, code: string) =>
    request<Session & { expires_at: string }>('/auth/login/mfa', { method: 'POST', body: JSON.stringify({ mfa_token: mfaToken, code }) }),
  mfaSetup: () => request<MFASetup>('/auth/mfa/setup', { method: 'POST' }),
  mfaEnable: (code: string) => request('/auth/mfa/enable', { method: 'POST', body: JSON.stringify({ code }) }),
  mfaDisable: (password: string, code: string) =>
    request('/auth/mfa/disable', { method: 'POST', body: JSON.stringify({ password, code }) }),
  me: () => request<Session>('/auth/me'),
  logout: () => (DEMO ? Promise.resolve() : request('/auth/logout', { method: 'POST' })),
  changePassword: (oldPassword: string, newPassword: string) =>
    request('/auth/password', { method: 'POST', body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }) }),
}
