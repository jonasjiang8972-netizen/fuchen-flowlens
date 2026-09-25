// HTTP client shared by both consoles. The session lives in an HttpOnly
// cookie set by the platform, so no token is ever stored in the browser.

export const API_BASE = '/api/v1'

// Static demo builds (VITE_DEMO=true) have no backend: services return
// built-in sample data instead of calling the API.
export const DEMO = import.meta.env.VITE_DEMO === 'true'

export class ApiError extends Error {
  status: number
  code?: string
  constructor(status: number, message: string, code?: string) {
    super(message)
    this.status = status
    this.code = code
  }
}

// Session events let the app shell react to expiry or a forced password
// change wherever a request happens.
export type SessionEvent = 'expired' | 'password-change-required'
const listeners = new Set<(e: SessionEvent) => void>()
export function onSessionEvent(fn: (e: SessionEvent) => void) {
  listeners.add(fn)
  return () => { listeners.delete(fn) }
}
function emit(e: SessionEvent) { listeners.forEach(fn => fn(e)) }

export async function request<T>(url: string, options: RequestInit = {}): Promise<T> {
  const method = (options.method || 'GET').toUpperCase()
  const headers: Record<string, string> = { ...(options.headers as Record<string, string> | undefined) }
  if (options.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json'
  // Required by the platform for cookie-authenticated state changes (CSRF).
  if (method !== 'GET' && method !== 'HEAD') headers['X-Requested-With'] = 'FlowLens'

  let resp: Response
  try {
    resp = await fetch(`${API_BASE}${url}`, { ...options, method, headers, credentials: 'same-origin' })
  } catch {
    throw new ApiError(0, '无法连接平台服务，请检查网络')
  }
  let body: any = null
  const text = await resp.text()
  if (text) {
    try { body = JSON.parse(text) } catch { body = text }
  }
  if (!resp.ok) {
    const message = (body && body.error) || `请求失败（${resp.status}）`
    const code = body && body.code
    if (resp.status === 401 && !url.startsWith('/auth/login')) emit('expired')
    if (resp.status === 403 && code === 'password_change_required') emit('password-change-required')
    throw new ApiError(resp.status, message, code)
  }
  return body as T
}

export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 403 && err.code === 'forbidden') return '没有执行该操作的权限'
    return err.message
  }
  return '操作失败，请稍后重试'
}
