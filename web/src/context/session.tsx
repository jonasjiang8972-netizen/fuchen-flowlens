import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { DEMO, onSessionEvent } from '../services/http'
import { authService, demoSession } from '../services/auth'
import type { Permission, Role, Session } from '../services/auth'

type Status = 'loading' | 'anonymous' | 'must-change' | 'must-enroll' | 'ready'

interface SessionContextValue {
  status: Status
  session: Session | null
  // Why the user was returned to the login page, e.g. idle timeout.
  notice: string
  can: (p: Permission) => boolean
  // Resolves to the second-factor token when the account has MFA on;
  // completeMfaLogin then finishes the login with the code.
  login: (username: string, password: string) => Promise<string | null>
  completeMfaLogin: (mfaToken: string, code: string) => Promise<void>
  logout: () => Promise<void>
  refresh: () => Promise<void>
  // Demo build only: switch the simulated identity.
  switchDemoRole: (role: Role) => void
}

const SessionContext = createContext<SessionContextValue | null>(null)

export function SessionProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status>('loading')
  const [session, setSession] = useState<Session | null>(null)
  const [notice, setNotice] = useState('')
  const statusRef = useRef<Status>('loading')
  statusRef.current = status

  const apply = useCallback((s: Session | null) => {
    setSession(s)
    setStatus(!s ? 'anonymous' : s.must_change_password ? 'must-change' : s.must_enroll_mfa || s.user.must_enroll_mfa ? 'must-enroll' : 'ready')
  }, [])

  const refresh = useCallback(async () => {
    if (DEMO) {
      apply(demoSession('sec_admin'))
      return
    }
    try {
      apply(await authService.me())
    } catch {
      apply(null)
    }
  }, [apply])

  useEffect(() => { refresh() }, [refresh])

  useEffect(() => onSessionEvent(e => {
    if (e === 'expired') {
      // Only a session that existed can expire; a 401 while signed out
      // (e.g. the initial session probe) is not news to the user.
      if (statusRef.current === 'ready' || statusRef.current === 'must-change' || statusRef.current === 'must-enroll') {
        setNotice('会话已超时或已在其他地方退出，请重新登录')
        apply(null)
      }
    } else if (e === 'password-change-required') {
      setStatus('must-change')
    } else if (e === 'mfa-enrollment-required') {
      setStatus('must-enroll')
    }
  }), [apply])

  const login = useCallback(async (username: string, password: string) => {
    const res = await authService.login(username, password)
    if (res.mfa_required) return res.mfa_token
    setNotice('')
    apply(res)
    return null
  }, [apply])

  const completeMfaLogin = useCallback(async (mfaToken: string, code: string) => {
    const res = await authService.loginMfa(mfaToken, code)
    setNotice('')
    apply(res)
  }, [apply])

  const logout = useCallback(async () => {
    try { await authService.logout() } catch { /* session may already be gone */ }
    if (DEMO) { apply(demoSession('sec_admin')); return }
    setNotice('')
    apply(null)
  }, [apply])

  const can = useCallback((p: Permission) => status === 'ready' && !!session?.permissions.includes(p), [session, status])

  const switchDemoRole = useCallback((role: Role) => { if (DEMO) apply(demoSession(role)) }, [apply])

  return (
    <SessionContext.Provider value={{ status, session, notice, can, login, completeMfaLogin, logout, refresh, switchDemoRole }}>
      {children}
    </SessionContext.Provider>
  )
}

export function useSession() {
  const ctx = useContext(SessionContext)
  if (!ctx) throw new Error('useSession must be used inside SessionProvider')
  return ctx
}
