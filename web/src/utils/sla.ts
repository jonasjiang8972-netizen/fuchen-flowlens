// Handling time limits per severity, counted from when the alert was
// raised.
export const slaHours: Record<string, number> = { critical: 1, high: 4, medium: 24, low: 72 }

export const closedStatuses = new Set(['resolved', 'false_positive'])

export interface SlaState {
  closed: boolean
  deadline: number // epoch ms
  remainingMs: number // negative once overdue (open alerts)
  breached: boolean // overdue now, or closed after the deadline
  elapsedShare: number // share of the time limit used, 0..1+
  closedAt?: number
}

// closedAt returns when the alert was last resolved or marked false
// positive, from its handling history.
export function closedAt(alert: any): number | undefined {
  const history: any[] = alert?.history || []
  for (let i = history.length - 1; i >= 0; i--) {
    if (closedStatuses.has(history[i].status)) return new Date(history[i].time).getTime()
  }
  return undefined
}

export function slaState(alert: any, now = Date.now()): SlaState {
  const raised = new Date(alert.timestamp).getTime()
  const limit = (slaHours[alert.severity] ?? 24) * 3600000
  const deadline = raised + limit
  const closed = closedStatuses.has(alert.status)
  const end = closed ? closedAt(alert) ?? now : now
  return {
    closed,
    deadline,
    remainingMs: deadline - now,
    breached: end > deadline,
    elapsedShare: (end - raised) / limit,
    closedAt: closed ? closedAt(alert) : undefined,
  }
}

export function formatDuration(ms: number): string {
  const abs = Math.abs(ms)
  const m = Math.round(abs / 60000)
  if (m < 60) return `${m} 分钟`
  const h = Math.floor(m / 60)
  if (h < 48) return `${h} 小时 ${m % 60} 分钟`
  return `${Math.floor(h / 24)} 天 ${h % 24} 小时`
}
