import { useEffect, useMemo, useState } from 'react'
import { Card, Progress, Select, Table, Tag, Timeline } from 'antd'
import { AuditOutlined, CheckCircleOutlined, ClockCircleOutlined, UserSwitchOutlined } from '@ant-design/icons'
import { alertActionLabel, alertService } from '../services/api'
import { closedStatuses, formatDuration, slaHours, slaState } from '../utils/sla'

interface Props { onNavigate: (page: string, id?: string) => void }

const statusMap: Record<string, { label: string; color: string }> = {
  open: { label: '待处理', color: 'error' },
  acknowledged: { label: '已确认', color: 'processing' },
  in_progress: { label: '处置中', color: 'warning' },
  resolved: { label: '已解决', color: 'success' },
  false_positive: { label: '误报', color: 'default' },
}

const severityColor: Record<string, string> = { critical: 'red', high: 'orange', medium: 'gold', low: 'blue' }
const severityLabel: Record<string, string> = { critical: '严重', high: '高危', medium: '中危', low: '低危' }

// Each alert is a work item; its time limit depends on severity (see
// utils/sla) and its handling steps come from the alert history.
export default function WorkOrderCenter({ onNavigate }: Props) {
  const [alerts, setAlerts] = useState<any[]>([])
  const [filter, setFilter] = useState('open')

  useEffect(() => {
    alertService.list().then(setAlerts)
  }, [])

  const now = Date.now()
  const rows = useMemo(() => alerts.map(a => {
    const sla = slaState(a, now)
    const history: any[] = a.history || []
    const last = history[history.length - 1]
    return { ...a, sla, handler: last?.actor || '-', lastAction: last ? alertActionLabel[last.action] || last.action : '-' }
  }).sort((x, y) => {
    // Open items first, nearest deadline first; closed ones newest first.
    if (x.sla.closed !== y.sla.closed) return x.sla.closed ? 1 : -1
    if (!x.sla.closed) return x.sla.deadline - y.sla.deadline
    return (y.sla.closedAt || 0) - (x.sla.closedAt || 0)
  }), [alerts, now])

  const open = rows.filter(r => !r.sla.closed)
  const overdue = open.filter(r => r.sla.breached)
  const closed = rows.filter(r => r.sla.closed)
  const closedInTime = closed.filter(r => !r.sla.breached)
  const handled = open.filter(r => (r.history || []).length > 0)
  const visible = filter === 'open' ? open : filter === 'overdue' ? overdue : filter === 'closed' ? closed : rows

  // Most recent handling steps across all alerts.
  const recentSteps = useMemo(() => alerts.flatMap(a => (a.history || []).map((h: any) => ({ ...h, alert: a })))
    .sort((x, y) => new Date(y.time).getTime() - new Date(x.time).getTime()).slice(0, 8), [alerts])

  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">处置闭环</div>
          <div className="page-heading__desc">每条告警即一个处置项，按严重程度设定处置时限：严重 {slaHours.critical} 小时、高危 {slaHours.high} 小时、中危 {slaHours.medium} 小时、低危 {slaHours.low} 小时。</div>
        </div>
      </div>

      <div className="metric-grid">
        <Card className="metric-card"><div className="metric-card__label"><AuditOutlined /> 未关闭</div><div className="metric-card__value">{open.length}</div><div className="metric-card__meta">待处理、已确认、处置中</div></Card>
        <Card className="metric-card"><div className="metric-card__label"><ClockCircleOutlined /> 已超时</div><div className="metric-card__value" style={{ color: overdue.length ? 'var(--fl-critical)' : undefined }}>{overdue.length}</div><div className="metric-card__meta">未关闭且超过处置时限</div></Card>
        <Card className="metric-card"><div className="metric-card__label"><UserSwitchOutlined /> 已有人处理</div><div className="metric-card__value">{handled.length}</div><div className="metric-card__meta">未关闭告警中已确认或已处置的</div></Card>
        <Card className="metric-card"><div className="metric-card__label"><CheckCircleOutlined /> 按时关闭率</div><div className="metric-card__value">{closed.length ? `${Math.round((closedInTime.length / closed.length) * 100)}%` : '-'}</div><div className="metric-card__meta">{closedInTime.length}/{closed.length} 个已关闭告警在时限内关闭</div></Card>
      </div>

      <Card title="处置项" extra={
        <Select value={filter} onChange={setFilter} style={{ width: 130 }} options={[
          { value: 'open', label: `未关闭（${open.length}）` },
          { value: 'overdue', label: `已超时（${overdue.length}）` },
          { value: 'closed', label: `已关闭（${closed.length}）` },
          { value: 'all', label: `全部（${rows.length}）` },
        ]} />
      }>
        <Table
          columns={[
            { title: '告警', dataIndex: 'title', key: 'title', render: (v: string, r: any) => <a onClick={() => onNavigate('alert-detail', r.alert_id)}>{v}</a> },
            { title: '等级', dataIndex: 'severity', key: 'severity', width: 80, render: (v: string) => <Tag color={severityColor[v]}>{severityLabel[v] || v}</Tag> },
            { title: '状态', dataIndex: 'status', key: 'status', width: 90, render: (v: string) => <Tag color={statusMap[v]?.color}>{statusMap[v]?.label || v}</Tag> },
            { title: '处置时限', key: 'sla', width: 200, render: (_: any, r: any) => {
              const s = r.sla
              const label = s.closed
                ? (s.breached ? '超时关闭' : '按时关闭')
                : (s.breached ? `已超时 ${formatDuration(-s.remainingMs)}` : `剩余 ${formatDuration(s.remainingMs)}`)
              return <div><Progress percent={Math.min(100, Math.round(s.elapsedShare * 100))} size="small" showInfo={false} strokeColor={s.breached ? 'var(--fl-critical)' : s.elapsedShare > 0.7 ? 'var(--fl-medium)' : 'var(--fl-success)'} /><span className="muted" style={{ fontSize: 12 }}>{label}</span></div>
            } },
            { title: '最近处置', dataIndex: 'lastAction', key: 'lastAction', width: 120 },
            { title: '处理人', dataIndex: 'handler', key: 'handler', width: 110 },
            { title: '产生时间', dataIndex: 'timestamp', key: 'timestamp', width: 160, render: (v: string) => new Date(v).toLocaleString('zh-CN') },
          ]}
          dataSource={visible}
          rowKey="alert_id"
          pagination={visible.length > 15 ? { pageSize: 15 } : false}
          locale={{ emptyText: filter === 'open' ? '没有未关闭的告警' : '暂无数据' }}
        />
      </Card>

      <Card title="最近处置记录">
        {recentSteps.length ? (
          <Timeline items={recentSteps.map((h: any) => ({
            color: closedStatuses.has(h.status) ? '#117865' : '#d96b20',
            children: (
              <div>
                <div className="section-title">{h.actor}：{alertActionLabel[h.action] || h.action}{h.note ? `（${h.note}）` : ''}</div>
                <div className="muted"><a onClick={() => onNavigate('alert-detail', h.alert.alert_id)}>{h.alert.title}</a> · {new Date(h.time).toLocaleString('zh-CN')}</div>
              </div>
            ),
          }))} />
        ) : <div className="muted">暂无处置记录。在告警中心确认、处置或关闭告警后，这里会记录操作人和时间。</div>}
      </Card>
    </div>
  )
}
