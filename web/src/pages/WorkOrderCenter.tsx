import { useEffect, useMemo, useState } from 'react'
import { Alert, Button, Card, Descriptions, Drawer, Empty, Form, Input, message, Modal, Progress, Segmented, Select, Space, Table, Tag, Timeline } from 'antd'
import { AuditOutlined, CheckCircleOutlined, ClockCircleOutlined, PlusOutlined, ReloadOutlined, UserSwitchOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import relativeTime from 'dayjs/plugin/relativeTime'
import 'dayjs/locale/zh-cn'
import { useSession } from '../context/session'
import { errorMessage } from '../services/http'
import { ticketService } from '../services/tickets'
import type { Ticket, TicketEvent, TicketStatus, TicketSummary } from '../services/tickets'

dayjs.extend(relativeTime)
dayjs.locale('zh-cn')

interface Props {
  // Ticket to open on arrival (from an alert); empty shows the list.
  focusId?: string
  onNavigate: (page: string, id?: string) => void
}

const STATUS: Record<string, { label: string; color: string }> = {
  pending: { label: '待分派', color: 'error' },
  processing: { label: '处理中', color: 'processing' },
  review: { label: '待复核', color: 'warning' },
  done: { label: '已闭环', color: 'success' },
  false_positive: { label: '误报', color: 'default' },
}
const SEV_COLOR: Record<string, string> = { critical: 'red', high: 'orange', medium: 'gold', low: 'blue' }

// What each state can do next. `note` says whether the platform requires a
// written reason for that step.
interface Step { to: TicketStatus; label: string; note: 'required' | 'optional' | 'none'; owner?: boolean; danger?: boolean; hint?: string }
const STEPS: Record<TicketStatus, Step[]> = {
  pending: [
    { to: 'processing', label: '开始处理', note: 'none', owner: true },
    { to: 'false_positive', label: '标记误报', note: 'required', hint: '说明为什么这不是真实问题（例如内部压测、合作方扫描）。' },
  ],
  processing: [
    { to: 'review', label: '提交复核', note: 'required', hint: '写清做了什么处置、如何验证。复核人必须是另一个人。' },
    { to: 'false_positive', label: '标记误报', note: 'required', hint: '说明为什么这不是真实问题。' },
  ],
  review: [
    { to: 'done', label: '复核通过', note: 'optional', hint: '提交复核的人不能自己通过。' },
    { to: 'processing', label: '驳回', note: 'required', hint: '说明哪里没做到位，工单会回到处理中。' },
    { to: 'false_positive', label: '标记误报', note: 'required' },
  ],
  done: [{ to: 'processing', label: '重新打开', note: 'required', hint: '说明问题为什么复现。SLA 会重新计时。' }],
  false_positive: [{ to: 'processing', label: '重新打开', note: 'required', hint: '说明为什么它其实是真实问题。SLA 会重新计时。' }],
}

const EVENT_LABEL: Record<string, string> = {
  created: '创建', assigned: '分派', transition: '状态变更', comment: '备注', alert_action: '告警处置', repeat: '关联告警',
}

const EVENT_COLOR: Record<string, string> = { created: 'gray', assigned: 'blue', transition: '#117865', comment: 'gray', alert_action: '#d96b20', repeat: 'gray' }

export default function WorkOrderCenter({ focusId, onNavigate }: Props) {
  const { can } = useSession()
  const canHandle = can('alert.handle')

  const [tickets, setTickets] = useState<Ticket[]>([])
  const [summary, setSummary] = useState<TicketSummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [status, setStatus] = useState<string>('all')
  const [severity, setSeverity] = useState<string | undefined>()
  const [keyword, setKeyword] = useState('')
  const [openId, setOpenId] = useState<string | null>(focusId || null)
  const [creating, setCreating] = useState(false)

  const load = async () => {
    setLoading(true)
    try {
      const [list, sum] = await Promise.all([
        ticketService.list({ status: status === 'all' ? undefined : status, severity, q: keyword.trim() || undefined }),
        ticketService.summary(),
      ])
      setTickets(list)
      setSummary(sum)
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => { load() }, [status, severity, keyword])
  useEffect(() => { if (focusId) setOpenId(focusId) }, [focusId])

  const statusOptions = useMemo(() => [
    { value: 'all', label: '全部' },
    ...Object.entries(STATUS).map(([value, s]) => ({ value, label: `${s.label}${summary?.by_status?.[value] ? ` ${summary.by_status[value]}` : ''}` })),
  ], [summary])

  const slaCell = (t: Ticket) => {
    if (!t.open) return <span className="muted">{t.status === 'done' ? '已闭环' : '已关闭'}</span>
    return (
      <div title={`到期 ${dayjs(t.due_at).format('MM-DD HH:mm')}`}>
        <Progress percent={Math.min(100, t.sla_percent)} size="small" showInfo={false} status={t.overdue ? 'exception' : t.sla_percent >= 80 ? 'active' : 'normal'}
          strokeColor={t.overdue ? 'var(--fl-critical, #c9352b)' : t.sla_percent >= 80 ? 'var(--fl-high, #d96b20)' : 'var(--fl-success, #168447)'} />
        <span className={t.overdue ? '' : 'muted'} style={t.overdue ? { color: 'var(--fl-critical, #c9352b)', fontSize: 12 } : { fontSize: 12 }}>
          {t.overdue ? `已超时 ${dayjs(t.due_at).fromNow(true)}` : `${dayjs(t.due_at).fromNow(true)}后到期`}
        </span>
      </div>
    )
  }

  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">处置闭环</div>
          <div className="page-heading__desc">严重告警自动开单，按等级计时；处置要经过另一个人复核才算闭环，每一步都记入审计。</div>
        </div>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={load} loading={loading}>刷新</Button>
          {canHandle && <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreating(true)}>新建工单</Button>}
        </Space>
      </div>

      <div className="metric-grid">
        <Card className="metric-card"><div className="metric-card__label"><AuditOutlined /> 开放工单</div><div className="metric-card__value">{summary?.open ?? '-'}</div><div className="metric-card__meta">待分派 {summary?.by_status?.pending ?? 0} · 处理中 {summary?.by_status?.processing ?? 0} · 待复核 {summary?.by_status?.review ?? 0}</div></Card>
        <Card className="metric-card"><div className="metric-card__label"><ClockCircleOutlined /> SLA 超时</div><div className="metric-card__value" style={{ color: summary?.overdue ? 'var(--fl-critical)' : undefined }}>{summary?.overdue ?? '-'}</div><div className="metric-card__meta">另有 {summary?.at_risk ?? 0} 张已用掉 80% 以上时限</div></Card>
        <Card className="metric-card"><div className="metric-card__label"><UserSwitchOutlined /> 负责人覆盖</div><div className="metric-card__value">{summary ? `${Math.round(summary.owner_coverage * 100)}%` : '-'}</div><div className="metric-card__meta">{summary?.unassigned ?? 0} 张开放工单还没有负责人</div></Card>
        <Card className="metric-card"><div className="metric-card__label"><CheckCircleOutlined /> 近 7 天关闭</div><div className="metric-card__value">{summary?.closed_7d ?? '-'}</div><div className="metric-card__meta">{summary?.mean_hours_to_close ? `平均 ${summary.mean_hours_to_close.toFixed(1)} 小时闭环（近 30 天）` : '暂无已闭环工单可统计'}</div></Card>
      </div>

      <div className="filter-bar">
        <Input.Search allowClear placeholder="搜索标题、编号、负责人" style={{ width: 300 }} onSearch={setKeyword} />
        <div className="filter-bar__controls">
          <Select allowClear placeholder="等级" style={{ width: 110 }} value={severity} onChange={setSeverity}
            options={['critical', 'high', 'medium', 'low'].map(v => ({ value: v, label: v }))} />
          <Segmented value={status} onChange={v => setStatus(String(v))} options={statusOptions} />
        </div>
      </div>

      <Card>
        <Table<Ticket>
          rowKey="ticket_id" loading={loading} dataSource={tickets} pagination={{ pageSize: 10, hideOnSinglePage: true }}
          locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="没有符合条件的工单。高危及以上告警会自动开单。" /> }}
          onRow={t => ({ onClick: () => setOpenId(t.ticket_id), style: { cursor: 'pointer' } })}
          columns={[
            { title: '编号', dataIndex: 'ticket_id', width: 100 },
            {
              title: '标题', dataIndex: 'title',
              render: (v: string, t) => (
                <Space direction="vertical" size={2}>
                  <span style={{ fontWeight: 600 }}>{v}</span>
                  <Space size={4} wrap>
                    {t.auto_created && <Tag>自动创建</Tag>}
                    {!!t.related_count && <Tag color="purple" title="同一来源、同一类检测的其他告警已并入本工单">+{t.related_count} 个关联告警</Tag>}
                    {!!t.reopened && <Tag color="volcano">重开 {t.reopened} 次</Tag>}
                  </Space>
                </Space>
              ),
            },
            { title: '等级', dataIndex: 'severity', width: 90, render: (v: string) => <Tag color={SEV_COLOR[v]}>{v}</Tag> },
            { title: '状态', dataIndex: 'status', width: 100, render: (v: string) => <Tag color={STATUS[v]?.color}>{STATUS[v]?.label}</Tag> },
            { title: '负责人', dataIndex: 'owner', width: 140, render: (v?: string) => v || <span className="muted">未分派</span> },
            { title: 'SLA', key: 'sla', width: 170, render: (_: unknown, t) => slaCell(t) },
            { title: '更新', dataIndex: 'updated_at', width: 110, render: (v: string) => <span className="muted">{dayjs(v).fromNow()}</span> },
          ]}
        />
      </Card>

      <TicketDrawer id={openId} canHandle={canHandle} onClose={() => setOpenId(null)} onChanged={load} onNavigate={onNavigate} />
      <CreateModal open={creating} onClose={() => setCreating(false)} onCreated={id => { setCreating(false); setOpenId(id); load() }} />
    </div>
  )
}

// ─── Detail drawer ──────────────────────────────────────────────

function TicketDrawer({ id, canHandle, onClose, onChanged, onNavigate }: {
  id: string | null; canHandle: boolean; onClose: () => void; onChanged: () => void; onNavigate: (page: string, id?: string) => void
}) {
  const [ticket, setTicket] = useState<Ticket | null>(null)
  const [step, setStep] = useState<Step | null>(null)
  const [assigning, setAssigning] = useState(false)
  const [comment, setComment] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    setTicket(null)
    if (!id) return
    ticketService.get(id).then(setTicket).catch(err => { message.error(errorMessage(err)); onClose() })
  }, [id])

  const apply = (t: Ticket) => { setTicket(t); onChanged() }

  const send = async (fn: () => Promise<Ticket>, ok: string) => {
    setBusy(true)
    try {
      apply(await fn())
      message.success(ok)
      return true
    } catch (err) {
      message.error(errorMessage(err))
      return false
    } finally {
      setBusy(false)
    }
  }

  const addComment = async () => {
    if (!ticket || !comment.trim()) return
    if (await send(() => ticketService.comment(ticket.ticket_id, comment), '已添加备注')) setComment('')
  }

  return (
    <Drawer open={!!id} onClose={onClose} width={620} destroyOnClose title={ticket ? `${ticket.ticket_id} · ${ticket.title}` : '工单'}>
      {!ticket ? null : (
        <Space direction="vertical" size={16} style={{ width: '100%' }}>
          {ticket.overdue && <Alert type="error" showIcon message={`已超过 SLA ${dayjs(ticket.due_at).fromNow(true)}`} />}
          {ticket.status === 'review' && (
            <Alert type="info" showIcon message={`${ticket.submitted_by || '处理人'} 已提交复核`} description="复核需要由另一个人完成，提交人不能自己通过。" />
          )}

          <Descriptions column={2} size="small">
            <Descriptions.Item label="状态"><Tag color={STATUS[ticket.status]?.color}>{STATUS[ticket.status]?.label}</Tag></Descriptions.Item>
            <Descriptions.Item label="等级"><Tag color={SEV_COLOR[ticket.severity]}>{ticket.severity}</Tag></Descriptions.Item>
            <Descriptions.Item label="负责人">{ticket.owner || <span className="muted">未分派</span>}</Descriptions.Item>
            <Descriptions.Item label="到期">{ticket.open ? dayjs(ticket.due_at).format('MM-DD HH:mm') : '—'}</Descriptions.Item>
            {ticket.alert_id && (
              <Descriptions.Item label="来源告警" span={2}>
                <a onClick={() => onNavigate('alert-detail', ticket.alert_id)}>{ticket.alert_id}</a>
                {!!ticket.related_count && <span className="muted">　另有 {ticket.related_count} 个同来源告警并入</span>}
              </Descriptions.Item>
            )}
            {ticket.action && <Descriptions.Item label="建议处置" span={2}>{ticket.action}</Descriptions.Item>}
            {ticket.description && <Descriptions.Item label="说明" span={2}>{ticket.description}</Descriptions.Item>}
            <Descriptions.Item label="创建">{ticket.created_by} · {dayjs(ticket.created_at).format('MM-DD HH:mm')}</Descriptions.Item>
            <Descriptions.Item label="重开次数">{ticket.reopened || 0}</Descriptions.Item>
          </Descriptions>

          {canHandle && (
            <Space wrap>
              {STEPS[ticket.status].map(s => (
                <Button key={s.to + s.label} type={s.to === 'done' || s.to === 'review' || (s.to === 'processing' && ticket.status === 'pending') ? 'primary' : 'default'}
                  danger={s.to === 'false_positive'} onClick={() => setStep(s)}>{s.label}</Button>
              ))}
              {ticket.open && <Button onClick={() => setAssigning(true)}>{ticket.owner ? '改派' : '指派'}</Button>}
              {ticket.alert_id && <Button onClick={() => onNavigate('attack-path', ticket.alert_id)}>查看攻击路径</Button>}
            </Space>
          )}

          <div>
            <div className="section-title" style={{ marginBottom: 12 }}>处理记录</div>
            <Timeline items={ticket.timeline.map((e: TicketEvent) => ({
              color: EVENT_COLOR[e.type],
              children: (
                <div>
                  <div>
                    <b>{EVENT_LABEL[e.type] || e.type}</b>
                    {e.type === 'transition' && <span>：{STATUS[e.from || '']?.label} → {STATUS[e.to || '']?.label}</span>}
                    <span className="muted">　{e.actor} · {dayjs(e.at).format('MM-DD HH:mm')}</span>
                  </div>
                  {e.detail && <div className="muted" style={{ whiteSpace: 'pre-wrap' }}>{e.detail}</div>}
                </div>
              ),
            }))} />
          </div>

          {canHandle && (
            <Space.Compact style={{ width: '100%' }}>
              <Input.TextArea rows={2} value={comment} onChange={e => setComment(e.target.value)} placeholder="添加备注（会记入处理记录）" maxLength={2000} />
              <Button type="primary" loading={busy} disabled={!comment.trim()} onClick={addComment} style={{ height: 'auto' }}>添加</Button>
            </Space.Compact>
          )}
        </Space>
      )}

      <StepModal step={step} ticket={ticket} onClose={() => setStep(null)}
        onSubmit={async (note, owner) => (ticket && step ? send(() => ticketService.transition(ticket.ticket_id, step.to, note, owner), `${step.label}已完成`) : false)} />
      <AssignModal open={assigning} ticket={ticket} onClose={() => setAssigning(false)}
        onSubmit={async owner => (ticket ? send(() => ticketService.assign(ticket.ticket_id, owner), '已更新负责人') : false)} />
    </Drawer>
  )
}

function StepModal({ step, ticket, onClose, onSubmit }: {
  step: Step | null; ticket: Ticket | null; onClose: () => void; onSubmit: (note: string, owner: string) => Promise<boolean>
}) {
  const [form] = Form.useForm()
  const [busy, setBusy] = useState(false)
  useEffect(() => { if (step) form.resetFields() }, [step])
  const needOwner = !!step?.owner && !ticket?.owner
  return (
    <Modal open={!!step} title={step?.label} okText="确认" cancelText="取消" confirmLoading={busy} onCancel={onClose} destroyOnClose
      okButtonProps={{ danger: step?.to === 'false_positive' }}
      onOk={async () => {
        const v = await form.validateFields().catch(() => null)
        if (!v) return
        setBusy(true)
        const ok = await onSubmit((v.note || '').trim(), (v.owner || '').trim())
        setBusy(false)
        if (ok) onClose()
      }}>
      <Form form={form} layout="vertical">
        {step?.hint && <div className="muted" style={{ marginBottom: 12 }}>{step.hint}</div>}
        {needOwner && <Form.Item name="owner" label="负责人" rules={[{ required: true, message: '开始处理前需要指定负责人' }]}><Input placeholder="人员或团队" maxLength={100} /></Form.Item>}
        {step && step.note !== 'none' && (
          <Form.Item name="note" label={step.note === 'required' ? '说明' : '说明（可选）'} rules={step.note === 'required' ? [{ required: true, whitespace: true, message: '请填写说明' }] : []}>
            <Input.TextArea rows={4} maxLength={2000} showCount />
          </Form.Item>
        )}
      </Form>
    </Modal>
  )
}

function AssignModal({ open, ticket, onClose, onSubmit }: { open: boolean; ticket: Ticket | null; onClose: () => void; onSubmit: (owner: string) => Promise<boolean> }) {
  const [form] = Form.useForm()
  const [busy, setBusy] = useState(false)
  useEffect(() => { if (open) form.setFieldsValue({ owner: ticket?.owner || '' }) }, [open])
  return (
    <Modal open={open} title={ticket?.owner ? '改派' : '指派'} okText="确认" cancelText="取消" confirmLoading={busy} onCancel={onClose} destroyOnClose
      onOk={async () => {
        const v = await form.validateFields().catch(() => null)
        if (!v) return
        setBusy(true)
        const ok = await onSubmit(v.owner.trim())
        setBusy(false)
        if (ok) onClose()
      }}>
      <Form form={form} layout="vertical">
        <Form.Item name="owner" label="负责人" rules={[{ required: true, whitespace: true, message: '请填写负责人' }]}><Input placeholder="人员或团队" maxLength={100} /></Form.Item>
      </Form>
    </Modal>
  )
}

function CreateModal({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (id: string) => void }) {
  const [form] = Form.useForm()
  const [busy, setBusy] = useState(false)
  useEffect(() => { if (open) form.resetFields() }, [open])
  return (
    <Modal open={open} title="新建工单" okText="创建" cancelText="取消" confirmLoading={busy} onCancel={onClose} destroyOnClose
      onOk={async () => {
        const v = await form.validateFields().catch(() => null)
        if (!v) return
        setBusy(true)
        try {
          const t = await ticketService.create({ title: v.title, severity: v.severity, owner: v.owner, action: v.action, description: v.description })
          message.success(`已创建 ${t.ticket_id}`)
          onCreated(t.ticket_id)
        } catch (err) {
          message.error(errorMessage(err))
        } finally {
          setBusy(false)
        }
      }}>
      <Form form={form} layout="vertical" initialValues={{ severity: 'medium' }}>
        <Form.Item name="title" label="标题" rules={[{ required: true, whitespace: true, message: '请填写标题' }]}><Input maxLength={200} /></Form.Item>
        <Form.Item name="severity" label="等级（决定 SLA：严重 4 小时、高危 24 小时、中危 3 天、低危 7 天）" rules={[{ required: true }]}>
          <Select options={['critical', 'high', 'medium', 'low'].map(v => ({ value: v, label: v }))} />
        </Form.Item>
        <Form.Item name="owner" label="负责人（可稍后指派）"><Input maxLength={100} placeholder="人员或团队" /></Form.Item>
        <Form.Item name="action" label="需要做什么"><Input maxLength={1000} /></Form.Item>
        <Form.Item name="description" label="背景说明"><Input.TextArea rows={3} maxLength={4000} /></Form.Item>
      </Form>
    </Modal>
  )
}
