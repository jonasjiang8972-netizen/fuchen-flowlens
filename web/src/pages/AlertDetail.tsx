import { useEffect, useState } from 'react'
import { Button, Card, Col, Dropdown, Input, Modal, Row, Space, Steps, Table, Tag, Timeline, message } from 'antd'
import {
  ArrowLeftOutlined,
  CheckCircleOutlined,
  CodeOutlined,
  DownOutlined,
  FileSearchOutlined,
  SafetyCertificateOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons'
import { alertActionLabel, alertActionStatus, alertService, executeAlertAction } from '../services/api'
import { errorMessage } from '../services/http'
import { useSession } from '../context/session'
import { closedStatuses, formatDuration, slaState } from '../utils/sla'

interface Props {
  alertId: string
  onBack: () => void
  onNavigate: (page: string, id?: string) => void
}

const severityLabel: Record<string, string> = { critical: '严重', high: '高危', medium: '中危', low: '低危' }
const severityColor: Record<string, string> = { critical: 'red', high: 'orange', medium: 'gold', low: 'blue' }
const statusLabel: Record<string, string> = {
  open: '待处理', acknowledged: '已确认', in_progress: '处置中', resolved: '已解决', false_positive: '误报',
}

// Handling advice per detection requirement.
const advice: Record<string, { title: string; desc: string }[]> = {
  'FR-DET-001': [
    { title: '限流或临时封禁该账号', desc: '阻止遍历继续扩大。' },
    { title: '核查对象级鉴权', desc: '确认接口校验了对象是否属于当前账号。' },
  ],
  'FR-DET-002': [
    { title: '临时封禁来源 IP', desc: '撞库和暴力破解通常来自少量 IP。' },
    { title: '排查涉及账号', desc: '检查是否有账号在攻击后登录成功，必要时强制改密。' },
  ],
  'FR-DET-005': [
    { title: '核查账号角色', desc: '确认该账号是否应当访问管理端点。' },
    { title: '收紧功能级鉴权', desc: '管理接口应在服务端校验角色，而不只依赖前端隐藏入口。' },
  ],
  'FR-DLP-001': [
    { title: '最小化返回字段', desc: '确认接口是否必须返回这些敏感字段。' },
    { title: '脱敏后返回', desc: '必须返回时按规范掩码，导出类接口增加审批。' },
  ],
  'FR-DET-007': [
    { title: '校验用户输入的 URL', desc: '对目标地址做白名单校验，禁止内网、元数据地址和危险协议。' },
    { title: '限制服务端出网', desc: '应用所在网络禁止访问元数据地址。' },
  ],
  'FR-RISK-002': [
    { title: '验证码挑战或限流', desc: '对该调用方增加人机验证或降低频率上限。' },
  ],
  'FR-DET-004': [
    { title: '对突增来源限流', desc: '优先限制请求最多的来源。' },
    { title: '确认是否为业务活动', desc: '营销活动等正常突增可在规则中调高阈值。' },
  ],
}

const disposalItems = [
  { key: 'ip_block', label: '封禁来源 IP' },
  { key: 'rate_limit', label: '限流' },
  { key: 'account_lock', label: '锁定账号' },
]

export default function AlertDetail({ alertId, onBack, onNavigate }: Props) {
  const { can } = useSession()
  const canHandle = can('alert.handle')
  const [detail, setDetail] = useState<any>(null)
  const [pending, setPending] = useState<string | null>(null)
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)

  const load = () => alertService.detail(alertId).then(setDetail)
  useEffect(() => { load() }, [alertId]) // eslint-disable-line react-hooks/exhaustive-deps

  if (!detail?.alert_id || !detail?.title) return <div className="commercial-page">加载中...</div>
  const alert = detail
  const raw = detail.raw_data || {}
  const sla = slaState(alert)
  const closed = closedStatuses.has(alert.status)

  const runAction = async () => {
    if (!pending) return
    setBusy(true)
    try {
      await executeAlertAction(alertId, pending, note.trim())
    } catch (err) {
      message.error(errorMessage(err))
      setBusy(false)
      return
    }
    setBusy(false)
    const disposal = alertActionStatus[pending] === 'in_progress'
    message.success(disposal ? `已记录处置：${alertActionLabel[pending]}。请在网关或 WAF 执行；配置了外发的平台会同步推送。` : `已${alertActionLabel[pending]}`)
    setPending(null)
    setNote('')
    load()
  }

  const evidenceRows = [
    { key: '检测命中次数', value: raw.occurrences || '1', meaning: '同一规则、账号和来源合并后的命中次数' },
    { key: '首次发现', value: raw.first_seen ? new Date(raw.first_seen).toLocaleString('zh-CN') : '-', meaning: '' },
    { key: '最近发现', value: raw.last_seen ? new Date(raw.last_seen).toLocaleString('zh-CN') : '-', meaning: '' },
    { key: '持续时长', value: raw.duration || '-', meaning: '首次到最近一次命中' },
    { key: '来源 IP', value: alert.source_ip || '-', meaning: '' },
    { key: '账号 / 调用方', value: alert.account_id || '-', meaning: alert.account_id?.startsWith('ip:') ? '请求未带身份信息，按来源 IP 归并' : '' },
    { key: '风险评分', value: String(alert.risk_score), meaning: '多次命中时取最高分' },
    { key: '身份置信度', value: `${Math.round((alert.confidence || 0) * 100)}%`, meaning: '调用方识别的可信程度' },
  ]

  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <Button type="link" icon={<ArrowLeftOutlined />} onClick={onBack} style={{ paddingLeft: 0 }}>返回告警中心</Button>
          <div className="page-heading__title">{alert.title}</div>
          <div className="page-heading__desc">{alert.description}</div>
        </div>
        {canHandle && (
          <Space>
            {closed ? (
              <Button onClick={() => setPending('reopen')}>重新打开</Button>
            ) : (
              <>
                {alert.status === 'open' && <Button onClick={() => setPending('acknowledge')}>确认</Button>}
                <Dropdown menu={{ items: disposalItems, onClick: ({ key }) => setPending(key) }}>
                  <Button type="primary" danger icon={<ThunderboltOutlined />}>处置 <DownOutlined /></Button>
                </Dropdown>
                <Button onClick={() => setPending('resolve')}>标记已解决</Button>
                <Button onClick={() => setPending('false_positive')}>标记误报</Button>
              </>
            )}
          </Space>
        )}
      </div>

      <div className="metric-grid">
        <Card className="metric-card">
          <div className="metric-card__label"><SafetyCertificateOutlined /> 风险评分</div>
          <div className="metric-card__value" style={{ color: alert.risk_score >= 90 ? 'var(--fl-critical)' : 'var(--fl-high)' }}>{alert.risk_score}</div>
          <div className="metric-card__meta"><Tag color={severityColor[alert.severity]}>{severityLabel[alert.severity]}</Tag> {alert.source_requirement}</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><FileSearchOutlined /> 命中次数</div>
          <div className="metric-card__value">{raw.occurrences || 1}</div>
          <div className="metric-card__meta">持续 {raw.duration || '-'}</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label">处置时限</div>
          <div className="metric-card__value" style={{ fontSize: 22, color: sla.breached ? 'var(--fl-critical)' : undefined }}>
            {closed ? (sla.breached ? '超时关闭' : '按时关闭') : sla.breached ? '已超时' : `剩余 ${formatDuration(sla.remainingMs)}`}
          </div>
          <div className="metric-card__meta">截止 {new Date(sla.deadline).toLocaleString('zh-CN')}</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><CheckCircleOutlined /> 当前状态</div>
          <div className="metric-card__value" style={{ fontSize: 22 }}>{statusLabel[alert.status] || alert.status}</div>
          <div className="metric-card__meta">{alert.disposal ? `已记录处置：${alertActionLabel[alert.disposal.action] || alert.disposal.action}` : '尚未处置'}</div>
        </Card>
      </div>

      <div className="two-column-grid">
        <Card title="命中依据">
          <Space direction="vertical" size={10} style={{ width: '100%' }}>
            {[
              ['检测规则', alert.source_requirement],
              ['涉及接口', (alert.endpoints || []).join('、') || '-'],
              ['最近一次原因', alert.description],
              ['产生时间', new Date(alert.timestamp).toLocaleString('zh-CN')],
            ].map(([label, value]) => (
              <div key={label} style={{ display: 'flex', gap: 12 }}>
                <span className="muted" style={{ width: 90, flexShrink: 0 }}>{label}</span>
                <span style={{ wordBreak: 'break-all' }}>{value}</span>
              </div>
            ))}
          </Space>
        </Card>
        <Card title="处置建议">
          <div className="priority-list">
            {(advice[alert.source_requirement] || [{ title: '人工研判', desc: '结合时间线和原始证据判断是否需要处置。' }]).map((a, index) => (
              <div className="insight-row" key={a.title}>
                <div className="insight-row__index">{index + 1}</div>
                <div><div className="section-title">{a.title}</div><div className="muted">{a.desc}</div></div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {alert.attack_path?.length > 0 && (
        <Card title={`检测记录（${alert.attack_path.length} 条）`}>
          <Steps
            direction="vertical"
            size="small"
            current={alert.attack_path.length}
            items={alert.attack_path.map((step: any) => ({
              title: step.detail,
              description: (
                <span className="muted">
                  IP: {step.source_ip || '-'}{step.path ? ` · 路径: ${step.path}` : ''}{step.status_code ? ` · 状态: ${step.status_code}` : ''} · {new Date(step.timestamp).toLocaleString('zh-CN')}
                </span>
              ),
            }))}
          />
        </Card>
      )}

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={14}>
          <Card title="证据">
            <Table
              columns={[
                { title: '证据项', dataIndex: 'key', key: 'key', width: 150 },
                { title: '值', dataIndex: 'value', key: 'value' },
                { title: '说明', dataIndex: 'meaning', key: 'meaning' },
              ]}
              dataSource={evidenceRows}
              rowKey="key"
              pagination={false}
              size="middle"
            />
          </Card>
        </Col>
        <Col xs={24} xl={10}>
          <Card title="时间线">
            <Timeline
              items={(detail.timeline || []).map((item: any) => ({
                color: item.event === '处置' ? '#d96b20' : '#117865',
                children: (
                  <div>
                    <div className="section-title">{item.event}</div>
                    <div className="muted">{item.detail}</div>
                    <div className="muted">{new Date(item.time).toLocaleString('zh-CN')}</div>
                  </div>
                ),
              }))}
            />
            <div className="section-title">关联告警（同一来源 IP 或账号）</div>
            <Space wrap style={{ marginTop: 8 }}>
              {(detail.related_alerts || []).length
                ? detail.related_alerts.map((id: string) => (
                  <Tag key={id} icon={<CodeOutlined />} onClick={() => onNavigate('alert-detail', id)} style={{ cursor: 'pointer' }}>{id}</Tag>
                ))
                : <span className="muted">无</span>}
            </Space>
          </Card>
        </Col>
      </Row>

      <Modal
        open={!!pending}
        title={pending ? alertActionLabel[pending] : ''}
        okText="确定"
        cancelText="取消"
        confirmLoading={busy}
        onOk={runAction}
        onCancel={() => { setPending(null); setNote('') }}
      >
        {pending && alertActionStatus[pending] === 'in_progress' && (
          <p className="muted">平台会记录这次处置并把告警置为"处置中"。实际的封禁、限流或锁定需要在网关、WAF 或 SOAR 中执行；配置了外发的平台会把处置事件推送过去。</p>
        )}
        <Input.TextArea rows={3} maxLength={500} showCount value={note} onChange={e => setNote(e.target.value)} placeholder="备注（可选），例如处置范围、工单号、误报原因" />
      </Modal>
    </div>
  )
}
