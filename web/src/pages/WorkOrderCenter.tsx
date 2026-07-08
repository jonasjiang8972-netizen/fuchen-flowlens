import { Card, Progress, Space, Table, Tag, Timeline } from 'antd'
import { AuditOutlined, CheckCircleOutlined, ClockCircleOutlined, UserSwitchOutlined } from '@ant-design/icons'

interface Props { onNavigate: (page: string, id?: string) => void }

const ticketRows = [
  { id: 'TKT-001', title: 'BOLA 攻击调查：订单对象遍历', source: 'alt-001', owner: '订单安全接口人', severity: 'high', status: 'processing', sla: 68, due: '4小时内', action: '限流账号 + 修复对象级鉴权' },
  { id: 'TKT-002', title: '撞库攻击 IP 封禁确认', source: 'alt-002', owner: '安全运营', severity: 'critical', status: 'pending', sla: 42, due: '1小时内', action: '封禁 IP + 通知 IAM' },
  { id: 'TKT-003', title: 'legacy/export 影子 API 纳管', source: 'alt-003', owner: '平台工程', severity: 'medium', status: 'processing', sla: 75, due: '2天内', action: '补 CMDB + Owner + 网关策略' },
  { id: 'TKT-004', title: '身份证号未脱敏修复', source: 'alt-005', owner: '用户服务 Owner', severity: 'high', status: 'review', sla: 88, due: '今天', action: '响应字段脱敏 + 回归验证' },
  { id: 'TKT-005', title: 'Partner API Key 注册表补齐', source: 'BLD-004', owner: '开放平台', severity: 'medium', status: 'done', sla: 100, due: '已完成', action: '同步 partner_registry' },
]

const statusMap: Record<string, { label: string; color: string }> = {
  pending: { label: '待分派', color: 'error' },
  processing: { label: '处理中', color: 'processing' },
  review: { label: '待复核', color: 'warning' },
  done: { label: '已闭环', color: 'success' },
}

export default function WorkOrderCenter({ onNavigate }: Props) {
  const openTickets = ticketRows.filter(t => t.status !== 'done')
  const overdue = ticketRows.filter(t => t.sla < 60 && t.status !== 'done')

  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">处置闭环</div>
          <div className="page-heading__desc">把告警、盲区和契约差异转成可分派、可复核、可审计的治理工单。</div>
        </div>
      </div>

      <div className="metric-grid">
        <Card className="metric-card"><div className="metric-card__label"><AuditOutlined /> 开放工单</div><div className="metric-card__value">{openTickets.length}</div><div className="metric-card__meta">待分派、处理中、待复核</div></Card>
        <Card className="metric-card"><div className="metric-card__label"><ClockCircleOutlined /> SLA 风险</div><div className="metric-card__value" style={{ color: 'var(--fl-critical)' }}>{overdue.length}</div><div className="metric-card__meta">剩余处理时间不足或已临近超时</div></Card>
        <Card className="metric-card"><div className="metric-card__label"><UserSwitchOutlined /> Owner 覆盖</div><div className="metric-card__value">92%</div><div className="metric-card__meta">风险已绑定责任团队</div></Card>
        <Card className="metric-card"><div className="metric-card__label"><CheckCircleOutlined /> 复发检测</div><div className="metric-card__value">3</div><div className="metric-card__meta">已闭环风险仍在观察窗口</div></Card>
      </div>

      <Card title="治理工单">
        <Table
          columns={[
            { title: '工单ID', dataIndex: 'id', key: 'id', width: 100 },
            { title: '标题', dataIndex: 'title', key: 'title' },
            { title: '来源', dataIndex: 'source', key: 'source', width: 110, render: (v: string) => <Tag onClick={() => v.startsWith('alt') && onNavigate('alert-detail', v)} style={{ cursor: v.startsWith('alt') ? 'pointer' : 'default' }}>{v}</Tag> },
            { title: 'Owner', dataIndex: 'owner', key: 'owner', width: 140 },
            { title: '等级', dataIndex: 'severity', key: 'severity', width: 90, render: (v: string) => <Tag color={v === 'critical' ? 'red' : v === 'high' ? 'orange' : 'gold'}>{v}</Tag> },
            { title: '状态', dataIndex: 'status', key: 'status', width: 100, render: (v: string) => <Tag color={statusMap[v]?.color}>{statusMap[v]?.label || v}</Tag> },
            { title: 'SLA', dataIndex: 'sla', key: 'sla', width: 150, render: (v: number) => <Progress percent={v} size="small" strokeColor={v < 60 ? 'var(--fl-critical)' : 'var(--fl-success)'} /> },
            { title: '期限', dataIndex: 'due', key: 'due', width: 100 },
            { title: '治理动作', dataIndex: 'action', key: 'action' },
          ]}
          dataSource={ticketRows}
          rowKey="id"
          pagination={false}
        />
      </Card>

      <Card title="闭环审计链">
        <Timeline
          items={[
            { color: '#117865', children: <div><div className="section-title">告警触发</div><div className="muted">alt-001 BOLA 对象遍历，风险评分 91。</div></div> },
            { color: '#117865', children: <div><div className="section-title">自动创建工单</div><div className="muted">绑定订单安全接口人，SLA 4 小时。</div></div> },
            { color: '#d96b20', children: <div><div className="section-title">临时处置</div><div className="muted">对账号限流并失效异常会话。</div></div> },
            { color: '#117865', children: <div><div className="section-title">修复验证</div><div className="muted">补充对象级鉴权测试，并进入复发观察窗口。</div></div> },
          ]}
        />
      </Card>
    </div>
  )
}
