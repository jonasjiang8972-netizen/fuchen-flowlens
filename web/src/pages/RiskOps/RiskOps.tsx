import { useState } from 'react'
import { Card, Table, Tag, Tabs, Button, Modal, Typography, Switch } from '@arco-design/web-react'

const mockTickets = [
  { id: 'TKT-001', title: 'BOLA 攻击调查: 订单遍历', severity: 'high', status: 'processing', assignee: '张三', created: '2小时前' },
  { id: 'TKT-002', title: '撞库攻击 IP 封禁确认', severity: 'critical', status: 'pending', assignee: '-', created: '30分钟前' },
  { id: 'TKT-003', title: '脱敏缺陷修复跟进', severity: 'medium', status: 'done', assignee: '李四', created: '1天前' },
]

export default function RiskOps({ onNavigate }: { onNavigate: (page: string, id?: string) => void }) {
  const [tab, setTab] = useState('tickets')

  const ticketCols = [
    { title: '工单ID', dataIndex: 'id', key: 'id', width: 100 },
    { title: '标题', dataIndex: 'title', key: 'title' },
    { title: '等级', dataIndex: 'severity', key: 'severity', width: 80,
      render: (s: string) => <Tag color={{ high: 'red', critical: 'red', medium: 'orange' }[s]}>{s}</Tag> },
    { title: '状态', dataIndex: 'status', key: 'status', width: 100,
      render: (s: string) => ({ pending: <Tag>待处理</Tag>, processing: <Tag color="blue">处理中</Tag>, done: <Tag color="green">已闭环</Tag> }[s]) },
    { title: '负责人', dataIndex: 'assignee', key: 'assignee', width: 100 },
    { title: '创建时间', dataIndex: 'created', key: 'created', width: 120 },
  ]

  const warnTicketCount = mockTickets.filter(t => t.severity !== 'low').length

  return (
    <div className="page-enter">
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
        <Card className="panel-card">
          <div style={{ fontSize: 12, color: '#8A93A3' }}>待处理工单</div>
          <div style={{ fontSize: 28, fontWeight: 700, color: '#D14D3D' }}>{warnTicketCount}</div>
        </Card>
        <Card className="panel-card">
          <div style={{ fontSize: 12, color: '#8A93A3' }}>联动处置</div>
          <div style={{ fontSize: 14, marginTop: 8 }}>联动系统的配置、封禁与解封已迁移到 <a onClick={() => onNavigate('soar')}>联动处置</a> 页面。</div>
        </Card>
      </div>

      <Tabs activeTab={tab} onChange={setTab}>
        <Tabs.TabPane key="tickets" title="工单管理">
          <Card className="panel-card">
            <div style={{ marginBottom: 12, display: 'flex', gap: 8 }}>
              {['待处理','处理中','已闭环','误报'].map(s => (
                <Button key={s} size="small" type="outline">{s}</Button>
              ))}
            </div>
            <Table columns={ticketCols} data={mockTickets} pagination={false} />
          </Card>
        </Tabs.TabPane>
      </Tabs>
    </div>
  )
}
