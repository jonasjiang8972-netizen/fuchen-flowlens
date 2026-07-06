import { useEffect, useState } from 'react'
import { Table, Tag, Button, Space, Typography, Card, Descriptions, Modal } from 'antd'
import { CheckCircleOutlined, CloseCircleOutlined } from '@ant-design/icons'
import { executeAlertAction, alertService } from '../services/api'

const { Title, Paragraph } = Typography

interface Props {
  onNavigate: (page: string, id?: string) => void
}

export default function Alerts({ onNavigate }: Props) {
  const [alerts, setAlerts] = useState<any[]>([])
  const [selectedAlert, setSelectedAlert] = useState<any>(null)

  useEffect(() => {
    alertService.list().then(setAlerts)
  }, [])

  const handleAction = (alertId: string, action: string) => {
    executeAlertAction(alertId, action)
    setAlerts(prev => prev.map(a =>
      a.alert_id === alertId ? { ...a, status: 'in_progress', disposal: { action, status: 'success' } } : a
    ))
  }

  const getAttackPath = (steps: any[]) => {
    if (!steps || steps.length === 0) return '无'
    return steps.map(s => `${s.sequence}. ${s.action} ${s.path} (${s.status || s.status_code})`).join(' → ')
  }

  const columns = [
    { title: '告警ID', dataIndex: 'alert_id', key: 'id', width: 100 },
    { title: '时间', dataIndex: 'timestamp', key: 'time', width: 160,
      render: (t: string) => new Date(t).toLocaleString('zh-CN') },
    { title: '标题', dataIndex: 'title', key: 'title' },
    {
      title: '等级', dataIndex: 'severity', key: 'severity', width: 80,
      render: (s: string) => {
        const colors: Record<string, string> = { critical: 'red', high: 'orange', medium: 'gold', low: 'blue' }
        return <Tag color={colors[s]}>{s}</Tag>
      },
    },
    { title: '评分', dataIndex: 'risk_score', key: 'score', width: 80,
      render: (s: number) => <span style={{ fontWeight: 600, color: s >= 80 ? '#F5222D' : s >= 60 ? '#FAAD14' : '#36CFC9' }}>{s}</span>,
    },
    { title: '来源', dataIndex: 'source_requirement', key: 'source', width: 120 },
    {
      title: '状态', dataIndex: 'status', key: 'status', width: 100,
      render: (s: string) => {
        const map: Record<string, any> = { open: { color: 'error', text: '待处理' }, acknowledged: { color: 'processing', text: '已确认' }, in_progress: { color: 'warning', text: '处置中' }, resolved: { color: 'success', text: '已解决' }, false_positive: { color: 'default', text: '误报' } }
        const info = map[s] || { color: 'default', text: s }
        return <Tag color={info.color}>{info.text}</Tag>
      },
    },
    {
      title: '操作', key: 'action', width: 200,
      render: (_: any, record: any) => (
        <Space>
          <Button size="small" onClick={() => onNavigate('alert-detail', record.alert_id)}>详情</Button>
          {record.status === 'open' && (
            <>
              <Button size="small" type="primary" danger onClick={() => handleAction(record.alert_id, 'ip_block')}>封禁</Button>
              <Button size="small" onClick={() => handleAction(record.alert_id, 'rate_limit')}>限流</Button>
            </>
          )}
        </Space>
      ),
    },
  ]

  return (
    <>
      <Card className="dashboard-card" title={<span style={{ color: '#F0F4F8' }}>威胁告警列表（点击行查看详情）</span>}>
        <Table
          columns={columns}
          dataSource={alerts}
          rowKey="alert_id"
          pagination={{ pageSize: 20 }}
          size="middle"
          onRow={(record) => ({ onClick: () => onNavigate('alert-detail', record.alert_id), style: { cursor: 'pointer' } })}
        />
      </Card>

      <Modal
        title={<span style={{ color: '#F0F4F8' }}>告警详情</span>}
        open={!!selectedAlert}
        onCancel={() => setSelectedAlert(null)}
        footer={null}
        width={700}
      >
        {selectedAlert && (
          <div style={{ color: '#F0F4F8' }}>
            <Descriptions bordered column={2} size="small" labelStyle={{ color: '#94A3B8' }} contentStyle={{ color: '#F0F4F8' }}>
              <Descriptions.Item label="告警ID">{selectedAlert.alert_id}</Descriptions.Item>
              <Descriptions.Item label="风险评分">{selectedAlert.risk_score}</Descriptions.Item>
              <Descriptions.Item label="来源规则">{selectedAlert.source_requirement}</Descriptions.Item>
              <Descriptions.Item label="置信度">{(selectedAlert.confidence * 100).toFixed(0)}%</Descriptions.Item>
              <Descriptions.Item label="来源IP">{selectedAlert.source_ip || '-'}</Descriptions.Item>
              <Descriptions.Item label="账号">{selectedAlert.account_id || '-'}</Descriptions.Item>
              <Descriptions.Item label="描述" span={2}>{selectedAlert.description}</Descriptions.Item>
              <Descriptions.Item label="攻击路径" span={2}>
                {selectedAlert.attack_path && selectedAlert.attack_path.length > 0 ? (
                  <div>{getAttackPath(selectedAlert.attack_path)}</div>
                ) : '-'}
              </Descriptions.Item>
            </Descriptions>
          </div>
        )}
      </Modal>
    </>
  )
}
