import { useEffect, useState } from 'react'
import { Card, Descriptions, Tag, Table, Typography, Row, Col, Timeline, Button, Space, Statistic, Steps } from 'antd'
import { ArrowLeftOutlined, ClockCircleOutlined } from '@ant-design/icons'
import { alertService } from '../services/api'

const { Title, Paragraph } = Typography

interface Props {
  alertId: string
  onBack: () => void
  onNavigate: (page: string, id?: string) => void
}

export default function AlertDetail({ alertId, onBack, onNavigate }: Props) {
  const [alert, setAlert] = useState<any>(null)
  const [detail, setDetail] = useState<any>(null)

  useEffect(() => {
    Promise.all([
      alertService.list(),
      alertService.detail(alertId),
    ]).then(([alerts, detail]) => {
      const found = alerts.find((a: any) => a.alert_id === alertId)
      if (found) setAlert(found)
      setDetail(detail)
    })
  }, [alertId])

  if (!alert) return <div style={{ color: '#F0F4F8' }}>加载中...</div>

  const relatedColumns = [
    { title: '告警ID', dataIndex: 'alert_id', key: 'id', width: 100,
      render: (id: string) => <a style={{ color: '#36CFC9' }} onClick={() => onNavigate('alert-detail', id)}>{id}</a> },
    { title: '标题', dataIndex: 'title', key: 'title' },
    {
      title: '等级', dataIndex: 'severity', key: 'severity', width: 80,
      render: (s: string) => {
        const colors: Record<string, string> = { critical: 'red', high: 'orange', medium: 'gold', low: 'blue' }
        return <Tag color={colors[s]}>{s}</Tag>
      },
    },
  ]

  return (
    <div>
      <div style={{ marginBottom: 16 }}>
        <Button type="link" icon={<ArrowLeftOutlined />} onClick={onBack} style={{ color: '#36CFC9', padding: 0 }}>
          返回告警列表
        </Button>
      </div>

      <Row gutter={[16, 16]}>
        <Col span={24}>
          <Card className="dashboard-card" title={<span style={{ color: '#F0F4F8' }}>告警基本信息</span>}>
            <Descriptions bordered column={3} size="small" labelStyle={{ color: '#94A3B8', background: '#132F4C' }} contentStyle={{ color: '#F0F4F8' }}>
              <Descriptions.Item label="告警ID">{alert.alert_id}</Descriptions.Item>
              <Descriptions.Item label="严重等级">
                <Tag color={{ critical: 'red', high: 'orange', medium: 'gold', low: 'blue' }[alert.severity]}>{alert.severity}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="风险评分" span={1}>
                <span style={{ fontSize: '20px', fontWeight: 700, color: alert.risk_score >= 80 ? '#F5222D' : alert.risk_score >= 60 ? '#FAAD14' : '#36CFC9' }}>
                  {alert.risk_score}
                </span>
              </Descriptions.Item>
              <Descriptions.Item label="来源规则">{alert.source_requirement}</Descriptions.Item>
              <Descriptions.Item label="置信度">{(alert.confidence * 100).toFixed(0)}%</Descriptions.Item>
              <Descriptions.Item label="状态">
                <Tag color={{ open: 'error', acknowledged: 'processing', in_progress: 'warning', resolved: 'success' }[alert.status]}>
                  {{ open: '待处理', acknowledged: '已确认', in_progress: '处置中', resolved: '已解决' }[alert.status]}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="来源IP">{alert.source_ip || '-'}</Descriptions.Item>
              <Descriptions.Item label="账号">{alert.account_id || '-'}</Descriptions.Item>
              <Descriptions.Item label="设备指纹">{alert.device_fingerprint || '-'}</Descriptions.Item>
              <Descriptions.Item label="发生时间">{new Date(alert.timestamp).toLocaleString('zh-CN')}</Descriptions.Item>
            </Descriptions>
            <div style={{ marginTop: 12 }}>
              <span style={{ color: '#94A3B8' }}>描述: </span>
              <span style={{ color: '#F0F4F8' }}>{alert.description}</span>
            </div>
          </Card>
        </Col>
      </Row>

      {alert.attack_path?.length > 0 && (
        <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
          <Col span={24}>
            <Card className="dashboard-card" title={<span style={{ color: '#F0F4F8' }}>攻击路径 ({alert.attack_path.length} 步)</span>}>
              <Steps
                direction="vertical"
                size="small"
                current={alert.attack_path.length}
                items={alert.attack_path.map((step: any) => ({
                  title: <span style={{ color: '#F0F4F8' }}>步骤 {step.sequence}: {step.action} - {step.detail}</span>,
                  description: (
                    <div style={{ color: '#94A3B8', fontSize: '12px' }}>
                      IP: {step.source_ip} | 路径: {step.path} | 状态: {step.status_code} | 时间: {new Date(step.timestamp).toLocaleString('zh-CN')}
                    </div>
                  ),
                }))}
              />
            </Card>
          </Col>
        </Row>
      )}

      {detail?.timeline?.length > 0 && (
        <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
          <Col span={12}>
            <Card className="dashboard-card" title={<span style={{ color: '#F0F4F8' }}>事件时间线</span>}>
              <Timeline
                items={detail.timeline.map((t: any) => ({
                  color: '#0D9373',
                  children: (
                    <div>
                      <div style={{ color: '#F0F4F8', fontWeight: 600 }}>{t.event}</div>
                      <div style={{ color: '#94A3B8', fontSize: '12px' }}>{t.detail}</div>
                      <div style={{ color: '#64748B', fontSize: '11px' }}>{new Date(t.time).toLocaleString('zh-CN')}</div>
                    </div>
                  ),
                }))}
              />
            </Card>
          </Col>
          <Col span={12}>
            <Card className="dashboard-card" title={<span style={{ color: '#F0F4F8' }}>原始数据</span>}>
              <Descriptions bordered column={1} size="small" labelStyle={{ color: '#94A3B8' }} contentStyle={{ color: '#F0F4F8' }}>
                {detail?.raw_data && Object.entries(detail.raw_data).map(([k, v]) => (
                  <Descriptions.Item key={k} label={k}>{v as string}</Descriptions.Item>
                ))}
              </Descriptions>
              {detail?.related_alerts?.length > 0 && (
                <div style={{ marginTop: 12 }}>
                  <span style={{ color: '#94A3B8' }}>关联告警: </span>
                  {detail.related_alerts.map((id: string) => (
                    <a key={id} style={{ color: '#36CFC9', marginRight: 8 }} onClick={() => onNavigate('alert-detail', id)}>{id}</a>
                  ))}
                </div>
              )}
            </Card>
          </Col>
        </Row>
      )}
    </div>
  )
}
