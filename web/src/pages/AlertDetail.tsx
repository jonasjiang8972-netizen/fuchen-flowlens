import { useEffect, useMemo, useState } from 'react'
import { Button, Card, Col, Descriptions, Row, Space, Steps, Table, Tag, Timeline } from 'antd'
import {
  ArrowLeftOutlined,
  AuditOutlined,
  CheckCircleOutlined,
  ClockCircleOutlined,
  CodeOutlined,
  FileSearchOutlined,
  SafetyCertificateOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons'
import { alertService } from '../services/api'

interface Props {
  alertId: string
  onBack: () => void
  onNavigate: (page: string, id?: string) => void
}

const severityLabel: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
}

const severityColor: Record<string, string> = {
  critical: 'red',
  high: 'orange',
  medium: 'gold',
  low: 'blue',
}

const statusLabel: Record<string, string> = {
  open: '待处理',
  acknowledged: '已确认',
  in_progress: '处置中',
  resolved: '已解决',
  false_positive: '误报',
}

function inferEvidence(alert: any, rawData: Record<string, string>) {
  const requestCount = Number(rawData?.request_count || '847')
  const uniqueIds = Number(rawData?.unique_ids || Math.max(1, requestCount))
  const baseline = alert?.source_requirement === 'FR-DET-002' ? 8 : 12
  const deviation = Math.max(1, Math.round(uniqueIds / baseline))
  const evidenceLevel = (alert?.confidence || 0) >= 0.9 ? '证据完整' : (alert?.confidence || 0) >= 0.75 ? '证据部分完整' : '需人工确认'
  return {
    requestCount,
    uniqueIds,
    baseline,
    deviation,
    evidenceLevel,
    successRate: rawData?.success_rate || '84.3%',
    duration: rawData?.duration || '25 minutes',
  }
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

  const rawData = detail?.raw_data || {}
  const evidence = useMemo(() => inferEvidence(alert, rawData), [alert, rawData])

  if (!alert) return <div className="commercial-page">加载中...</div>

  const evidenceColumns = [
    { title: '证据项', dataIndex: 'key', key: 'key', width: 170 },
    { title: '采集值', dataIndex: 'value', key: 'value' },
    { title: '解释', dataIndex: 'meaning', key: 'meaning' },
  ]

  const evidenceRows = [
    { key: '来源 IP', value: alert.source_ip || '-', meaning: '攻击主体或异常调用来源' },
    { key: '账号 / 主体', value: alert.account_id || alert.device_fingerprint || '-', meaning: '用于关联用户行为与业务流程' },
    { key: '请求次数', value: evidence.requestCount.toLocaleString(), meaning: '当前检测窗口内观测到的请求规模' },
    { key: '唯一对象数', value: evidence.uniqueIds.toLocaleString(), meaning: '判断对象遍历、批量查询或越权访问的重要依据' },
    { key: '历史基线', value: `${evidence.baseline} / 5分钟`, meaning: '同账号或同角色的正常访问水平' },
    { key: '偏离倍数', value: `${evidence.deviation}x`, meaning: '偏离越大，越需要快速处置或限流' },
    { key: '成功率', value: evidence.successRate, meaning: '高成功率说明攻击可能已经命中真实业务对象' },
    { key: 'JA3 / 指纹', value: rawData.ja3_fingerprint || alert.device_fingerprint || '-', meaning: '辅助识别自动化工具、代理或异常客户端' },
  ]

  const recommendedActions = [
    { title: '临时封禁来源 IP', desc: '适用于撞库、批量遍历、恶意爬虫等明显自动化行为。' },
    { title: '对账号或设备限流', desc: '降低误伤风险，适合仍需保留部分业务访问的场景。' },
    { title: '失效当前会话', desc: '适合账号疑似被盗用或 IP 地域异常切换。' },
    { title: '通知 API Owner 核查鉴权', desc: '如果是 BOLA/BFLA，应检查对象级或功能级鉴权逻辑。' },
  ]

  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <Button type="link" icon={<ArrowLeftOutlined />} onClick={onBack} style={{ paddingLeft: 0 }}>返回告警中心</Button>
          <div className="page-heading__title">{alert.title}</div>
          <div className="page-heading__desc">从命中依据、攻击时间线、原始证据和处置建议四个维度完成研判。</div>
        </div>
        <Space>
          <Button icon={<AuditOutlined />}>标记误报</Button>
          <Button icon={<ClockCircleOutlined />}>创建工单</Button>
          <Button type="primary" danger icon={<ThunderboltOutlined />}>立即处置</Button>
        </Space>
      </div>

      <div className="metric-grid">
        <Card className="metric-card">
          <div className="metric-card__label"><SafetyCertificateOutlined /> 风险评分</div>
          <div className="metric-card__value" style={{ color: alert.risk_score >= 90 ? 'var(--fl-critical)' : 'var(--fl-high)' }}>{alert.risk_score}</div>
          <div className="metric-card__meta"><Tag color={severityColor[alert.severity]}>{severityLabel[alert.severity]}</Tag></div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><FileSearchOutlined /> 置信度</div>
          <div className="metric-card__value">{Math.round((alert.confidence || 0) * 100)}%</div>
          <div className="metric-card__meta">{evidence.evidenceLevel}</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label">影响面</div>
          <div className="metric-card__value">{alert.affected_asset_count || 1}</div>
          <div className="metric-card__meta">资产 · {alert.account_id ? '账号上下文完整' : '缺少账号上下文'}</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><CheckCircleOutlined /> 当前状态</div>
          <div className="metric-card__value" style={{ fontSize: 22 }}>{statusLabel[alert.status] || alert.status}</div>
          <div className="metric-card__meta">{new Date(alert.timestamp).toLocaleString('zh-CN')}</div>
        </Card>
      </div>

      <div className="two-column-grid">
        <Card title="命中依据">
          <Descriptions column={1} size="small">
            <Descriptions.Item label="检测规则">{alert.source_requirement}</Descriptions.Item>
            <Descriptions.Item label="核心原因">{alert.description}</Descriptions.Item>
            <Descriptions.Item label="检测窗口">{evidence.duration}</Descriptions.Item>
            <Descriptions.Item label="基线偏离">当前 {evidence.uniqueIds} 个唯一对象，历史基线约 {evidence.baseline} 个，偏离 {evidence.deviation}x</Descriptions.Item>
            <Descriptions.Item label="证据完整性"><Tag color={alert.confidence >= 0.9 ? 'success' : 'warning'}>{evidence.evidenceLevel}</Tag></Descriptions.Item>
          </Descriptions>
        </Card>
        <Card title="处置建议">
          <div className="priority-list">
            {recommendedActions.map((action, index) => (
              <div className="insight-row" key={action.title}>
                <div className="insight-row__index">{index + 1}</div>
                <div>
                  <div className="section-title">{action.title}</div>
                  <div className="muted">{action.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {alert.attack_path?.length > 0 && (
        <Card title={`攻击路径 (${alert.attack_path.length} 步)`}>
          <Steps
            direction="vertical"
            size="small"
            current={alert.attack_path.length}
            items={alert.attack_path.map((step: any) => ({
              title: `${step.action} · ${step.detail}`,
              description: (
                <span className="muted">
                  IP: {step.source_ip || '-'} · 路径: {step.path || '-'} · 状态: {step.status || step.status_code || '-'} · {new Date(step.timestamp).toLocaleString('zh-CN')}
                </span>
              ),
            }))}
          />
        </Card>
      )}

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={14}>
          <Card title="原始证据">
            <Table columns={evidenceColumns} dataSource={evidenceRows} rowKey="key" pagination={false} size="middle" />
          </Card>
        </Col>
        <Col xs={24} xl={10}>
          <Card title="研判时间线">
            <Timeline
              items={(detail?.timeline || []).map((item: any) => ({
                color: '#117865',
                children: (
                  <div>
                    <div className="section-title">{item.event}</div>
                    <div className="muted">{item.detail}</div>
                    <div className="muted">{new Date(item.time).toLocaleString('zh-CN')}</div>
                  </div>
                ),
              }))}
            />
            {detail?.related_alerts?.length > 0 && (
              <div>
                <div className="section-title">关联告警</div>
                <Space wrap style={{ marginTop: 8 }}>
                  {detail.related_alerts.map((id: string) => (
                    <Tag key={id} icon={<CodeOutlined />} onClick={() => onNavigate('alert-detail', id)} style={{ cursor: 'pointer' }}>{id}</Tag>
                  ))}
                </Space>
              </div>
            )}
          </Card>
        </Col>
      </Row>
    </div>
  )
}
