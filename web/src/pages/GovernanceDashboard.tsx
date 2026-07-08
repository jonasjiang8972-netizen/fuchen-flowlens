import { useEffect, useMemo, useState } from 'react'
import { Button, Card, Col, Progress, Row, Space, Table, Tag } from 'antd'
import { AlertOutlined, ApiOutlined, DatabaseOutlined, SafetyCertificateOutlined, TeamOutlined } from '@ant-design/icons'
import ReactECharts from 'echarts-for-react'
import { alertService, assetService } from '../services/api'

interface Props { onNavigate: (page: string, id?: string) => void }

const businessRows = [
  { domain: '零售事业部 / 交易系统', apis: 42, highRisk: 8, ownerCoverage: 86, sla: 74, dataExposure: '高' },
  { domain: '支付系统', apis: 18, highRisk: 5, ownerCoverage: 68, sla: 62, dataExposure: '高' },
  { domain: '供应链 / 仓储', apis: 16, highRisk: 2, ownerCoverage: 91, sla: 88, dataExposure: '中' },
  { domain: '推荐系统', apis: 21, highRisk: 1, ownerCoverage: 100, sla: 92, dataExposure: '低' },
]

export default function GovernanceDashboard({ onNavigate }: Props) {
  const [assets, setAssets] = useState<any[]>([])
  const [alerts, setAlerts] = useState<any[]>([])

  useEffect(() => {
    Promise.all([assetService.list(), alertService.list()]).then(([assetRows, alertRows]) => {
      setAssets(assetRows)
      setAlerts(alertRows)
    })
  }, [])

  const highAlerts = alerts.filter(a => a.severity === 'critical' || a.severity === 'high')
  const highAssets = assets.filter(a => a.sensitivity_hint === 'high')
  const shadowAssets = assets.filter(a => a.status === 'shadow')
  const unclaimedAssets = assets.filter(a => a.claim_status === 'unclaimed')
  const externalAssets = assets.filter(a => a.host?.includes('api.example.com'))
  const partnerRisk = 7

  const trendOption = useMemo(() => ({
    color: ['#c9352b', '#d96b20', '#117865'],
    tooltip: { trigger: 'axis' },
    legend: { top: 0, right: 8, textStyle: { color: '#64748b' } },
    grid: { top: 42, left: 42, right: 18, bottom: 28 },
    xAxis: { type: 'category', data: ['W1', 'W2', 'W3', 'W4', 'W5', 'W6'], axisLabel: { color: '#64748b' }, axisLine: { lineStyle: { color: '#d9e2ec' } } },
    yAxis: { type: 'value', axisLabel: { color: '#64748b' }, splitLine: { lineStyle: { color: '#edf1f6' } } },
    series: [
      { name: '高危风险', type: 'line', smooth: true, data: [18, 21, 16, 14, 12, highAlerts.length] },
      { name: '未认领资产', type: 'line', smooth: true, data: [9, 8, 7, 6, 5, unclaimedAssets.length] },
      { name: 'SLA达成率', type: 'line', smooth: true, data: [63, 68, 72, 75, 78, 82] },
    ],
  }), [highAlerts.length, unclaimedAssets.length])

  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">治理驾驶舱</div>
          <div className="page-heading__desc">面向 IT / 安全 / 架构负责人，聚合 API 暴露面、数据风险、供应链风险和治理责任闭环。</div>
        </div>
        <Space>
          <Button onClick={() => onNavigate('coverage')}>查看盲区</Button>
          <Button type="primary" onClick={() => onNavigate('work-orders')}>查看处置闭环</Button>
        </Space>
      </div>

      <div className="metric-grid">
        <Card className="metric-card"><div className="metric-card__label"><ApiOutlined /> API 总资产</div><div className="metric-card__value">{assets.length}</div><div className="metric-card__meta">{externalAssets.length} 个外部入口，{shadowAssets.length} 个影子 API</div></Card>
        <Card className="metric-card"><div className="metric-card__label"><AlertOutlined /> 高危风险</div><div className="metric-card__value" style={{ color: 'var(--fl-critical)' }}>{highAlerts.length}</div><div className="metric-card__meta">影响 {highAssets.length} 个高敏 API</div></Card>
        <Card className="metric-card"><div className="metric-card__label"><DatabaseOutlined /> 数据暴露面</div><div className="metric-card__value">{highAssets.length}</div><div className="metric-card__meta">高敏字段和未脱敏接口需持续治理</div></Card>
        <Card className="metric-card"><div className="metric-card__label"><TeamOutlined /> 供应链风险</div><div className="metric-card__value">{partnerRisk}</div><div className="metric-card__meta">Partner API Key、外发字段、回调接口</div></Card>
      </div>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={15}>
          <Card title="治理趋势">
            <ReactECharts option={trendOption} style={{ height: 320 }} />
          </Card>
        </Col>
        <Col xs={24} xl={9}>
          <Card title="治理成熟度">
            <Space direction="vertical" size={16} style={{ width: '100%' }}>
              <div><Row justify="space-between"><span>资产 Owner 覆盖</span><b>82%</b></Row><Progress percent={82} strokeColor="#117865" /></div>
              <div><Row justify="space-between"><span>采集覆盖率</span><b>76%</b></Row><Progress percent={76} strokeColor="#117865" /></div>
              <div><Row justify="space-between"><span>身份解析置信度</span><b>88%</b></Row><Progress percent={88} strokeColor="#117865" /></div>
              <div><Row justify="space-between"><span>处置 SLA 达成</span><b>82%</b></Row><Progress percent={82} strokeColor="#117865" /></div>
            </Space>
          </Card>
        </Col>
      </Row>

      <Card title="业务线风险排行">
        <Table
          columns={[
            { title: '业务域', dataIndex: 'domain', key: 'domain' },
            { title: 'API 数', dataIndex: 'apis', key: 'apis', width: 90, align: 'right' as const },
            { title: '高危风险', dataIndex: 'highRisk', key: 'risk', width: 100, align: 'right' as const, render: (v: number) => <span style={{ color: v > 4 ? 'var(--fl-critical)' : 'var(--fl-medium)' }}>{v}</span> },
            { title: 'Owner 覆盖', dataIndex: 'ownerCoverage', key: 'owner', width: 160, render: (v: number) => <Progress percent={v} size="small" /> },
            { title: 'SLA 达成', dataIndex: 'sla', key: 'sla', width: 160, render: (v: number) => <Progress percent={v} size="small" strokeColor={v < 70 ? 'var(--fl-high)' : 'var(--fl-success)'} /> },
            { title: '数据暴露', dataIndex: 'dataExposure', key: 'data', width: 100, render: (v: string) => <Tag color={v === '高' ? 'red' : v === '中' ? 'gold' : 'blue'}>{v}</Tag> },
          ]}
          dataSource={businessRows}
          rowKey="domain"
          pagination={false}
        />
      </Card>

      <Card title="管理层关注问题">
        <div className="governance-question-grid">
          {['哪些 API 对公网开放？', '哪些数据正在外发给 Partner？', '哪些业务线高危风险复发？', '哪些资产长期无人认领？', '哪些告警超过 SLA？', '哪些采集盲区会影响判断？'].map((item, index) => (
            <div className="insight-row" key={item}><div className="insight-row__index">{index + 1}</div><div><div className="section-title">{item}</div><div className="muted">可从资产、身份、链路、数据和工单维度继续下钻。</div></div></div>
          ))}
        </div>
      </Card>
    </div>
  )
}
