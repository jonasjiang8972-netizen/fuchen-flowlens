import { useEffect, useMemo, useState } from 'react'
import { Button, Card, Col, Row, Space, Table, Tag } from 'antd'
import {
  AlertOutlined,
  ApiOutlined,
  CheckCircleOutlined,
  ClockCircleOutlined,
  CloudServerOutlined,
  RightOutlined,
  TeamOutlined,
} from '@ant-design/icons'
import ReactECharts from 'echarts-for-react'
import { agentService, alertService, assetService } from '../services/api'

interface Props {
  onNavigate: (page: string, id?: string) => void
}

const severityText: Record<string, string> = {
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

const statusText: Record<string, string> = {
  open: '待处理',
  acknowledged: '已确认',
  in_progress: '处置中',
  resolved: '已解决',
  false_positive: '误报',
}

export default function Dashboard({ onNavigate }: Props) {
  const [agents, setAgents] = useState<any[]>([])
  const [assets, setAssets] = useState<any[]>([])
  const [alerts, setAlerts] = useState<any[]>([])

  useEffect(() => {
    Promise.all([agentService.list(), assetService.list(), alertService.list()]).then(([agentRows, assetRows, alertRows]) => {
      setAgents(agentRows)
      setAssets(assetRows)
      setAlerts(alertRows)
    })
  }, [])

  const openAlerts = alerts.filter(a => a.status === 'open')
  const criticalAlerts = alerts.filter(a => a.severity === 'critical')
  const highAssets = assets.filter(a => a.sensitivity_hint === 'high')
  const shadowAssets = assets.filter(a => a.status === 'shadow')
  const unclaimedAssets = assets.filter(a => a.claim_status === 'unclaimed')
  const onlineAgents = agents.filter(a => a.status === 'online')
  const degradedAgents = agents.filter(a => a.status === 'degraded' || a.status === 'offline')

  const priorityAlerts = useMemo(() => {
    return [...alerts]
      .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
      .slice(0, 5)
  }, [alerts])

  const attentionAssets = useMemo(() => {
    const seen = new Set<string>()
    return [...highAssets, ...shadowAssets].filter(asset => {
      const id = asset.asset_id || `${asset.method}-${asset.host}-${asset.path_normalized}`
      if (seen.has(id)) return false
      seen.add(id)
      return true
    }).slice(0, 8)
  }, [highAssets, shadowAssets])

  const chartText = '#64748b'
  const trendOption = {
    color: ['#c9352b', '#d96b20', '#117865'],
    tooltip: { trigger: 'axis' },
    legend: { top: 0, right: 8, textStyle: { color: chartText } },
    grid: { top: 42, right: 18, bottom: 28, left: 42 },
    xAxis: {
      type: 'category',
      data: ['周一', '周二', '周三', '周四', '周五', '周六', '周日'],
      axisLabel: { color: chartText },
      axisLine: { lineStyle: { color: '#d9e2ec' } },
    },
    yAxis: {
      type: 'value',
      axisLabel: { color: chartText },
      splitLine: { lineStyle: { color: '#edf1f6' } },
    },
    series: [
      { name: '严重', type: 'line', smooth: true, data: [3, 4, 2, 5, 4, 2, criticalAlerts.length], areaStyle: { opacity: 0.06 } },
      { name: '高危', type: 'line', smooth: true, data: [8, 12, 7, 16, 11, 8, alerts.filter(a => a.severity === 'high').length], areaStyle: { opacity: 0.06 } },
      { name: '待处理', type: 'line', smooth: true, data: [22, 26, 18, 31, 24, 20, openAlerts.length], areaStyle: { opacity: 0.06 } },
    ],
  }

  const riskDistOption = {
    tooltip: { trigger: 'item' },
    legend: { bottom: 0, textStyle: { color: chartText } },
    series: [{
      type: 'pie',
      radius: ['54%', '72%'],
      center: ['50%', '44%'],
      data: [
        { value: criticalAlerts.length, name: '严重', itemStyle: { color: '#c9352b' } },
        { value: alerts.filter(a => a.severity === 'high').length, name: '高危', itemStyle: { color: '#d96b20' } },
        { value: alerts.filter(a => a.severity === 'medium').length, name: '中危', itemStyle: { color: '#b7791f' } },
        { value: alerts.filter(a => a.severity === 'low').length, name: '低危', itemStyle: { color: '#2563a9' } },
      ],
      label: { color: chartText },
    }],
  }

  const assetColumns = [
    {
      title: '资产',
      dataIndex: 'path_normalized',
      key: 'path',
      render: (path: string, row: any) => (
        <Space direction="vertical" size={2}>
          <span className="asset-path">{row.method} {path}</span>
          <span className="muted">{row.host} · {row.group_path || '未分组'}</span>
        </Space>
      ),
    },
    {
      title: '风险',
      dataIndex: 'sensitivity_hint',
      key: 'sensitivity',
      width: 86,
      render: (value: string) => <Tag color={value === 'high' ? 'red' : value === 'medium' ? 'gold' : 'blue'}>{value === 'high' ? '高敏' : value === 'medium' ? '中敏' : '低敏'}</Tag>,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 92,
      render: (value: string) => <Tag color={value === 'shadow' ? 'orange' : value === 'zombie' ? 'default' : 'success'}>{value}</Tag>,
    },
    {
      title: '调用',
      dataIndex: 'daily_avg_calls',
      key: 'calls',
      width: 108,
      align: 'right' as const,
      render: (value: number) => value?.toLocaleString(),
    },
  ]

  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">安全工作台</div>
          <div className="page-heading__desc">聚合今日风险、资产变化和采集健康，优先处理影响面最大的 API 安全事件。</div>
        </div>
        <Space>
          <Button onClick={() => onNavigate('assets')}>查看资产</Button>
          <Button type="primary" onClick={() => onNavigate('alerts')}>处理告警</Button>
        </Space>
      </div>

      <div className="metric-grid">
        <Card className="metric-card">
          <div className="metric-card__label"><AlertOutlined /> 待处理告警</div>
          <div className="metric-card__value">{openAlerts.length}</div>
          <div className="metric-card__meta">{criticalAlerts.length} 个严重，{alerts.filter(a => a.severity === 'high').length} 个高危</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><ApiOutlined /> 高敏 API 资产</div>
          <div className="metric-card__value">{highAssets.length}</div>
          <div className="metric-card__meta">{shadowAssets.length} 个影子 API，{unclaimedAssets.length} 个待认领</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><CloudServerOutlined /> 采集器健康</div>
          <div className="metric-card__value">{onlineAgents.length}/{agents.length}</div>
          <div className="metric-card__meta">{degradedAgents.length} 个异常节点需要排查</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><TeamOutlined /> 责任归属</div>
          <div className="metric-card__value">{assets.length - unclaimedAssets.length}</div>
          <div className="metric-card__meta">已认领资产覆盖率 {assets.length ? Math.round((assets.length - unclaimedAssets.length) / assets.length * 100) : 0}%</div>
        </Card>
      </div>

      <div className="workbench-grid">
        <Card title="今日优先处置" extra={<Button type="link" onClick={() => onNavigate('alerts')}>进入告警中心 <RightOutlined /></Button>}>
          <div className="priority-list">
            {priorityAlerts.map(alert => (
              <div className="priority-item" key={alert.alert_id} onClick={() => onNavigate('alert-detail', alert.alert_id)}>
                <div className={`priority-item__rail priority-item__rail--${alert.severity}`} />
                <div>
                  <div className="priority-item__title">{alert.title}</div>
                  <div className="priority-item__meta">
                    {severityText[alert.severity] || alert.severity} · {statusText[alert.status] || alert.status} · {alert.source_ip || alert.account_id || '未知来源'}
                  </div>
                </div>
                <div className="score-pill">{alert.risk_score}</div>
              </div>
            ))}
          </div>
        </Card>

        <Card title="运营状态">
          <Space direction="vertical" size={14} style={{ width: '100%' }}>
            <Row justify="space-between"><Col className="muted"><CheckCircleOutlined /> 数据链路</Col><Col><Tag color="success">正常</Tag></Col></Row>
            <Row justify="space-between"><Col className="muted"><ClockCircleOutlined /> 最新发现</Col><Col>{shadowAssets.length} 个影子 API</Col></Row>
            <Row justify="space-between"><Col className="muted"><AlertOutlined /> 处置 SLA</Col><Col>{openAlerts.length > 5 ? <Tag color="warning">需关注</Tag> : <Tag color="success">稳定</Tag>}</Col></Row>
            <Row justify="space-between"><Col className="muted"><CloudServerOutlined /> 采集异常</Col><Col>{degradedAgents.length} 个节点</Col></Row>
          </Space>
        </Card>
      </div>

      <div className="two-column-grid">
        <Card title="近 7 天风险趋势">
          <ReactECharts option={trendOption} style={{ height: 300 }} />
        </Card>
        <Card title="告警等级分布">
          <ReactECharts option={riskDistOption} style={{ height: 300 }} />
        </Card>
      </div>

      <Card title="需要关注的 API 资产" extra={<Button type="link" onClick={() => onNavigate('assets')}>查看全部</Button>}>
        <Table
          columns={assetColumns}
          dataSource={attentionAssets}
          rowKey="asset_id"
          pagination={false}
          size="middle"
          onRow={(record) => ({ onClick: () => onNavigate('asset-detail', record.asset_id), style: { cursor: 'pointer' } })}
        />
      </Card>
    </div>
  )
}
