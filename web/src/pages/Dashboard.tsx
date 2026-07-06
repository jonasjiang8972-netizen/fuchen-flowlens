import { useEffect, useState } from 'react'
import { Row, Col, Card, Statistic, Table, Tag, Typography } from 'antd'
import {
  ApiOutlined,
  AlertOutlined,
  CheckCircleOutlined,
  WarningOutlined,
} from '@ant-design/icons'
import ReactECharts from 'echarts-for-react'
import { agentService, assetService, alertService } from '../services/api'

const { Title } = Typography

interface Props {
  onNavigate: (page: string, id?: string) => void
}

export default function Dashboard({ onNavigate }: Props) {
  const [agents, setAgents] = useState<any[]>([])
  const [assets, setAssets] = useState<any[]>([])
  const [alerts, setAlerts] = useState<any[]>([])

  useEffect(() => {
    Promise.all([agentService.list(), assetService.list(), alertService.list()]).then(([a, as, al]) => {
      setAgents(a)
      setAssets(as)
      setAlerts(al)
    })
  }, [])

  const onlineAgents = agents.filter(a => a.status === 'online').length
  const highAlerts = alerts.filter(a => a.severity === 'high' || a.severity === 'critical').length
  const unclaimedAssets = assets.filter(a => a.claim_status === 'unclaimed').length

  const trendOption = {
    backgroundColor: 'transparent',
    tooltip: { trigger: 'axis' },
    xAxis: {
      type: 'category',
      data: ['周一', '周二', '周三', '周四', '周五', '周六', '周日'],
      axisLine: { lineStyle: { color: '#1E3A5F' } },
      axisLabel: { color: '#94A3B8' },
    },
    yAxis: {
      type: 'value',
      axisLine: { lineStyle: { color: '#1E3A5F' } },
      axisLabel: { color: '#94A3B8' },
      splitLine: { lineStyle: { color: '#1E3A5F' } },
    },
    series: [
      {
        name: '告警数',
        type: 'line',
        smooth: true,
        data: [12, 19, 8, 25, 16, 9, 14],
        lineStyle: { color: '#F5222D', width: 2 },
        areaStyle: { color: 'rgba(245, 34, 45, 0.1)' },
        itemStyle: { color: '#F5222D' },
      },
      {
        name: '风险事件',
        type: 'line',
        smooth: true,
        data: [35, 42, 28, 55, 38, 22, 30],
        lineStyle: { color: '#FAAD14', width: 2 },
        areaStyle: { color: 'rgba(250, 173, 20, 0.1)' },
        itemStyle: { color: '#FAAD14' },
      },
    ],
    grid: { top: 20, right: 20, bottom: 30, left: 50 },
  }

  const riskDistOption = {
    backgroundColor: 'transparent',
    tooltip: { trigger: 'item' },
    series: [
      {
        type: 'pie',
        radius: ['50%', '70%'],
        data: [
          { value: 5, name: '严重', itemStyle: { color: '#F5222D' } },
          { value: 12, name: '高危', itemStyle: { color: '#FA8C16' } },
          { value: 28, name: '中危', itemStyle: { color: '#FAAD14' } },
          { value: 63, name: '低危', itemStyle: { color: '#36CFC9' } },
        ],
        label: { color: '#94A3B8' },
      },
    ],
  }

  const topAlertsColumns = [
    { title: '时间', dataIndex: 'timestamp', key: 'time', width: 160,
      render: (t: string) => new Date(t).toLocaleString('zh-CN') },
    { title: '告警标题', dataIndex: 'title', key: 'title' },
    {
      title: '严重等级', dataIndex: 'severity', key: 'severity', width: 100,
      render: (s: string) => {
        const colors: Record<string, string> = { critical: 'red', high: 'orange', medium: 'gold', low: 'blue' }
        return <Tag color={colors[s] || 'default'}>{s}</Tag>
      },
    },
    { title: '风险评分', dataIndex: 'risk_score', key: 'score', width: 100,
      render: (s: number) => <span style={{ color: s >= 80 ? '#F5222D' : s >= 60 ? '#FAAD14' : '#36CFC9' }}>{s}</span>,
    },
    {
      title: '状态', dataIndex: 'status', key: 'status', width: 100,
      render: (s: string) => {
        const map: Record<string, string> = { open: '待处理', acknowledged: '已确认', in_progress: '处置中', resolved: '已解决' }
        return <Tag>{map[s] || s}</Tag>
      },
    },
  ]

  const handleAlertClick = (alertId: string) => { onNavigate('alert-detail', alertId) }
  const handleAssetClick = (assetId: string) => { onNavigate('asset-detail', assetId) }

  return (
    <div>
      <Row gutter={[16, 16]}>
        <Col span={6}>
          <Card className="dashboard-card" styles={{ body: { padding: '20px' } }}>
            <Statistic
              title={<span style={{ color: '#94A3B8' }}>API 资产总数</span>}
              value={assets.length}
              prefix={<ApiOutlined style={{ color: '#36CFC9' }} />}
              valueStyle={{ color: '#F0F4F8', fontSize: '28px', fontWeight: 700 }}
              suffix={<span style={{ fontSize: '12px', color: '#36CFC9', cursor: 'pointer' }} onClick={() => onNavigate('assets')}>查看全部 &gt;</span>}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card className="dashboard-card" styles={{ body: { padding: '20px' } }}>
            <Statistic
              title={<span style={{ color: '#94A3B8' }}>在线采集器</span>}
              value={onlineAgents}
              suffix={<span style={{ fontSize: '14px', color: '#94A3B8' }}> / {agents.length}</span>}
              prefix={onlineAgents === agents.length ? <CheckCircleOutlined style={{ color: '#52C41A' }} /> : <WarningOutlined style={{ color: '#FAAD14' }} />}
              valueStyle={{ color: '#F0F4F8', fontSize: '28px', fontWeight: 700 }}
            />
            <div style={{ marginTop: 8, fontSize: '12px', color: '#36CFC9', cursor: 'pointer' }} onClick={() => onNavigate('agents')}>查看详情 &gt;</div>
          </Card>
        </Col>
        <Col span={6}>
          <Card className="dashboard-card" styles={{ body: { padding: '20px' } }}>
            <Statistic
              title={<span style={{ color: '#94A3B8' }}>高危告警</span>}
              value={highAlerts}
              prefix={<AlertOutlined style={{ color: '#F5222D' }} />}
              valueStyle={{ color: '#F5222D', fontSize: '28px', fontWeight: 700 }}
            />
            <div style={{ marginTop: 8, fontSize: '12px', color: '#F5222D', cursor: 'pointer' }} onClick={() => onNavigate('alerts')}>查看告警 &gt;</div>
          </Card>
        </Col>
        <Col span={6}>
          <Card className="dashboard-card" styles={{ body: { padding: '20px' } }}>
            <Statistic
              title={<span style={{ color: '#94A3B8' }}>待认领资产</span>}
              value={unclaimedAssets}
              prefix={<ApiOutlined style={{ color: '#FAAD14' }} />}
              valueStyle={{ color: '#FAAD14', fontSize: '28px', fontWeight: 700 }}
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col span={16}>
          <Card className="dashboard-card" title={<span style={{ color: '#F0F4F8' }}>告警趋势（近7天）</span>}>
            <ReactECharts option={trendOption} style={{ height: '280px' }} />
          </Card>
        </Col>
        <Col span={8}>
          <Card className="dashboard-card" title={<span style={{ color: '#F0F4F8' }}>风险等级分布</span>}>
            <ReactECharts option={riskDistOption} style={{ height: '280px' }} />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col span={24}>
          <Card className="dashboard-card" title={<span style={{ color: '#F0F4F8' }}>Top 风险告警（点击行下钻）</span>}>
            <Table
              columns={topAlertsColumns}
              dataSource={alerts}
              rowKey="alert_id"
              pagination={false}
              size="middle"
              onRow={(record) => ({ onClick: () => handleAlertClick(record.alert_id), style: { cursor: 'pointer' } })}
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col span={24}>
          <Card className="dashboard-card" title={<span style={{ color: '#F0F4F8' }}>高风险资产（点击行下钻）</span>}>
            <Table
              columns={[
                { title: '资产ID', dataIndex: 'asset_id', key: 'id', width: 100,
                  render: (id: string) => <a style={{ color: '#36CFC9' }} onClick={(e) => { e.stopPropagation(); handleAssetClick(id) }}>{id}</a> },
                { title: '路径', dataIndex: 'path_normalized', key: 'path' },
                { title: '敏感度', dataIndex: 'sensitivity_hint', key: 'sens', width: 80,
                  render: (s: string) => <Tag color={s === 'high' ? 'red' : s === 'medium' ? 'orange' : 'green'}>{s}</Tag> },
                { title: '状态', dataIndex: 'status', key: 'status', width: 100,
                  render: (s: string) => <Tag color={s === 'active' ? 'green' : s === 'shadow' ? 'orange' : 'red'}>{s}</Tag> },
                { title: '日均调用', dataIndex: 'daily_avg_calls', key: 'calls', width: 120,
                  render: (c: number) => c?.toLocaleString() },
              ]}
              dataSource={assets.filter((a: any) => a.sensitivity_hint === 'high').slice(0, 5)}
              rowKey="asset_id"
              pagination={false}
              size="middle"
              onRow={(record) => ({ onClick: () => handleAssetClick(record.asset_id), style: { cursor: 'pointer' } })}
            />
          </Card>
        </Col>
      </Row>
    </div>
  )
}
