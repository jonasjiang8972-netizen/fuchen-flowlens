import { useEffect, useMemo, useState } from 'react'
import { Button, Card, Col, Progress, Row, Space, Table, Tag } from 'antd'
import { AlertOutlined, ApiOutlined, DatabaseOutlined, TeamOutlined } from '@ant-design/icons'
import ReactECharts from 'echarts-for-react'
import { alertService, assetService, callerService, coverageService } from '../services/api'
import { closedStatuses, slaState } from '../utils/sla'

interface Props { onNavigate: (page: string, id?: string) => void }

const isOwned = (a: any) => a.claim_status === 'claimed' && !!a.owner
const isSensitive = (a: any) => (a.sensitive_fields?.length || 0) > 0 || a.sensitivity_hint === 'high'
const pct = (n: number, d: number) => (d > 0 ? Math.round((n / d) * 100) : null)

export default function GovernanceDashboard({ onNavigate }: Props) {
  const [assets, setAssets] = useState<any[]>([])
  const [alerts, setAlerts] = useState<any[]>([])
  const [trend, setTrend] = useState<any[]>([])
  const [coverage, setCoverage] = useState<any>(null)
  const [callers, setCallers] = useState<any>(null)

  useEffect(() => {
    Promise.all([assetService.list(), alertService.list(), alertService.trend(14), coverageService.summary(), callerService.list('partner')])
      .then(([assetRows, alertRows, trendRows, cov, partnerCallers]) => {
        setAssets(assetRows)
        setAlerts(alertRows)
        setTrend(trendRows)
        setCoverage(cov)
        setCallers(partnerCallers)
      })
  }, [])

  const openAlerts = alerts.filter(a => !closedStatuses.has(a.status))
  const openHigh = openAlerts.filter(a => a.severity === 'critical' || a.severity === 'high')
  const sensitiveAssets = assets.filter(isSensitive)
  const unclaimed = assets.filter(a => !isOwned(a))
  const shadow = assets.filter(a => a.status === 'shadow')
  const overdue = openAlerts.filter(a => slaState(a).breached)
  const closed = alerts.filter(a => closedStatuses.has(a.status))
  const closedInTime = closed.filter(a => !slaState(a).breached)
  const partners = callers?.stats?.callers_by_type?.partner || 0
  const partnerRequests = callers?.stats?.requests_by_type?.partner || 0
  const blindSpots: any[] = coverage?.blind_spots || []

  const maturity = [
    { label: '资产责任人覆盖', value: pct(assets.length - unclaimed.length, assets.length), note: `${assets.length - unclaimed.length}/${assets.length} 个接口已认领` },
    { label: '采集器在线率', value: pct(coverage?.agents?.online || 0, coverage?.agents?.total || 0), note: `${coverage?.agents?.online || 0}/${coverage?.agents?.total || 0} 个采集器在线` },
    { label: '调用方可识别率', value: coverage?.traffic?.events ? Math.round(coverage.traffic.identified_share * 100) : null, note: '请求中能识别出用户、合作方或服务的比例' },
    { label: '处置时限达成率', value: pct(closedInTime.length, closed.length), note: `${closedInTime.length}/${closed.length} 个已关闭告警在时限内关闭` },
  ]

  // Assets grouped by host: the business systems the platform sees.
  const hostRows = useMemo(() => {
    const byHost = new Map<string, any[]>()
    for (const a of assets) {
      const host = a.host || '（未知主机）'
      byHost.set(host, [...(byHost.get(host) || []), a])
    }
    return [...byHost.entries()].map(([host, rows]) => ({
      host,
      apis: rows.length,
      sensitive: rows.filter(isSensitive).length,
      unclaimed: rows.filter(a => !isOwned(a)).length,
      ownerCoverage: pct(rows.filter(isOwned).length, rows.length) ?? 0,
      dailyCalls: rows.reduce((sum, a) => sum + (a.daily_avg_calls || 0), 0),
    })).sort((a, b) => b.sensitive - a.sensitive || b.apis - a.apis)
  }, [assets])

  const trendOption = useMemo(() => ({
    color: ['#c9352b', '#117865'],
    tooltip: { trigger: 'axis' },
    legend: { top: 0, right: 8, textStyle: { color: '#64748b' } },
    grid: { top: 42, left: 42, right: 18, bottom: 28 },
    xAxis: { type: 'category', data: trend.map(d => d.date.slice(5)), axisLabel: { color: '#64748b' }, axisLine: { lineStyle: { color: '#d9e2ec' } } },
    yAxis: { type: 'value', minInterval: 1, axisLabel: { color: '#64748b' }, splitLine: { lineStyle: { color: '#edf1f6' } } },
    series: [
      { name: '新增严重/高危告警', type: 'line', data: trend.map(d => d.critical + d.high) },
      { name: '关闭告警', type: 'line', data: trend.map(d => d.closed) },
    ],
  }), [trend])

  const questions = [
    { q: '有哪些未登记的影子 API？', a: `${shadow.length} 个`, page: 'assets' },
    { q: '有多少合作方在调用？', a: `${partners} 个合作方，${partnerRequests.toLocaleString()} 次请求`, page: 'identity-center' },
    { q: '有多少严重/高危告警未关闭？', a: `${openHigh.length} 个`, page: 'alerts' },
    { q: '有多少资产无人认领？', a: `${unclaimed.length} 个，其中敏感接口 ${sensitiveAssets.filter(a => !isOwned(a)).length} 个`, page: 'assets' },
    { q: '有多少告警超过处置时限？', a: `${overdue.length} 个`, page: 'work-orders' },
    { q: '有哪些盲区会影响判断？', a: `${blindSpots.length} 项，其中高风险 ${blindSpots.filter(s => s.severity === 'high').length} 项`, page: 'coverage' },
  ]

  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">治理驾驶舱</div>
          <div className="page-heading__desc">面向 IT / 安全 / 架构负责人，聚合 API 暴露面、数据风险、合作方调用和处置闭环。</div>
        </div>
        <Space>
          <Button onClick={() => onNavigate('coverage')}>查看盲区</Button>
          <Button type="primary" onClick={() => onNavigate('work-orders')}>查看处置闭环</Button>
        </Space>
      </div>

      <div className="metric-grid">
        <Card className="metric-card"><div className="metric-card__label"><ApiOutlined /> API 总资产</div><div className="metric-card__value">{assets.length}</div><div className="metric-card__meta">{hostRows.length} 个主机，{shadow.length} 个影子 API</div></Card>
        <Card className="metric-card"><div className="metric-card__label"><AlertOutlined /> 未关闭高危风险</div><div className="metric-card__value" style={{ color: openHigh.length ? 'var(--fl-critical)' : undefined }}>{openHigh.length}</div><div className="metric-card__meta">{overdue.length} 个告警已超过处置时限</div></Card>
        <Card className="metric-card"><div className="metric-card__label"><DatabaseOutlined /> 数据暴露面</div><div className="metric-card__value">{sensitiveAssets.length}</div><div className="metric-card__meta">涉及敏感字段的接口，{sensitiveAssets.filter(a => !isOwned(a)).length} 个无责任人</div></Card>
        <Card className="metric-card"><div className="metric-card__label"><TeamOutlined /> 合作方调用</div><div className="metric-card__value">{partners}</div><div className="metric-card__meta">{partnerRequests.toLocaleString()} 次请求（平台启动以来）</div></Card>
      </div>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={15}>
          <Card title="近 14 天告警趋势">
            <ReactECharts option={trendOption} style={{ height: 320 }} />
          </Card>
        </Col>
        <Col xs={24} xl={9}>
          <Card title="治理成熟度">
            <Space direction="vertical" size={16} style={{ width: '100%' }}>
              {maturity.map(m => (
                <div key={m.label}>
                  <Row justify="space-between"><span>{m.label}</span><b>{m.value === null ? '暂无数据' : `${m.value}%`}</b></Row>
                  <Progress percent={m.value ?? 0} showInfo={false} strokeColor={(m.value ?? 0) >= 80 ? '#117865' : '#d96b20'} />
                  <div className="muted" style={{ fontSize: 12 }}>{m.note}</div>
                </div>
              ))}
            </Space>
          </Card>
        </Col>
      </Row>

      <Card title="按主机统计">
        <Table
          columns={[
            { title: '主机', dataIndex: 'host', key: 'host' },
            { title: 'API 数', dataIndex: 'apis', key: 'apis', width: 90, align: 'right' as const },
            { title: '敏感接口', dataIndex: 'sensitive', key: 'sensitive', width: 100, align: 'right' as const, render: (v: number) => <span style={{ color: v > 0 ? 'var(--fl-high)' : undefined }}>{v}</span> },
            { title: '无责任人', dataIndex: 'unclaimed', key: 'unclaimed', width: 100, align: 'right' as const },
            { title: '责任人覆盖', dataIndex: 'ownerCoverage', key: 'owner', width: 160, render: (v: number) => <Progress percent={v} size="small" /> },
            { title: '日均调用', dataIndex: 'dailyCalls', key: 'calls', width: 120, align: 'right' as const, render: (v: number) => v.toLocaleString() },
          ]}
          dataSource={hostRows}
          rowKey="host"
          pagination={hostRows.length > 10 ? { pageSize: 10 } : false}
          locale={{ emptyText: '暂无资产：接入流量后自动发现' }}
        />
      </Card>

      <Card title="管理层关注问题">
        <div className="governance-question-grid">
          {questions.map((item, index) => (
            <div className="insight-row" key={item.q} style={{ cursor: 'pointer' }} onClick={() => onNavigate(item.page)}>
              <div className="insight-row__index">{index + 1}</div>
              <div><div className="section-title">{item.q}</div><div className="muted"><Tag>{item.a}</Tag></div></div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  )
}
