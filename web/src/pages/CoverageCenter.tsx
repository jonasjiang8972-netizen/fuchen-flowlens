import { useEffect, useState } from 'react'
import { Card, Col, Progress, Row, Space, Table, Tag } from 'antd'
import { ApiOutlined, CloudServerOutlined, EyeInvisibleOutlined, TeamOutlined } from '@ant-design/icons'
import { coverageService } from '../services/api'

interface Props { onNavigate: (page: string, id?: string) => void }

const severityColor: Record<string, string> = { high: 'red', medium: 'orange', low: 'gold' }
const severityLabel: Record<string, string> = { high: '高', medium: '中', low: '低' }

const pct = (n: number, d: number) => (d > 0 ? Math.round((n / d) * 100) : null)

export default function CoverageCenter({ onNavigate }: Props) {
  const [data, setData] = useState<any>(null)

  useEffect(() => {
    coverageService.summary().then(setData)
  }, [])

  const agents = data?.agents || { total: 0, online: 0, degraded: 0, offline: 0 }
  const assets = data?.assets || { total: 0, unclaimed: 0, stale: 0, sensitive: 0, sensitive_unclaimed: 0 }
  const traffic = data?.traffic || { events: 0, identified_share: 0, body_share: 0 }
  const spots: any[] = data?.blind_spots || []
  const hasTraffic = traffic.events > 0

  const matrix = [
    { label: '采集器在线', value: pct(agents.online, agents.total), note: `${agents.online}/${agents.total} 个采集器在线` },
    { label: '资产责任人覆盖', value: pct(assets.total - assets.unclaimed, assets.total), note: `${assets.total - assets.unclaimed}/${assets.total} 个接口已认领` },
    { label: '24 小时内有流量的接口', value: pct(assets.total - assets.stale, assets.total), note: `${assets.stale} 个接口超过 24 小时无流量` },
    { label: '可识别调用方的请求', value: hasTraffic ? Math.round(traffic.identified_share * 100) : null, note: '其余只能按来源 IP 归并' },
    { label: '采集到响应体的请求', value: hasTraffic ? Math.round(traffic.body_share * 100) : null, note: '影响响应中敏感字段的识别' },
  ]

  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">覆盖率与盲区</div>
          <div className="page-heading__desc">明确哪些采集点、接口、调用方和数据还看不见，避免用不完整的证据做判断。</div>
        </div>
      </div>

      <div className="metric-grid">
        <Card className="metric-card"><div className="metric-card__label"><CloudServerOutlined /> 采集器</div><div className="metric-card__value">{agents.online}/{agents.total}</div><div className="metric-card__meta">在线；{agents.degraded} 个异常，{agents.offline} 个离线</div></Card>
        <Card className="metric-card"><div className="metric-card__label"><ApiOutlined /> 已发现接口</div><div className="metric-card__value">{assets.total}</div><div className="metric-card__meta">{assets.unclaimed} 个无责任人，{assets.sensitive} 个涉及敏感字段</div></Card>
        <Card className="metric-card"><div className="metric-card__label"><TeamOutlined /> 调用方可识别</div><div className="metric-card__value">{hasTraffic ? `${Math.round(traffic.identified_share * 100)}%` : '-'}</div><div className="metric-card__meta">{hasTraffic ? `${traffic.events.toLocaleString()} 次请求（平台启动以来）` : '暂无流量'}</div></Card>
        <Card className="metric-card"><div className="metric-card__label"><EyeInvisibleOutlined /> 盲区</div><div className="metric-card__value" style={{ color: spots.some(s => s.severity === 'high') ? 'var(--fl-critical)' : undefined }}>{spots.length}</div><div className="metric-card__meta">高风险 {spots.filter(s => s.severity === 'high').length} 项</div></Card>
      </div>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={10}>
          <Card title="覆盖率">
            <Space direction="vertical" size={16} style={{ width: '100%' }}>
              {matrix.map(m => (
                <div key={m.label}>
                  <Row justify="space-between"><span>{m.label}</span><b>{m.value === null ? '暂无数据' : `${m.value}%`}</b></Row>
                  <Progress percent={m.value ?? 0} showInfo={false} strokeColor={(m.value ?? 0) >= 80 ? '#117865' : '#d96b20'} />
                  <div className="muted" style={{ fontSize: 12 }}>{m.note}</div>
                </div>
              ))}
            </Space>
          </Card>
        </Col>
        <Col xs={24} xl={14}>
          <Card title="盲区说明">
            <div className="governance-question-grid">
              {[
                ['采集盲区', '采集器离线或异常时，对应采集点的流量看不到。'],
                ['身份盲区', '请求不带用户、API Key 或服务名时，只能按来源 IP 判断调用方，越权和爬虫检测的准确性下降。'],
                ['数据盲区', '没有采集响应体时，只能从 URL 参数识别敏感字段。'],
                ['责任盲区', '接口没有责任人时，风险无法自动分派。'],
                ['时效盲区', '接口长时间无流量，可能已下线，也可能是采集中断。'],
              ].map(([title, desc], index) => (
                <div className="insight-row" key={title}><div className="insight-row__index">{index + 1}</div><div><div className="section-title">{title}</div><div className="muted">{desc}</div></div></div>
              ))}
            </div>
          </Card>
        </Col>
      </Row>

      <Card title="盲区清单与修复建议">
        <Table
          columns={[
            { title: '类型', dataIndex: 'type', key: 'type', width: 150, render: (v: string) => <Tag>{v}</Tag> },
            { title: '范围', dataIndex: 'area', key: 'area', width: 170 },
            { title: '影响', dataIndex: 'impact', key: 'impact' },
            { title: '等级', dataIndex: 'severity', key: 'severity', width: 70, render: (v: string) => <Tag color={severityColor[v]}>{severityLabel[v] || v}</Tag> },
            { title: '建议修复', dataIndex: 'fix', key: 'fix' },
          ]}
          dataSource={spots.map((s, i) => ({ ...s, key: i }))}
          pagination={false}
          locale={{ emptyText: '暂未发现盲区' }}
          onRow={(record: any) => ({ onClick: () => record.link && onNavigate(record.link), style: { cursor: record.link ? 'pointer' : 'default' } })}
        />
      </Card>
    </div>
  )
}
