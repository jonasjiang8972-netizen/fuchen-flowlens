import { useEffect, useState } from 'react'
import { Card, Col, Progress, Row, Select, Table, Tag } from 'antd'
import { ApartmentOutlined, GlobalOutlined, KeyOutlined, UserOutlined } from '@ant-design/icons'
import { callerService } from '../services/api'

const typeLabel: Record<string, string> = {
  external_user: '外部用户',
  partner: '合作方',
  internal_service: '内部服务',
  network_principal: '仅识别到 IP',
  unknown: '未知',
}

const typeColor: Record<string, string> = {
  external_user: 'blue',
  partner: 'purple',
  internal_service: 'cyan',
  network_principal: 'default',
  unknown: 'default',
}

const evidenceLabel: Record<string, string> = {
  gateway_header: '网关身份头',
  api_key: 'API Key',
  service_header: '服务名请求头',
  query_param: 'URL 参数',
  source_ip: '来源 IP',
  none: '无',
}

function ago(t: string) {
  const s = Math.max(0, (Date.now() - new Date(t).getTime()) / 1000)
  if (s < 60) return '刚刚'
  if (s < 3600) return `${Math.floor(s / 60)} 分钟前`
  if (s < 86400) return `${Math.floor(s / 3600)} 小时前`
  return `${Math.floor(s / 86400)} 天前`
}

export default function IdentityCenter() {
  const [data, setData] = useState<any>(null)
  const [type, setType] = useState('')

  useEffect(() => {
    callerService.list(type || undefined).then(setData)
  }, [type])

  const stats = data?.stats
  const byType = stats?.callers_by_type || {}
  const traffic = stats?.requests_by_type || {}
  const totalRequests = stats?.requests || 0
  const identifiedRequests = totalRequests - (traffic.network_principal || 0) - (traffic.unknown || 0)
  const identifiedShare = totalRequests ? Math.round((identifiedRequests / totalRequests) * 100) : null

  const metric = (icon: React.ReactNode, key: string, desc: string) => (
    <Card className="metric-card" style={{ cursor: 'pointer' }} onClick={() => setType(type === key ? '' : key)}>
      <div className="metric-card__label">{icon} {typeLabel[key]}</div>
      <div className="metric-card__value">{(byType[key] || 0).toLocaleString()}</div>
      <div className="metric-card__meta">{(traffic[key] || 0).toLocaleString()} 次请求 · {desc}</div>
    </Card>
  )

  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">身份与调用方</div>
          <div className="page-heading__desc">按请求中的身份信息识别外部用户、合作方和内部服务，统计各调用方的访问情况（平台启动以来）。</div>
        </div>
      </div>

      <div className="metric-grid">
        {metric(<UserOutlined />, 'external_user', '网关身份头或 URL 参数')}
        {metric(<KeyOutlined />, 'partner', 'API Key')}
        {metric(<ApartmentOutlined />, 'internal_service', '服务名请求头')}
        {metric(<GlobalOutlined />, 'network_principal', '只能按来源 IP 归并')}
      </div>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={16}>
          <Card
            title="调用方"
            extra={<Select value={type} onChange={setType} style={{ width: 150 }}
              options={[{ value: '', label: '全部类型' }, ...Object.keys(typeLabel).filter(k => k !== 'unknown').map(k => ({ value: k, label: typeLabel[k] }))]} />}
          >
            <Table
              columns={[
                { title: '调用方', dataIndex: 'caller_id', key: 'id', render: (v: string) => <span className="mono">{v}</span> },
                { title: '类型', dataIndex: 'type', key: 'type', width: 110, render: (v: string) => <Tag color={typeColor[v]}>{typeLabel[v] || v}</Tag> },
                { title: '识别依据', dataIndex: 'evidence', key: 'evidence', width: 110, render: (v: string) => evidenceLabel[v] || v },
                { title: '置信度', dataIndex: 'confidence', key: 'confidence', width: 120, render: (v: number) => <Progress percent={Math.round(v * 100)} size="small" strokeColor={v >= 0.9 ? 'var(--fl-success)' : 'var(--fl-medium)'} /> },
                { title: '请求', dataIndex: 'requests', key: 'requests', width: 90, align: 'right' as const, render: (v: number) => v.toLocaleString() },
                { title: '错误率', key: 'errors', width: 80, align: 'right' as const, render: (_: any, r: any) => { const rate = r.requests ? r.errors / r.requests : 0; return <span style={{ color: rate >= 0.2 ? 'var(--fl-critical)' : undefined }}>{(rate * 100).toFixed(1)}%</span> } },
                { title: '接口数', dataIndex: 'endpoints', key: 'endpoints', width: 80, align: 'right' as const },
                { title: '未关闭告警', dataIndex: 'open_alerts', key: 'alerts', width: 100, align: 'right' as const, render: (v: number) => (v ? <Tag color="red">{v}</Tag> : 0) },
                { title: '最近访问', dataIndex: 'last_seen', key: 'last', width: 100, render: ago },
              ]}
              dataSource={data?.items || []}
              rowKey="caller_id"
              size="small"
              pagination={(data?.items?.length || 0) > 15 ? { pageSize: 15 } : false}
              expandable={{ expandedRowRender: (r: any) => <span className="muted">来源 IP：{(r.source_ips || []).join('、') || '-'}　首次访问：{new Date(r.first_seen).toLocaleString('zh-CN')}{r.role ? `　角色：${r.role}` : ''}</span> }}
              locale={{ emptyText: '暂无流量' }}
            />
            {(stats?.untracked_requests || 0) > 0 && <div className="muted" style={{ marginTop: 8 }}>调用方超过 2 万个后，新调用方的 {stats.untracked_requests.toLocaleString()} 次请求未单独统计。</div>}
          </Card>
        </Col>
        <Col xs={24} xl={8}>
          <Card title="身份识别情况">
            <div style={{ marginBottom: 16 }}>
              <Row justify="space-between"><span>可识别调用方的请求</span><b>{identifiedShare === null ? '暂无数据' : `${identifiedShare}%`}</b></Row>
              <Progress percent={identifiedShare ?? 0} showInfo={false} strokeColor={(identifiedShare ?? 0) >= 50 ? '#117865' : '#d96b20'} />
              <div className="muted" style={{ fontSize: 12 }}>其余请求只能按来源 IP 归并。让网关透传 x-user-id、x-api-key 或 x-service-name 请求头可以提高识别率。</div>
            </div>
          </Card>
          <Card title="识别规则（按顺序匹配）" style={{ marginTop: 16 }}>
            <Table
              columns={[
                { title: '依据', dataIndex: 'source', key: 'source', render: (v: string, r: any) => <div><div>{v}</div><div className="muted" style={{ fontSize: 12 }}>{r.note}</div></div> },
                { title: '识别为', dataIndex: 'type', key: 'type', width: 100, render: (v: string) => <Tag color={typeColor[v]}>{typeLabel[v] || v}</Tag> },
                { title: '置信度', dataIndex: 'confidence', key: 'confidence', width: 70, render: (v: number) => v.toFixed(2) },
              ]}
              dataSource={data?.rules || []}
              rowKey="order"
              size="small"
              pagination={false}
            />
          </Card>
        </Col>
      </Row>
    </div>
  )
}
