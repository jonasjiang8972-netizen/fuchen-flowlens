import { useEffect, useMemo, useState } from 'react'
import { Card, Col, Input, Row, Space, Table, Tag } from 'antd'
import { ApiOutlined, ClusterOutlined, LinkOutlined, SearchOutlined, WarningOutlined } from '@ant-design/icons'
import ReactECharts from 'echarts-for-react'
import { assetService, topologyService } from '../services/api'

interface Props {
  onNavigate: (page: string, id?: string) => void
}

const callerLabel: Record<string, string> = {
  external_user: '外部用户',
  partner: '合作方',
  internal_service: '内部服务',
  network_principal: '仅识别到 IP',
  unknown: '未知调用方',
}

const kindColumn: Record<string, number> = { caller: 0, host: 1, service: 2 }
const kindStyle: Record<string, any> = {
  caller: { color: '#dbeafe', borderColor: '#2563a9' },
  host: { color: '#ccfbf1', borderColor: '#117865' },
  service: { color: '#ffffff', borderColor: '#64748b' },
}

const nodeName = (id: string) => {
  const [kind, ...rest] = id.split(':')
  const name = rest.join(':')
  return kind === 'caller' ? callerLabel[name] || name : name
}

export default function FlowMap({ onNavigate }: Props) {
  const [assets, setAssets] = useState<any[]>([])
  const [topology, setTopology] = useState<any>(null)
  const [keyword, setKeyword] = useState('')

  useEffect(() => {
    Promise.all([assetService.list(), topologyService.get()]).then(([assetRows, topo]) => {
      setAssets(assetRows)
      setTopology(topo)
    })
  }, [])

  const nodes: any[] = topology?.nodes || []
  const edges: any[] = topology?.edges || []

  // Three columns: caller types -> hosts -> backends. At most 12 nodes per
  // column, busiest first, so the graph stays readable.
  const graph = useMemo(() => {
    const perColumn: Record<number, any[]> = { 0: [], 1: [], 2: [] }
    for (const n of nodes) {
      const col = kindColumn[n.kind]
      if (col !== undefined && perColumn[col].length < 12) perColumn[col].push(n)
    }
    const shown = new Set<string>()
    const data: any[] = []
    const maxRequests = Math.max(1, ...nodes.map(n => n.requests))
    for (const col of [0, 1, 2]) {
      const list = perColumn[col]
      list.forEach((n, i) => {
        shown.add(n.id)
        data.push({
          id: n.id,
          name: nodeName(n.id),
          x: col * 300,
          y: (i + 1) * (Math.max(360, list.length * 56) / (list.length + 1)),
          label: { position: col === 2 ? 'right' : col === 0 ? 'left' : 'bottom' },
          symbolSize: 28 + 30 * Math.sqrt(n.requests / maxRequests),
          value: n.requests,
          itemStyle: { ...kindStyle[n.kind], borderWidth: 2 },
        })
      })
    }
    const links = edges.filter(e => shown.has(e.from) && shown.has(e.to)).map(e => {
      const errorRate = e.requests ? e.errors / e.requests : 0
      return {
        source: e.from,
        target: e.to,
        value: e.requests,
        label: { show: true, formatter: `${e.requests.toLocaleString()}${errorRate >= 0.1 ? ` · 错误 ${(errorRate * 100).toFixed(0)}%` : ''}` },
        lineStyle: { color: errorRate >= 0.1 ? '#c9352b' : '#94a3b8', width: 1 + 4 * Math.sqrt(e.requests / maxRequests) },
      }
    })
    return { data, links }
  }, [nodes, edges])

  const graphOption = {
    tooltip: { formatter: (p: any) => (p.dataType === 'edge' ? `${nodeName(p.data.source)} → ${nodeName(p.data.target)}<br/>${p.data.value.toLocaleString()} 次请求` : `${p.data.name}<br/>${(p.data.value || 0).toLocaleString()} 次请求`) },
    series: [{
      type: 'graph',
      layout: 'none',
      roam: true,
      label: { show: true, position: 'bottom', color: '#142033', fontSize: 12 },
      edgeLabel: { show: true, color: '#64748b', fontSize: 11 },
      edgeSymbol: ['none', 'arrow'],
      data: graph.data,
      links: graph.links,
    }],
  }

  const callers = nodes.filter(n => n.kind === 'caller')
  const hosts = nodes.filter(n => n.kind === 'host')
  const backends = nodes.filter(n => n.kind === 'service')
  const noisyEdges = edges.filter(e => e.requests >= 20 && e.errors / e.requests >= 0.1)

  const edgeRows = edges.filter(e => {
    const kw = keyword.trim().toLowerCase()
    return !kw || `${nodeName(e.from)} ${nodeName(e.to)}`.toLowerCase().includes(kw)
  }).map(e => ({ ...e, key: `${e.from}>${e.to}`, errorRate: e.requests ? e.errors / e.requests : 0 }))

  const selectedAssets = useMemo(() => {
    const kw = keyword.trim().toLowerCase()
    return assets.filter(asset => !kw || [asset.path_normalized, asset.group_path, asset.host].some(v => String(v || '').toLowerCase().includes(kw))).slice(0, 20)
  }, [assets, keyword])

  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">调用链路</div>
          <div className="page-heading__desc">根据真实流量还原"调用方 → 访问主机 → 网关转发的后端服务"三段关系（平台启动以来）。</div>
        </div>
      </div>

      <div className="metric-grid">
        <Card className="metric-card">
          <div className="metric-card__label"><LinkOutlined /> 调用方类型</div>
          <div className="metric-card__value">{callers.length}</div>
          <div className="metric-card__meta">{callers.map(c => nodeName(c.id)).join('、') || '暂无流量'}</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><ApiOutlined /> 访问主机</div>
          <div className="metric-card__value">{hosts.length}</div>
          <div className="metric-card__meta">请求中的 Host</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><ClusterOutlined /> 后端服务</div>
          <div className="metric-card__value">{backends.length}</div>
          <div className="metric-card__meta">网关路由名或转发地址</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><WarningOutlined /> 高错误率链路</div>
          <div className="metric-card__value" style={{ color: noisyEdges.length ? 'var(--fl-critical)' : undefined }}>{noisyEdges.length}</div>
          <div className="metric-card__meta">错误率 ≥ 10% 且请求 ≥ 20 次</div>
        </Card>
      </div>

      <div className="filter-bar">
        <Input prefix={<SearchOutlined />} allowClear value={keyword} onChange={e => setKeyword(e.target.value)} placeholder="搜索调用方、主机、服务或 API" style={{ width: 320 }} />
        {topology?.truncated && <Tag color="warning">链路过多，只统计了前 5000 条</Tag>}
      </div>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={16}>
          <Card title="调用拓扑">
            {graph.data.length ? <ReactECharts option={graphOption} style={{ height: Math.max(380, Math.min(12, nodes.filter(n => n.kind === 'service').length) * 56 + 40) }} />
              : <div style={{ height: 380, display: 'flex', alignItems: 'center', justifyContent: 'center' }} className="muted">暂无流量：接入采集器后自动生成</div>}
          </Card>
        </Col>
        <Col xs={24} xl={8}>
          <Card title="如何阅读">
            <Space direction="vertical" size={12}>
              <div className="insight-row"><div className="insight-row__index">1</div><div><div className="section-title">左：调用方类型</div><div className="muted">按请求头识别出的外部用户、合作方、内部服务；识别不到时按来源 IP 归为一类。</div></div></div>
              <div className="insight-row"><div className="insight-row__index">2</div><div><div className="section-title">中：访问主机</div><div className="muted">请求的 Host。节点越大请求越多，红色连线表示错误率 ≥ 10%。</div></div></div>
              <div className="insight-row"><div className="insight-row__index">3</div><div><div className="section-title">右：后端服务</div><div className="muted">网关日志中的路由名或转发地址。服务之间的内部调用需要接入链路追踪（trace）后才能还原。</div></div></div>
            </Space>
          </Card>
        </Col>
      </Row>

      <Card title="链路明细">
        <Table
          columns={[
            { title: '从', dataIndex: 'from', key: 'from', render: (v: string) => nodeName(v) },
            { title: '到', dataIndex: 'to', key: 'to', render: (v: string) => nodeName(v) },
            { title: '请求数', dataIndex: 'requests', key: 'requests', width: 120, align: 'right' as const, render: (v: number) => v.toLocaleString() },
            { title: '错误率', dataIndex: 'errorRate', key: 'errorRate', width: 110, align: 'right' as const, render: (v: number) => <span style={{ color: v >= 0.1 ? 'var(--fl-critical)' : undefined }}>{(v * 100).toFixed(1)}%</span> },
          ]}
          dataSource={edgeRows}
          rowKey="key"
          pagination={edgeRows.length > 10 ? { pageSize: 10 } : false}
          locale={{ emptyText: '暂无流量' }}
        />
      </Card>

      <Card title="相关 API 资产">
        <Table
          columns={[
            { title: 'API', dataIndex: 'path_normalized', key: 'path', render: (value: string, row: any) => <span className="asset-path">{row.method} {value}</span> },
            { title: '主机', dataIndex: 'host', key: 'host' },
            { title: '服务/分组', dataIndex: 'group_path', key: 'group' },
            { title: '敏感度', dataIndex: 'sensitivity_hint', key: 'sensitivity', render: (value: string) => <Tag color={value === 'high' ? 'red' : 'blue'}>{value}</Tag> },
            { title: '状态', dataIndex: 'status', key: 'status', render: (value: string) => <Tag>{value === 'shadow' ? '影子 API' : value}</Tag> },
          ]}
          dataSource={selectedAssets}
          rowKey="asset_id"
          pagination={false}
          onRow={(record) => ({ onClick: () => onNavigate('asset-detail', record.asset_id), style: { cursor: 'pointer' } })}
        />
      </Card>
    </div>
  )
}
