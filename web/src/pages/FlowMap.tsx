import { useEffect, useMemo, useState } from 'react'
import { Alert, Button, Card, Col, Descriptions, Empty, Input, Row, Segmented, Space, Spin, Table, Tag } from 'antd'
import { ApiOutlined, ClusterOutlined, DatabaseOutlined, ReloadOutlined, SearchOutlined, WarningOutlined } from '@ant-design/icons'
import ForceGraph, { KIND_LABEL } from '../components/ForceGraph'
import type { GraphNode } from '../components/ForceGraph'
import { graphService } from '../services/graph'
import type { FlowGraph, FlowView } from '../services/graph'

interface Props {
  onNavigate: (page: string, id?: string) => void
}

const VIEW_HELP: Record<FlowView, string> = {
  business: '调用方 → 服务 → 接口 → 敏感字段：谁在访问哪些接口，接口又暴露了哪些数据。',
  service: '服务与其接口的归属关系，用于评估改动某个接口的影响面。',
  data: '只保留暴露敏感字段的接口，看敏感数据从哪些服务流出。',
}

const RISK_COLOR: Record<string, string> = { critical: 'red', high: 'orange', medium: 'gold', low: 'blue' }

export default function FlowMap({ onNavigate }: Props) {
  const [view, setView] = useState<FlowView>('business')
  const [keyword, setKeyword] = useState('')
  const [query, setQuery] = useState('')
  const [graph, setGraph] = useState<FlowGraph | null>(null)
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<GraphNode | null>(null)

  const load = () => {
    setLoading(true)
    graphService.flow(view, query).then(g => { setGraph(g); setSelected(null) }).finally(() => setLoading(false))
  }
  useEffect(load, [view, query])

  const nodes = graph?.nodes ?? []
  const edges = graph?.edges ?? []
  const byId = useMemo(() => new Map(nodes.map(n => [n.id, n])), [nodes])

  const endpoints = nodes.filter(n => n.kind === 'endpoint')
  const fields = nodes.filter(n => n.kind === 'field')
  const externalClients = nodes.filter(n => n.kind === 'client' && n.zone === 'external')
  const riskyEndpoints = endpoints.filter(n => n.risk).sort((a, b) => (b.calls || 0) - (a.calls || 0))

  // Nodes on the other end of every edge touching the selected node.
  const related = useMemo(() => {
    if (!selected) return []
    return edges
      .filter(e => e.source === selected.id || e.target === selected.id)
      .map(e => {
        const outgoing = e.source === selected.id
        return { edge: e, node: byId.get(outgoing ? e.target : e.source), outgoing }
      })
      .filter(r => r.node)
      .sort((a, b) => (b.edge.calls || 0) - (a.edge.calls || 0))
  }, [selected, edges, byId])

  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">调用链路</div>
          <div className="page-heading__desc">由真实流量聚合出的调用方、服务、接口与敏感字段关系图，随采集持续更新。</div>
        </div>
        <Button icon={<ReloadOutlined />} onClick={load} loading={loading}>刷新</Button>
      </div>

      <div className="metric-grid">
        <Card className="metric-card">
          <div className="metric-card__label"><ApiOutlined /> 接口节点</div>
          <div className="metric-card__value">{endpoints.length}</div>
          <div className="metric-card__meta">当前视图内被调用过的接口</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><ClusterOutlined /> 外网调用方</div>
          <div className="metric-card__value">{externalClients.length}</div>
          <div className="metric-card__meta">来自非内网地址的来源</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><WarningOutlined /> 风险接口</div>
          <div className="metric-card__value">{riskyEndpoints.length}</div>
          <div className="metric-card__meta">暴露敏感字段，或多数调用失败</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><DatabaseOutlined /> 敏感字段类型</div>
          <div className="metric-card__value">{fields.length}</div>
          <div className="metric-card__meta">在响应中被识别到的数据类型</div>
        </Card>
      </div>

      <div className="filter-bar">
        <Input
          prefix={<SearchOutlined />} allowClear value={keyword} style={{ width: 320 }}
          onChange={e => { setKeyword(e.target.value); if (!e.target.value) setQuery('') }}
          onPressEnter={() => setQuery(keyword)}
          placeholder="搜索接口、服务或来源，回车确认"
        />
        <div className="filter-bar__controls">
          <Segmented<FlowView> value={view} onChange={setView} options={[
            { value: 'business', label: '业务流程' },
            { value: 'service', label: '服务依赖' },
            { value: 'data', label: '数据流向' },
          ]} />
        </div>
      </div>

      {graph?.stats.truncated && (
        <Alert type="info" showIcon style={{ marginBottom: 12 }}
          message={`图中只显示调用量最高的 ${graph.stats.shown_edges} 条关系（共 ${graph.stats.total_edges} 条）。可用搜索缩小范围。`} />
      )}
      {!!graph?.stats.dropped && (
        <Alert type="warning" showIcon style={{ marginBottom: 12 }}
          message={`图谱容量已满，${graph.stats.dropped} 次观测未被记录。流量规模超出单机图谱上限，请缩小采集范围或分片部署。`} />
      )}

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={16}>
          <Card title="内外网调用拓扑" extra={<span className="muted">{VIEW_HELP[view]}</span>}>
            <Spin spinning={loading}>
              <ForceGraph
                nodes={nodes} links={edges} height={480} layered
                selectedId={selected?.id} onSelect={setSelected}
                emptyText={loading ? '' : '还没有观测到流量。接入采集器后，这里会自动生成关系图。'}
              />
            </Spin>
          </Card>
        </Col>
        <Col xs={24} xl={8}>
          <Card title={selected ? '节点详情' : '使用说明'} style={{ minHeight: 200 }}>
            {selected ? (
              <Space direction="vertical" size={12} style={{ width: '100%' }}>
                <Descriptions column={1} size="small" colon={false}>
                  <Descriptions.Item label="名称"><span className="asset-path">{selected.label}</span></Descriptions.Item>
                  <Descriptions.Item label="类型">{KIND_LABEL[selected.kind] || selected.kind}{selected.zone ? (selected.zone === 'internal' ? '（内网）' : '（外网）') : ''}</Descriptions.Item>
                  {!!selected.calls && <Descriptions.Item label="调用">{selected.calls} 次{selected.errors ? `，其中 ${selected.errors} 次失败` : ''}</Descriptions.Item>}
                  {selected.risk && <Descriptions.Item label="风险"><Tag color={RISK_COLOR[selected.risk]}>{selected.risk}</Tag></Descriptions.Item>}
                  {selected.detail && <Descriptions.Item label="说明">{selected.detail}</Descriptions.Item>}
                </Descriptions>
                <div>
                  <div className="section-title" style={{ marginBottom: 6 }}>直接关联（{related.length}）</div>
                  {related.length === 0 ? <span className="muted">没有关联节点</span> : (
                    <Space direction="vertical" size={4} style={{ width: '100%' }}>
                      {related.slice(0, 12).map(r => (
                        <div key={r.edge.source + r.edge.target} style={{ display: 'flex', gap: 8, fontSize: 13 }}>
                          <span className="muted">{r.outgoing ? '→' : '←'}</span>
                          <span style={{ flex: 1, wordBreak: 'break-all', cursor: 'pointer' }} onClick={() => setSelected(r.node!)}>{r.node!.label}</span>
                          <span className="muted">{r.edge.calls} 次</span>
                        </div>
                      ))}
                    </Space>
                  )}
                </div>
              </Space>
            ) : (
              <Space direction="vertical" size={12}>
                <div className="insight-row"><div className="insight-row__index">1</div><div><div className="section-title">来自真实流量</div><div className="muted">节点和连线由采集到的请求实时聚合，不是手工绘制的架构图。线越粗，调用越多。</div></div></div>
                <div className="insight-row"><div className="insight-row__index">2</div><div><div className="section-title">红色描边 = 风险</div><div className="muted">暴露敏感字段的接口，或多数调用失败（可能在被探测或撞库）的接口和来源。</div></div></div>
                <div className="insight-row"><div className="insight-row__index">3</div><div><div className="section-title">交互</div><div className="muted">悬停高亮相邻关系，拖动节点固定位置，点击查看详情，滚轮缩放。</div></div></div>
              </Space>
            )}
          </Card>
        </Col>
      </Row>

      <Card title="风险接口">
        <Table
          size="middle" rowKey="id" pagination={{ pageSize: 8, hideOnSinglePage: true }}
          locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="当前视图没有风险接口" /> }}
          dataSource={riskyEndpoints}
          onRow={record => ({ onClick: () => setSelected(record), style: { cursor: 'pointer' } })}
          columns={[
            { title: '接口', dataIndex: 'label', render: (v: string) => <span className="asset-path">{v}</span> },
            { title: '风险', dataIndex: 'risk', width: 90, render: (v: string) => <Tag color={RISK_COLOR[v]}>{v}</Tag> },
            { title: '调用', dataIndex: 'calls', width: 90, align: 'right' as const },
            { title: '失败', dataIndex: 'errors', width: 90, align: 'right' as const, render: (v?: number) => v || 0 },
            { title: '说明', dataIndex: 'detail' },
          ]}
        />
        <div style={{ marginTop: 12 }}>
          <Button type="link" style={{ paddingLeft: 0 }} onClick={() => onNavigate('attack-path')}>查看攻击路径图 →</Button>
        </div>
      </Card>
    </div>
  )
}
