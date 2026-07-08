import { useEffect, useMemo, useState } from 'react'
import { Card, Col, Input, Row, Select, Space, Table, Tag } from 'antd'
import { ApiOutlined, ClusterOutlined, DatabaseOutlined, LinkOutlined, SearchOutlined, WarningOutlined } from '@ant-design/icons'
import ReactECharts from 'echarts-for-react'
import { alertService, assetService } from '../services/api'

interface Props {
  onNavigate: (page: string, id?: string) => void
}

export default function FlowMap({ onNavigate }: Props) {
  const [assets, setAssets] = useState<any[]>([])
  const [alerts, setAlerts] = useState<any[]>([])
  const [keyword, setKeyword] = useState('')
  const [view, setView] = useState('business')

  useEffect(() => {
    Promise.all([assetService.list(), alertService.list()]).then(([assetRows, alertRows]) => {
      setAssets(assetRows)
      setAlerts(alertRows)
    })
  }, [])

  const selectedAssets = useMemo(() => {
    const kw = keyword.trim().toLowerCase()
    return assets.filter(asset => !kw || [asset.path_normalized, asset.group_path, asset.host].some(v => String(v || '').toLowerCase().includes(kw))).slice(0, 8)
  }, [assets, keyword])

  const graphOption = {
    tooltip: {},
    series: [{
      type: 'graph',
      layout: 'none',
      roam: false,
      symbolSize: 54,
      label: { show: true, color: '#142033', fontSize: 12 },
      edgeLabel: { show: true, color: '#64748b', fontSize: 11, formatter: (params: any) => params.data.label || '' },
      lineStyle: { color: '#94a3b8', width: 1.5, curveness: 0.08 },
      data: [
        { name: '外部用户', x: 40, y: 160, itemStyle: { color: '#dbeafe' } },
        { name: 'API Gateway', x: 210, y: 160, itemStyle: { color: '#ccfbf1' } },
        { name: 'BFF', x: 380, y: 160, itemStyle: { color: '#e0f2fe' } },
        { name: '订单服务', x: 560, y: 95, itemStyle: { color: '#ffffff', borderColor: '#117865', borderWidth: 2 } },
        { name: '支付服务', x: 560, y: 225, itemStyle: { color: '#fff7ed', borderColor: '#d96b20', borderWidth: 2 } },
        { name: '风控服务', x: 740, y: 225, itemStyle: { color: '#fef2f2', borderColor: '#c9352b', borderWidth: 2 } },
        { name: '敏感数据', x: 740, y: 95, itemStyle: { color: '#fee2e2' } },
      ],
      links: [
        { source: '外部用户', target: 'API Gateway', label: '156k/min' },
        { source: 'API Gateway', target: 'BFF', label: 'P95 42ms' },
        { source: 'BFF', target: '订单服务', label: 'GET /order' },
        { source: 'BFF', target: '支付服务', label: 'POST /checkout' },
        { source: '支付服务', target: '风控服务', label: '缺少 trace' },
        { source: '订单服务', target: '敏感数据', label: 'recipient_phone' },
      ],
    }],
  }

  const flowRows = [
    { id: 'flow-001', name: '登录后查询订单并发起支付', entry: 'GET /api/v1/order/{id}', steps: 5, deviation: '风控调用缺少 trace_id', risk: 'high' },
    { id: 'flow-002', name: '后台批量导出客户资料', entry: 'GET /api/v1/legacy/export', steps: 3, deviation: '文档缺失，含高敏字段', risk: 'critical' },
    { id: 'flow-003', name: '移动端商品推荐浏览', entry: 'recommendation.ProductService/List', steps: 4, deviation: '调用频率高度规律', risk: 'medium' },
    { id: 'flow-004', name: '管理员查看用户角色', entry: 'GET /api/v1/admin/users', steps: 2, deviation: '管理端点需核查调用来源', risk: 'high' },
  ]

  const columns = [
    { title: '业务流程', dataIndex: 'name', key: 'name' },
    { title: '入口 API', dataIndex: 'entry', key: 'entry', render: (value: string) => <span className="asset-path">{value}</span> },
    { title: '节点数', dataIndex: 'steps', key: 'steps', width: 80, align: 'right' as const },
    { title: '设计偏差 / 盲区', dataIndex: 'deviation', key: 'deviation' },
    { title: '风险', dataIndex: 'risk', key: 'risk', width: 90, render: (value: string) => <Tag color={value === 'critical' ? 'red' : value === 'high' ? 'orange' : 'gold'}>{value}</Tag> },
  ]

  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">调用链路</div>
          <div className="page-heading__desc">合并入口流量、服务间调用和数据字段流转，用真实流量校验业务流程与接口设计是否一致。</div>
        </div>
      </div>

      <div className="metric-grid">
        <Card className="metric-card">
          <div className="metric-card__label"><LinkOutlined /> 已还原流程</div>
          <div className="metric-card__value">42</div>
          <div className="metric-card__meta">覆盖登录、下单、支付、导出等核心链路</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><ClusterOutlined /> 内外网合并链路</div>
          <div className="metric-card__value">18</div>
          <div className="metric-card__meta">入口 API 与内部服务依赖已关联</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><WarningOutlined /> 设计偏差</div>
          <div className="metric-card__value">{flowRows.filter(r => r.risk === 'critical' || r.risk === 'high').length}</div>
          <div className="metric-card__meta">文档缺失、trace 缺口、绕过校验</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><DatabaseOutlined /> 数据流转节点</div>
          <div className="metric-card__value">27</div>
          <div className="metric-card__meta">含敏感字段的跨服务流转路径</div>
        </Card>
      </div>

      <div className="filter-bar">
        <Input prefix={<SearchOutlined />} allowClear value={keyword} onChange={e => setKeyword(e.target.value)} placeholder="搜索入口 API、服务、分组" style={{ width: 320 }} />
        <div className="filter-bar__controls">
          <Select value={view} onChange={setView} style={{ width: 160 }} options={[
            { value: 'business', label: '业务流程视角' },
            { value: 'service', label: '服务依赖视角' },
            { value: 'data', label: '数据流向视角' },
          ]} />
          <Tag color="processing">弱关联: session + account + 5min window</Tag>
        </div>
      </div>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={16}>
          <Card title="内外网调用拓扑">
            <ReactECharts option={graphOption} style={{ height: 360 }} />
          </Card>
        </Col>
        <Col xs={24} xl={8}>
          <Card title="当前视角解释">
            <Space direction="vertical" size={12}>
              <div className="insight-row"><div className="insight-row__index">1</div><div><div className="section-title">外部入口与内部服务合并</div><div className="muted">从网关日志、Agent 采集和服务元数据中关联入口 API 与下游服务。</div></div></div>
              <div className="insight-row"><div className="insight-row__index">2</div><div><div className="section-title">设计偏差标注</div><div className="muted">文档缺失、trace 缺口、敏感字段流转和绕过校验会被标为治理项。</div></div></div>
              <div className="insight-row"><div className="insight-row__index">3</div><div><div className="section-title">面向开发的影响分析</div><div className="muted">帮助判断改动某个接口会影响哪些调用方、流程和下游服务。</div></div></div>
            </Space>
          </Card>
        </Col>
      </Row>

      <Card title="业务流程与一致性偏差">
        <Table columns={columns} dataSource={flowRows} rowKey="id" pagination={false} />
      </Card>

      <Card title="相关 API 资产">
        <Table
          columns={[
            { title: 'API', dataIndex: 'path_normalized', key: 'path', render: (value: string, row: any) => <span className="asset-path">{row.method} {value}</span> },
            { title: '服务/分组', dataIndex: 'group_path', key: 'group' },
            { title: '敏感度', dataIndex: 'sensitivity_hint', key: 'sensitivity', render: (value: string) => <Tag color={value === 'high' ? 'red' : 'blue'}>{value}</Tag> },
            { title: '状态', dataIndex: 'status', key: 'status', render: (value: string) => <Tag>{value}</Tag> },
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
