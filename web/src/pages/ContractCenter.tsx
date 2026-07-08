import { Card, Input, Select, Space, Table, Tag } from 'antd'
import { FileDoneOutlined, SearchOutlined } from '@ant-design/icons'

interface Props { onNavigate: (page: string, id?: string) => void }

const driftRows = [
  { id: 'CON-001', api: 'GET /api/v1/legacy/export', type: '文档缺失接口', source: '真实流量有调用，OpenAPI/CMDB 不存在', owner: '待认领', severity: 'high', impact: '返回姓名、身份证、手机号' },
  { id: 'CON-002', api: 'GET /api/v1/order/{id}', type: '响应字段漂移', source: '响应新增 recipient_phone，契约未声明', owner: '订单团队', severity: 'high', impact: '敏感字段超范围返回' },
  { id: 'CON-003', api: 'POST /api/v1/payment/checkout', type: '状态码不一致', source: '线上出现 402/429，文档未声明', owner: '支付团队', severity: 'medium', impact: '客户端错误处理不稳定' },
  { id: 'CON-004', api: 'GET /api/v1/admin/users', type: '非预期调用方', source: '公网来源触达管理端点', owner: '安全团队', severity: 'high', impact: '需校验网关路由和角色鉴权' },
  { id: 'CON-005', api: 'recommendation.ProductService/List', type: '高频旧版本调用', source: '旧客户端仍调用 v1 schema', owner: '推荐团队', severity: 'medium', impact: '下线风险和兼容成本' },
]

export default function ContractCenter({ onNavigate }: Props) {
  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">契约一致性</div>
          <div className="page-heading__desc">用真实流量校验 OpenAPI / Proto / CMDB / 业务流程设计，发现接口失控、字段漂移和非预期调用。</div>
        </div>
      </div>

      <div className="metric-grid">
        <Card className="metric-card"><div className="metric-card__label"><FileDoneOutlined /> 差异项</div><div className="metric-card__value">{driftRows.length}</div><div className="metric-card__meta">真实流量与设计契约不一致</div></Card>
        <Card className="metric-card"><div className="metric-card__label">文档缺失</div><div className="metric-card__value">2</div><div className="metric-card__meta">影子 API 或未纳入 CMDB</div></Card>
        <Card className="metric-card"><div className="metric-card__label">Schema 漂移</div><div className="metric-card__value">4</div><div className="metric-card__meta">请求/响应字段变化</div></Card>
        <Card className="metric-card"><div className="metric-card__label">非预期调用方</div><div className="metric-card__value">3</div><div className="metric-card__meta">公网、Partner 或内部服务越界调用</div></Card>
      </div>

      <div className="filter-bar">
        <Input prefix={<SearchOutlined />} placeholder="搜索 API、Owner、差异类型" style={{ width: 320 }} />
        <div className="filter-bar__controls">
          <Select defaultValue="all" style={{ width: 140 }} options={[{ value: 'all', label: '全部差异' }, { value: 'schema', label: 'Schema 漂移' }, { value: 'missing', label: '文档缺失' }, { value: 'caller', label: '非预期调用' }]} />
          <Select defaultValue="all" style={{ width: 120 }} options={[{ value: 'all', label: '全部等级' }, { value: 'high', label: '高危' }, { value: 'medium', label: '中危' }]} />
        </div>
      </div>

      <Card title="契约差异清单">
        <Table
          columns={[
            { title: '差异ID', dataIndex: 'id', key: 'id', width: 100 },
            { title: 'API', dataIndex: 'api', key: 'api', render: (v: string) => <span className="asset-path">{v}</span> },
            { title: '差异类型', dataIndex: 'type', key: 'type', width: 140, render: (v: string) => <Tag>{v}</Tag> },
            { title: '真实流量证据', dataIndex: 'source', key: 'source' },
            { title: 'Owner', dataIndex: 'owner', key: 'owner', width: 120 },
            { title: '等级', dataIndex: 'severity', key: 'severity', width: 90, render: (v: string) => <Tag color={v === 'high' ? 'orange' : 'gold'}>{v}</Tag> },
            { title: '影响', dataIndex: 'impact', key: 'impact' },
          ]}
          dataSource={driftRows}
          rowKey="id"
          pagination={false}
          onRow={(record) => ({ onClick: () => record.api.includes('/api/') && onNavigate('assets'), style: { cursor: 'pointer' } })}
        />
      </Card>

      <Card title="一致性校验维度">
        <div className="governance-question-grid">
          {['接口是否在 OpenAPI/Proto 中声明', '请求参数类型是否与真实流量一致', '响应字段是否出现超范围返回', '状态码是否符合客户端设计', '调用方是否在设计范围内', '业务流程是否缺少鉴权/风控/审批步骤'].map((item, index) => (
            <div className="insight-row" key={item}><div className="insight-row__index">{index + 1}</div><div><div className="section-title">{item}</div><div className="muted">结合网关、流量、Schema 指纹和 CMDB 做自动比对。</div></div></div>
          ))}
        </div>
      </Card>
    </div>
  )
}
