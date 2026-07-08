import { Card, Col, Progress, Row, Space, Table, Tag } from 'antd'
import { ApartmentOutlined, KeyOutlined, SafetyCertificateOutlined, TeamOutlined, UserOutlined } from '@ant-design/icons'

const principalRows = [
  {
    id: 'usr-88213',
    type: 'external_user',
    label: '外部用户',
    source: 'JWT sub + Cookie sid + 登录事件绑定',
    confidence: 92,
    zone: '公网',
    lastSeen: '5分钟前',
    risk: 'high',
  },
  {
    id: 'partner-alipay-openapi',
    type: 'partner',
    label: '供应链伙伴',
    source: 'x-api-key + partner registry + 白名单 IP',
    confidence: 96,
    zone: 'Partner 专线',
    lastSeen: '12分钟前',
    risk: 'medium',
  },
  {
    id: 'svc-order-api',
    type: 'internal_service',
    label: '内部服务',
    source: 'mTLS SAN + x-service-name + K8s serviceAccount',
    confidence: 98,
    zone: '内网服务',
    lastSeen: '刚刚',
    risk: 'low',
  },
  {
    id: 'ops-admin-zhang',
    type: 'internal_user',
    label: '内部用户',
    source: 'SSO token + VPN 网关 + 企业邮箱域',
    confidence: 89,
    zone: '办公网',
    lastSeen: '28分钟前',
    risk: 'medium',
  },
]

const extractorRows = [
  { id: 'jwt-sub', name: 'JWT Subject', source: 'header.Authorization', parser: 'jwt.claim.sub', principal: '外部用户 / 内部用户', status: 'enabled' },
  { id: 'partner-key', name: 'Partner API Key', source: 'header.x-api-key', parser: 'api_key.lookup(partner_registry)', principal: '供应链伙伴', status: 'enabled' },
  { id: 'mtls-san', name: 'mTLS Service Identity', source: 'tls.peer_certificate.san', parser: 'certificate.san', principal: '内部服务', status: 'enabled' },
  { id: 'session-bind', name: 'Session 弱关联', source: 'cookie.sid + ip + ua + 5min window', parser: 'behavior_correlation', principal: '外部用户', status: 'observe' },
  { id: 'gateway-consumer', name: 'Gateway Consumer', source: 'x-consumer-id / x-route-id', parser: 'gateway_header', principal: '外部用户 / Partner', status: 'enabled' },
]

const registryRows = [
  { name: 'internal_user_registry', owner: 'IAM / SSO 团队', records: 12842, use: '识别内部员工、运维账号、后台用户' },
  { name: 'partner_registry', owner: '开放平台团队', records: 126, use: '识别合作方、Partner API Key、配额和数据外发责任' },
  { name: 'service_account_registry', owner: '平台工程团队', records: 842, use: '识别内部服务账号、K8s ServiceAccount、mTLS 证书' },
  { name: 'network_zone_registry', owner: '网络安全团队', records: 38, use: '区分公网、办公网、生产内网、Partner 专线、VPN' },
]

function riskTag(risk: string) {
  const color: Record<string, string> = { high: 'orange', medium: 'gold', low: 'blue' }
  const label: Record<string, string> = { high: '高风险', medium: '需关注', low: '正常' }
  return <Tag color={color[risk]}>{label[risk]}</Tag>
}

export default function IdentityCenter() {
  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">身份与调用方</div>
          <div className="page-heading__desc">通过显式身份解析、弱关联和注册表映射，识别外部用户、内部用户、供应链伙伴与内部服务。</div>
        </div>
      </div>

      <div className="metric-grid">
        <Card className="metric-card">
          <div className="metric-card__label"><UserOutlined /> 外部用户</div>
          <div className="metric-card__value">18.4k</div>
          <div className="metric-card__meta">JWT、Cookie、登录事件和设备指纹关联</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><TeamOutlined /> 内部用户</div>
          <div className="metric-card__value">326</div>
          <div className="metric-card__meta">SSO、VPN、办公网和后台操作链路</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><KeyOutlined /> 供应链伙伴</div>
          <div className="metric-card__value">42</div>
          <div className="metric-card__meta">API Key、Partner 专线路由和白名单 IP</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><ApartmentOutlined /> 内部服务</div>
          <div className="metric-card__value">168</div>
          <div className="metric-card__meta">mTLS、K8s ServiceAccount 和服务发现</div>
        </Card>
      </div>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={15}>
          <Card title="主体识别结果">
            <Table
              columns={[
                { title: '主体ID', dataIndex: 'id', key: 'id' },
                { title: '类型', dataIndex: 'label', key: 'label', width: 110, render: (value: string) => <Tag>{value}</Tag> },
                { title: '证据来源', dataIndex: 'source', key: 'source' },
                { title: '置信度', dataIndex: 'confidence', key: 'confidence', width: 130, render: (value: number) => <Progress percent={value} size="small" strokeColor={value >= 90 ? 'var(--fl-success)' : 'var(--fl-medium)'} /> },
                { title: '网络域', dataIndex: 'zone', key: 'zone', width: 120 },
                { title: '风险', dataIndex: 'risk', key: 'risk', width: 100, render: riskTag },
              ]}
              dataSource={principalRows}
              rowKey="id"
              pagination={false}
            />
          </Card>
        </Col>
        <Col xs={24} xl={9}>
          <Card title="解析策略原则">
            <Space direction="vertical" size={12}>
              <div className="insight-row"><div className="insight-row__index">1</div><div><div className="section-title">优先使用显式身份</div><div className="muted">JWT、API Key、mTLS、网关 Consumer 等证据置信度最高。</div></div></div>
              <div className="insight-row"><div className="insight-row__index">2</div><div><div className="section-title">弱关联必须标注置信度</div><div className="muted">IP + UA + Session 只能作为候选主体，不应被当成确定用户。</div></div></div>
              <div className="insight-row"><div className="insight-row__index">3</div><div><div className="section-title">分类依赖注册表</div><div className="muted">内部、外部、Partner 和服务身份必须可配置、可审计、可人工纠偏。</div></div></div>
            </Space>
          </Card>
        </Col>
      </Row>

      <Card title="身份解析器配置">
        <Table
          columns={[
            { title: '解析器', dataIndex: 'name', key: 'name' },
            { title: '来源', dataIndex: 'source', key: 'source', render: (value: string) => <span className="asset-path">{value}</span> },
            { title: '解析方式', dataIndex: 'parser', key: 'parser' },
            { title: '主体类型', dataIndex: 'principal', key: 'principal' },
            { title: '状态', dataIndex: 'status', key: 'status', width: 100, render: (value: string) => <Tag color={value === 'enabled' ? 'success' : 'warning'}>{value === 'enabled' ? '启用' : '观察'}</Tag> },
          ]}
          dataSource={extractorRows}
          rowKey="id"
          pagination={false}
        />
      </Card>

      <Card title="身份注册表">
        <Table
          columns={[
            { title: '注册表', dataIndex: 'name', key: 'name' },
            { title: '责任团队', dataIndex: 'owner', key: 'owner', width: 160 },
            { title: '记录数', dataIndex: 'records', key: 'records', width: 110, align: 'right' as const, render: (value: number) => value.toLocaleString() },
            { title: '用途', dataIndex: 'use', key: 'use' },
          ]}
          dataSource={registryRows}
          rowKey="name"
          pagination={false}
        />
      </Card>

      <Card title="输出字段示例">
        <pre className="code-block">{`{
  "principal_id": "partner-alipay-openapi",
  "principal_type": "partner",
  "identity_confidence": 0.96,
  "network_zone": "partner_link",
  "evidence": ["header.x-api-key", "partner_registry", "source_ip_whitelist"],
  "governance_owner": "开放平台团队"
}`}</pre>
      </Card>
    </div>
  )
}
