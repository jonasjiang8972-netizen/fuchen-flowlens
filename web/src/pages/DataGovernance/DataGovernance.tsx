import { useEffect, useMemo, useState } from 'react'
import { Card, Col, Progress, Row, Space, Table, Tag } from 'antd'
import { AuditOutlined, DatabaseOutlined, FileProtectOutlined, SafetyCertificateOutlined } from '@ant-design/icons'
import ReactECharts from 'echarts-for-react'
import { alertService, assetService } from '../../services/api'

const standardRows = [
  { id: 'personal', category: '个人身份信息', examples: '姓名、身份证、手机号、邮箱、地址', basis: '个人信息保护法 / 企业数据分类分级', level: 'high', owner: '数据治理团队' },
  { id: 'finance', category: '金融与交易信息', examples: '银行卡、交易金额、支付凭证、订单金额', basis: '金融行业数据安全分级 / 内部合规', level: 'high', owner: '支付合规团队' },
  { id: 'credential', category: '认证凭据', examples: 'Token、Password、Secret、API Key、Session', basis: '安全基线 / 等保 2.0', level: 'critical', owner: '安全团队' },
  { id: 'business', category: '企业业务敏感', examples: '客户名单、合同、供应链信息、内部账号', basis: '企业内部数据安全制度', level: 'medium', owner: '业务数据 Owner' },
]

const classifierRows = [
  { id: 'field-name', name: '字段语义匹配', method: '字段名/路径关键词', signal: 'phone, id_card_no, recipient_phone, api_key', status: 'enabled' },
  { id: 'regex', name: '正则与校验位', method: '身份证/手机号/银行卡/Luhn', signal: '18位身份证、11位手机号、银行卡号', status: 'enabled' },
  { id: 'schema', name: 'Schema 指纹', method: '请求/响应结构漂移', signal: '字段新增、字段类型变化、响应超范围', status: 'enabled' },
  { id: 'nlp', name: 'NLP/NER 识别', method: '姓名、地址、组织实体', signal: '非标准字段名中的自然语言内容', status: 'observe' },
  { id: 'custom-dict', name: '企业字典', method: '业务字段字典', signal: '客户号、会员号、保单号、供应商编号', status: 'enabled' },
]

const confirmationRows = [
  { id: 'id_card_no', field: 'id_card_no', type: '身份证号', asset: '/api/v1/user/{id}', status: 'confirmed', owner: '数据治理团队', action: '要求脱敏' },
  { id: 'recipient_phone', field: 'recipient_phone', type: '手机号', asset: '/api/v1/order/{id}', status: 'confirmed', owner: '订单业务 Owner', action: '允许返回后四位' },
  { id: 'card_number', field: 'card_number', type: '银行卡', asset: '/api/v1/payment/checkout', status: 'pending', owner: '支付合规团队', action: '待确认' },
  { id: 'role', field: 'role', type: '内部权限信息', asset: '/api/v1/admin/users', status: 'pending', owner: '安全团队', action: '核查最小化返回' },
]

export default function DataGovernance({ onNavigate }: { onNavigate: (page: string, id?: string) => void }) {
  const [assets, setAssets] = useState<any[]>([])
  const [alerts, setAlerts] = useState<any[]>([])

  useEffect(() => {
    Promise.all([assetService.list(), alertService.list()]).then(([assetRows, alertRows]) => {
      setAssets(assetRows)
      setAlerts(alertRows)
    })
  }, [])

  const sensitiveAssets = assets.filter(asset => asset.sensitive_fields?.length)
  const sensitiveFields = useMemo(() => {
    return sensitiveAssets.flatMap(asset => (asset.sensitive_fields || []).map((field: string) => ({
      field,
      asset: asset.path_normalized,
      owner: asset.owner || '待认领',
      sensitivity: asset.sensitivity_hint,
    })))
  }, [sensitiveAssets])
  const dlpAlerts = alerts.filter(alert => alert.source_requirement?.startsWith('FR-DLP') || alert.source_requirement === 'FR-DLP-003')

  const flowOption = {
    tooltip: {},
    series: [{
      type: 'graph',
      layout: 'force',
      roam: false,
      symbolSize: 58,
      label: { show: true, color: '#142033', fontSize: 12 },
      force: { repulsion: 380, edgeLength: 150 },
      categories: [
        { name: '服务', itemStyle: { color: '#ccfbf1' } },
        { name: '敏感字段', itemStyle: { color: '#fee2e2' } },
        { name: '外发/Partner', itemStyle: { color: '#ffedd5' } },
      ],
      data: [
        { id: 'user-svc', name: '用户服务', category: 0 },
        { id: 'order-svc', name: '订单服务', category: 0 },
        { id: 'payment-svc', name: '支付服务', category: 0 },
        { id: 'partner', name: 'Partner API', category: 2 },
        { id: 'phone', name: '手机号', category: 1 },
        { id: 'id-card', name: '身份证', category: 1 },
        { id: 'bank', name: '银行卡', category: 1 },
      ],
      links: [
        { source: 'user-svc', target: 'phone' },
        { source: 'user-svc', target: 'id-card' },
        { source: 'order-svc', target: 'phone' },
        { source: 'payment-svc', target: 'bank' },
        { source: 'order-svc', target: 'partner' },
      ],
    }],
  }

  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">数据分类分级</div>
          <div className="page-heading__desc">定义敏感数据标准、识别算法、字段确认和脱敏治理闭环，回答“什么是敏感数据、谁定义、谁确认”。</div>
        </div>
      </div>

      <div className="metric-grid">
        <Card className="metric-card">
          <div className="metric-card__label"><DatabaseOutlined /> 敏感字段</div>
          <div className="metric-card__value">{sensitiveFields.length}</div>
          <div className="metric-card__meta">来自 {sensitiveAssets.length} 个 API 资产</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><FileProtectOutlined /> 脱敏缺陷</div>
          <div className="metric-card__value">{dlpAlerts.length || 3}</div>
          <div className="metric-card__meta">未脱敏、部分脱敏、超范围返回</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><AuditOutlined /> 人工确认</div>
          <div className="metric-card__value">{confirmationRows.filter(row => row.status === 'confirmed').length}/{confirmationRows.length}</div>
          <div className="metric-card__meta">高价值字段必须由数据 Owner 确认</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><SafetyCertificateOutlined /> 策略覆盖率</div>
          <div className="metric-card__value">82%</div>
          <div className="metric-card__meta">内置标准 + 企业字典 + 算法识别</div>
        </Card>
      </div>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={15}>
          <Card title="敏感数据流向">
            <ReactECharts option={flowOption} style={{ height: 360 }} />
          </Card>
        </Col>
        <Col xs={24} xl={9}>
          <Card title="治理原则">
            <Space direction="vertical" size={12}>
              <div className="insight-row"><div className="insight-row__index">1</div><div><div className="section-title">标准来自法规和企业制度</div><div className="muted">平台内置基础标准，企业可按数据分类分级制度扩展。</div></div></div>
              <div className="insight-row"><div className="insight-row__index">2</div><div><div className="section-title">算法只做初筛</div><div className="muted">字段名、正则、校验位、Schema 和 NLP 识别需要人工确认闭环。</div></div></div>
              <div className="insight-row"><div className="insight-row__index">3</div><div><div className="section-title">Owner 决定治理动作</div><div className="muted">安全团队、数据治理团队、业务 Owner 与合规团队共同维护口径。</div></div></div>
            </Space>
          </Card>
        </Col>
      </Row>

      <Card title="分类分级标准">
        <Table
          columns={[
            { title: '分类', dataIndex: 'category', key: 'category' },
            { title: '示例字段', dataIndex: 'examples', key: 'examples' },
            { title: '依据', dataIndex: 'basis', key: 'basis' },
            { title: '等级', dataIndex: 'level', key: 'level', width: 100, render: (value: string) => <Tag color={value === 'critical' ? 'red' : value === 'high' ? 'orange' : 'gold'}>{value}</Tag> },
            { title: '维护方', dataIndex: 'owner', key: 'owner', width: 150 },
          ]}
          dataSource={standardRows}
          rowKey="id"
          pagination={false}
        />
      </Card>

      <Card title="识别算法与规则">
        <Table
          columns={[
            { title: '识别器', dataIndex: 'name', key: 'name' },
            { title: '方法', dataIndex: 'method', key: 'method' },
            { title: '信号', dataIndex: 'signal', key: 'signal' },
            { title: '状态', dataIndex: 'status', key: 'status', width: 100, render: (value: string) => <Tag color={value === 'enabled' ? 'success' : 'warning'}>{value === 'enabled' ? '启用' : '观察'}</Tag> },
          ]}
          dataSource={classifierRows}
          rowKey="id"
          pagination={false}
        />
      </Card>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={14}>
          <Card title="字段确认闭环">
            <Table
              columns={[
                { title: '字段', dataIndex: 'field', key: 'field', render: (value: string) => <Tag color="red">{value}</Tag> },
                { title: '类型', dataIndex: 'type', key: 'type' },
                { title: '接口', dataIndex: 'asset', key: 'asset', render: (value: string) => <span className="asset-path">{value}</span> },
                { title: '状态', dataIndex: 'status', key: 'status', width: 100, render: (value: string) => <Tag color={value === 'confirmed' ? 'success' : 'warning'}>{value === 'confirmed' ? '已确认' : '待确认'}</Tag> },
                { title: '动作', dataIndex: 'action', key: 'action' },
              ]}
              dataSource={confirmationRows}
              rowKey="id"
              pagination={false}
              size="middle"
            />
          </Card>
        </Col>
        <Col xs={24} xl={10}>
          <Card title="敏感字段样本">
            <Table
              columns={[
                { title: '字段', dataIndex: 'field', key: 'field' },
                { title: 'API', dataIndex: 'asset', key: 'asset', render: (value: string) => <span className="asset-path">{value}</span> },
                { title: 'Owner', dataIndex: 'owner', key: 'owner' },
                { title: '敏感度', dataIndex: 'sensitivity', key: 'sensitivity', render: (value: string) => <Tag color={value === 'high' ? 'red' : 'gold'}>{value}</Tag> },
              ]}
              dataSource={sensitiveFields.slice(0, 8)}
              rowKey={(row: any) => `${row.asset}-${row.field}`}
              pagination={false}
              size="small"
              onRow={(record) => ({ onClick: () => onNavigate('assets'), style: { cursor: 'pointer' } })}
            />
          </Card>
        </Col>
      </Row>

      <Card title="策略输出示例">
        <pre className="code-block">{`{
  "field": "recipient_phone",
  "data_type": "手机号",
  "classification": "个人身份信息",
  "sensitivity_level": "high",
  "detection_method": ["field_name", "regex", "schema_fingerprint"],
  "confirmed_by": "订单业务 Owner",
  "required_action": "mask_last_4_digits"
}`}</pre>
      </Card>
    </div>
  )
}
