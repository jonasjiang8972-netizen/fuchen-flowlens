import { Card, Col, Progress, Row, Space, Table, Tag } from 'antd'
import { CloudServerOutlined, EyeInvisibleOutlined, LinkOutlined, WarningOutlined } from '@ant-design/icons'

interface Props { onNavigate: (page: string, id?: string) => void }

const blindspotRows = [
  { id: 'BLD-001', area: 'shanghai-legacy', type: '集群未接入', impact: 'legacy/export 流量只能从网关侧看到，缺少服务间调用', owner: '平台工程', severity: 'high', fix: '部署 gateway_log Agent 或接入 VPC Flow Log' },
  { id: 'BLD-002', area: 'payment-system', type: '响应体采样不足', impact: '银行卡字段脱敏核验置信度降低', owner: '支付团队', severity: 'high', fix: '扩大 body sampling 或配置字段级采样' },
  { id: 'BLD-003', area: 'recommendation', type: 'Trace 缺失', impact: '入口 API 与内部 gRPC 链路只能弱关联', owner: '推荐团队', severity: 'medium', fix: '接入 traceparent / x-request-id' },
  { id: 'BLD-004', area: 'partner-link', type: 'Partner 注册表缺失', impact: '部分 API Key 无法映射合作方责任主体', owner: '开放平台', severity: 'medium', fix: '同步 partner_registry' },
  { id: 'BLD-005', area: 'admin-system', type: 'Owner 缺失', impact: '管理接口风险无法自动分派', owner: '安全团队', severity: 'medium', fix: '补齐 CMDB owner 和业务分组' },
]

export default function CoverageCenter({ onNavigate }: Props) {
  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">覆盖率与盲区</div>
          <div className="page-heading__desc">明确哪些 API、身份、数据、链路和基础设施还不可见，避免用不完整证据做错误判断。</div>
        </div>
      </div>

      <div className="metric-grid">
        <Card className="metric-card"><div className="metric-card__label"><CloudServerOutlined /> 采集覆盖</div><div className="metric-card__value">76%</div><div className="metric-card__meta">8/10 集群已接入</div></Card>
        <Card className="metric-card"><div className="metric-card__label"><LinkOutlined /> Trace 覆盖</div><div className="metric-card__value">61%</div><div className="metric-card__meta">弱关联链路仍需标注置信度</div></Card>
        <Card className="metric-card"><div className="metric-card__label"><EyeInvisibleOutlined /> 盲区项</div><div className="metric-card__value">{blindspotRows.length}</div><div className="metric-card__meta">高风险盲区 {blindspotRows.filter(r => r.severity === 'high').length} 项</div></Card>
        <Card className="metric-card"><div className="metric-card__label"><WarningOutlined /> 证据缺口</div><div className="metric-card__value">14</div><div className="metric-card__meta">身份、响应体、Partner、Owner、Trace</div></Card>
      </div>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={10}>
          <Card title="覆盖率矩阵">
            <Space direction="vertical" size={16} style={{ width: '100%' }}>
              <div><Row justify="space-between"><span>Kubernetes 集群</span><b>82%</b></Row><Progress percent={82} strokeColor="#117865" /></div>
              <div><Row justify="space-between"><span>网关入口</span><b>94%</b></Row><Progress percent={94} strokeColor="#117865" /></div>
              <div><Row justify="space-between"><span>服务间调用</span><b>63%</b></Row><Progress percent={63} strokeColor="#d96b20" /></div>
              <div><Row justify="space-between"><span>响应体采样</span><b>58%</b></Row><Progress percent={58} strokeColor="#d96b20" /></div>
              <div><Row justify="space-between"><span>Partner 归属</span><b>71%</b></Row><Progress percent={71} strokeColor="#117865" /></div>
            </Space>
          </Card>
        </Col>
        <Col xs={24} xl={14}>
          <Card title="盲区解释">
            <div className="governance-question-grid">
              {[
                ['采集盲区', '节点未部署 Agent、网关日志缺失、VPC Flow Log 未订阅。'],
                ['身份盲区', 'Token 无法解析、API Key 未注册、Session 只能弱关联。'],
                ['数据盲区', '响应体采样关闭、字段无法分类、脱敏状态缺少校验。'],
                ['链路盲区', '缺 trace_id、服务间调用未接入、异步消息链路断开。'],
                ['责任盲区', '资产无 Owner、Partner 无归属、业务线未映射 CMDB。'],
                ['证据盲区', '告警缺少请求样本、基线不足、置信度低于处置阈值。'],
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
            { title: 'ID', dataIndex: 'id', key: 'id', width: 100 },
            { title: '范围', dataIndex: 'area', key: 'area', width: 150 },
            { title: '类型', dataIndex: 'type', key: 'type', width: 140, render: (v: string) => <Tag>{v}</Tag> },
            { title: '影响', dataIndex: 'impact', key: 'impact' },
            { title: 'Owner', dataIndex: 'owner', key: 'owner', width: 120 },
            { title: '等级', dataIndex: 'severity', key: 'severity', width: 90, render: (v: string) => <Tag color={v === 'high' ? 'orange' : 'gold'}>{v}</Tag> },
            { title: '建议修复', dataIndex: 'fix', key: 'fix' },
          ]}
          dataSource={blindspotRows}
          rowKey="id"
          pagination={false}
          onRow={(record) => ({ onClick: () => record.type.includes('集群') ? onNavigate('agents') : undefined, style: { cursor: 'pointer' } })}
        />
      </Card>
    </div>
  )
}
