import { useEffect, useMemo, useState } from 'react'
import { Card, Col, Row, Space, Table, Tag } from 'antd'
import { AuditOutlined, DatabaseOutlined, FileProtectOutlined, SafetyCertificateOutlined } from '@ant-design/icons'
import ReactECharts from 'echarts-for-react'
import { alertService, assetService, ruleService } from '../../services/api'
import { sensitiveLabel, sensitiveType, sensitiveTypes } from '../../utils/sensitive'

const levelColor: Record<string, string> = { critical: 'red', high: 'orange', medium: 'gold' }
const levelLabel: Record<string, string> = { critical: '极高', high: '高', medium: '中' }
const closed = new Set(['resolved', 'false_positive'])

export default function DataGovernance({ onNavigate }: { onNavigate: (page: string, id?: string) => void }) {
  const [assets, setAssets] = useState<any[]>([])
  const [alerts, setAlerts] = useState<any[]>([])
  const [dlpRule, setDlpRule] = useState<any>(null)

  useEffect(() => {
    Promise.all([assetService.list(), alertService.list(), ruleService.detail('R-DLP-001')]).then(([assetRows, alertRows, rule]) => {
      setAssets(assetRows)
      setAlerts(alertRows)
      setDlpRule(rule)
    })
  }, [])

  // Every sensitive field the platform recognised, with its type and API.
  const fields = useMemo(() => assets.flatMap(asset => (asset.sensitive_fields || []).map((field: string) => ({
    key: `${asset.asset_id}-${field}`,
    field,
    type: sensitiveType(field),
    assetId: asset.asset_id,
    api: `${asset.method} ${asset.path_normalized}`,
    host: asset.host || '（未知主机）',
    owner: asset.claim_status === 'claimed' && asset.owner ? asset.owner : '',
  }))), [assets])

  const sensitiveAssets = assets.filter(a => a.sensitive_fields?.length)
  const unowned = sensitiveAssets.filter(a => !(a.claim_status === 'claimed' && a.owner))
  const dlpAlerts = alerts.filter(a => a.source_requirement?.startsWith('FR-DLP'))
  const openDlp = dlpAlerts.filter(a => !closed.has(a.status))

  const paramValue = (key: string) => {
    const p = dlpRule?.params?.find((x: any) => x.key === key)
    return p ? (p.value ?? p.default_value) : undefined
  }
  const typeEnabled = (key: string) => dlpRule?.enabled && paramValue(key) === true
  const countByType = (key: string) => fields.filter(f => f.type === key).length

  // Hosts -> data types they expose.
  const flowOption = useMemo(() => {
    const hosts = [...new Set(fields.map(f => f.host))].slice(0, 15)
    const types = [...new Set(fields.map(f => f.type).filter(Boolean))]
    const links = new Map<string, number>()
    for (const f of fields) {
      if (!f.type || !hosts.includes(f.host)) continue
      const k = `${f.host}|${f.type}`
      links.set(k, (links.get(k) || 0) + 1)
    }
    return {
      tooltip: {},
      series: [{
        type: 'graph',
        layout: 'force',
        roam: true,
        label: { show: true, color: '#142033', fontSize: 12 },
        force: { repulsion: 320, edgeLength: 140 },
        categories: [{ name: '主机', itemStyle: { color: '#ccfbf1' } }, { name: '敏感数据', itemStyle: { color: '#fee2e2' } }],
        data: [
          ...hosts.map(h => ({ id: `h:${h}`, name: h, category: 0, symbolSize: 46 })),
          ...types.map(t => ({ id: `t:${t}`, name: sensitiveLabel(t), category: 1, symbolSize: 30 + 4 * Math.min(10, countByType(t)) })),
        ],
        links: [...links.entries()].map(([k, n]) => {
          const [h, t] = k.split('|')
          return { source: `h:${h}`, target: `t:${t}`, value: n, label: { show: true, formatter: `${n} 个字段` } }
        }),
        edgeLabel: { show: true, color: '#64748b', fontSize: 11 },
      }],
    }
  }, [fields]) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">数据分类分级</div>
          <div className="page-heading__desc">平台从流量中识别出的敏感字段、它们所在的接口和责任人，以及敏感数据检测规则的当前设置。</div>
        </div>
      </div>

      <div className="metric-grid">
        <Card className="metric-card">
          <div className="metric-card__label"><DatabaseOutlined /> 敏感字段</div>
          <div className="metric-card__value">{fields.length}</div>
          <div className="metric-card__meta">来自 {sensitiveAssets.length} 个 API 资产</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><FileProtectOutlined /> 敏感数据告警</div>
          <div className="metric-card__value" style={{ color: openDlp.length ? 'var(--fl-high)' : undefined }}>{openDlp.length}</div>
          <div className="metric-card__meta">未关闭；累计 {dlpAlerts.length} 个</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><AuditOutlined /> 无责任人的敏感接口</div>
          <div className="metric-card__value">{unowned.length}</div>
          <div className="metric-card__meta">在 API 资产中认领后可分派治理</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><SafetyCertificateOutlined /> 检测规则</div>
          <div className="metric-card__value" style={{ fontSize: 22 }}>{dlpRule ? (dlpRule.enabled ? '已启用' : '已停用') : '-'}</div>
          <div className="metric-card__meta">识别 {sensitiveTypes.filter(t => typeEnabled(t.key)).length}/{sensitiveTypes.length} 类数据（R-DLP-001）</div>
        </Card>
      </div>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={15}>
          <Card title="敏感数据分布（主机 → 数据类型）">
            {fields.length ? <ReactECharts option={flowOption} style={{ height: 360 }} />
              : <div style={{ height: 360, display: 'flex', alignItems: 'center', justifyContent: 'center' }} className="muted">尚未识别到敏感字段</div>}
          </Card>
        </Col>
        <Col xs={24} xl={9}>
          <Card title="识别方式">
            <Space direction="vertical" size={12}>
              <div className="insight-row"><div className="insight-row__index">1</div><div><div className="section-title">采集端先脱敏</div><div className="muted">身份证号、手机号、银行卡号由采集器按正则和校验位掩码，凭证替换为指纹，明文不离开主机。</div></div></div>
              <div className="insight-row"><div className="insight-row__index">2</div><div><div className="section-title">平台按字段名识别</div><div className="muted">识别 URL 参数和 JSON 响应体中的字段名，例如 id_card、phone、card_number、token。</div></div></div>
              <div className="insight-row"><div className="insight-row__index">3</div><div><div className="section-title">规则决定是否告警</div><div className="muted">导出类接口返回敏感字段，或单次返回的敏感字段数达到阈值时告警。可在检测策略中调整。</div></div></div>
            </Space>
          </Card>
        </Col>
      </Row>

      <Card title="分类标准" extra={<a onClick={() => onNavigate('rules')}>调整检测规则</a>}>
        <Table
          columns={[
            { title: '数据类型', dataIndex: 'label', key: 'label', width: 120 },
            { title: '识别的字段名（包含即匹配）', dataIndex: 'markers', key: 'markers', render: (v: string[]) => <span className="mono">{v.join(', ')}</span> },
            { title: '等级', dataIndex: 'level', key: 'level', width: 80, render: (v: string) => <Tag color={levelColor[v]}>{levelLabel[v]}</Tag> },
            { title: '已识别字段', key: 'count', width: 110, align: 'right' as const, render: (_: any, r: any) => countByType(r.key) },
            { title: '参与告警', key: 'enabled', width: 100, render: (_: any, r: any) => (dlpRule ? <Tag color={typeEnabled(r.key) ? 'success' : 'default'}>{typeEnabled(r.key) ? '是' : '否'}</Tag> : '-') },
          ]}
          dataSource={sensitiveTypes}
          rowKey="key"
          pagination={false}
        />
      </Card>

      <Card title="敏感字段清单">
        <Table
          columns={[
            { title: '字段', dataIndex: 'field', key: 'field', render: (v: string) => <Tag color="red">{v}</Tag> },
            { title: '类型', dataIndex: 'type', key: 'type', width: 110, render: (v: string) => sensitiveLabel(v) || '-' },
            { title: '接口', dataIndex: 'api', key: 'api', render: (v: string) => <span className="asset-path">{v}</span> },
            { title: '主机', dataIndex: 'host', key: 'host', width: 180 },
            { title: '责任人', dataIndex: 'owner', key: 'owner', width: 180, render: (v: string) => v || <Tag color="warning">待认领</Tag> },
          ]}
          dataSource={fields}
          rowKey="key"
          size="middle"
          pagination={fields.length > 15 ? { pageSize: 15 } : false}
          locale={{ emptyText: '尚未识别到敏感字段' }}
          onRow={(record: any) => ({ onClick: () => onNavigate('asset-detail', record.assetId), style: { cursor: 'pointer' } })}
        />
      </Card>
    </div>
  )
}
