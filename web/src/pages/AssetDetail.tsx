import { useEffect, useMemo, useState } from 'react'
import { Button, Card, Col, Descriptions, Progress, Row, Space, Table, Tag, Timeline } from 'antd'
import { ArrowLeftOutlined, ApiOutlined, DatabaseOutlined, DeploymentUnitOutlined, GlobalOutlined } from '@ant-design/icons'
import ReactECharts from 'echarts-for-react'
import { assetService } from '../services/api'
import { sensitiveLabel, sensitiveType } from '../utils/sensitive'

const changeLabel: Record<string, string> = {
  discovered: '首次发现',
  sensitive_field_added: '新出现敏感字段',
  owner_changed: '责任人变更',
}

interface Props {
  assetId: string
  onBack: () => void
  onNavigate: (page: string, id?: string) => void
}

function exposureType(asset: any) {
  const dist = asset?.source_distribution || {}
  if (String(dist.external || '').includes('90') || asset?.host?.includes('api.example.com')) return '公网入口'
  if (asset?.host?.includes('internal')) return '内网接口'
  return '混合访问'
}

export default function AssetDetail({ assetId, onBack, onNavigate }: Props) {
  const [asset, setAsset] = useState<any>(null)
  const [detail, setDetail] = useState<any>(null)

  useEffect(() => {
    Promise.all([
      assetService.list(),
      assetService.detail(assetId),
    ]).then(([assets, detail]) => {
      const found = assets.find((a: any) => a.asset_id === assetId)
      if (found) setAsset(found)
      setDetail(detail)
    })
  }, [assetId])

  const statusDist = useMemo(() => {
    const dist = asset?.request_stats?.status_code_distribution || {}
    return Object.entries(dist).map(([name, value]) => ({ name, value }))
  }, [asset])

  if (!asset) return <div className="commercial-page">加载中...</div>

  const chartText = '#64748b'
  const hourlyOption = {
    color: ['#117865'],
    tooltip: { trigger: 'axis' },
    grid: { top: 18, right: 18, bottom: 30, left: 46 },
    xAxis: {
      type: 'category',
      data: Array.from({ length: 24 }, (_, i) => `${i}:00`),
      axisLabel: { color: chartText, fontSize: 10 },
      axisLine: { lineStyle: { color: '#d9e2ec' } },
    },
    yAxis: {
      type: 'value',
      axisLabel: { color: chartText },
      splitLine: { lineStyle: { color: '#edf1f6' } },
    },
    series: [{ name: '调用量', type: 'bar', data: asset.request_stats?.hourly_calls || [], barWidth: 12 }],
  }

  const statusOption = {
    tooltip: { trigger: 'item' },
    series: [{
      type: 'pie',
      radius: ['54%', '72%'],
      data: statusDist.map((item: any) => ({
        ...item,
        itemStyle: { color: String(item.name).startsWith('2') ? '#117865' : String(item.name).startsWith('4') ? '#d96b20' : '#c9352b' },
      })),
      label: { color: chartText },
    }],
  }

  const callerColumns = [
    { title: '调用方', dataIndex: 'ip', key: 'ip' },
    { title: '调用量', dataIndex: 'calls', key: 'calls', align: 'right' as const, render: (value: number) => value?.toLocaleString() },
    { title: '错误率', dataIndex: 'error_rate', key: 'error_rate', align: 'right' as const, render: (value: number) => <span style={{ color: value > 5 ? 'var(--fl-critical)' : 'var(--fl-success)' }}>{value}%</span> },
  ]

  const alertsColumns = [
    { title: '告警ID', dataIndex: 'alert_id', key: 'id', width: 110, render: (id: string) => <Button type="link" onClick={() => onNavigate('alert-detail', id)}>{id}</Button> },
    { title: '标题', dataIndex: 'title', key: 'title' },
    { title: '等级', dataIndex: 'severity', key: 'severity', width: 86, render: (value: string) => <Tag color={value === 'high' ? 'orange' : value === 'critical' ? 'red' : 'gold'}>{value}</Tag> },
    { title: '状态', dataIndex: 'status', key: 'status', width: 90, render: (value: string) => <Tag>{value}</Tag> },
  ]

  const openAlerts = (detail?.alerts || []).filter((a: any) => a.status !== 'resolved' && a.status !== 'false_positive')
  const owned = asset.claim_status === 'claimed' && !!asset.owner
  const governanceChecks = [
    { label: '已认领责任人', ok: owned },
    { label: '敏感字段有人负责（无敏感字段也算通过）', ok: !asset.sensitive_fields?.length || owned },
    { label: '没有未关闭的告警', ok: openAlerts.length === 0 },
    { label: '24 小时内有流量', ok: !!asset.last_seen && Date.now() - new Date(asset.last_seen).getTime() < 86400000 },
  ]

  const flowNodes = [
    { title: '外部调用方', desc: asset.source_distribution?.external || '外部入口' },
    { title: 'API Gateway', desc: asset.host },
    { title: asset.path_normalized, desc: `${asset.method} · ${asset.protocol_type}` },
    { title: asset.group_path || '业务服务', desc: asset.owner || 'Owner 未认领' },
    { title: '数据字段', desc: asset.sensitive_fields?.length ? `${asset.sensitive_fields.length} 个敏感字段` : '未发现敏感字段' },
  ]

  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <Button type="link" icon={<ArrowLeftOutlined />} onClick={onBack} style={{ paddingLeft: 0 }}>返回资产中心</Button>
          <div className="page-heading__title"><span className="asset-path">{asset.method} {asset.path_normalized}</span></div>
          <div className="page-heading__desc">API 安全档案：生产暴露面、调用画像、数据风险、关联事件和责任归属。</div>
        </div>
        <Space>
          <Button type="primary" icon={<DeploymentUnitOutlined />} onClick={() => onNavigate('flow-map')}>查看链路</Button>
        </Space>
      </div>

      <div className="metric-grid">
        <Card className="metric-card">
          <div className="metric-card__label"><ApiOutlined /> 24h 调用量</div>
          <div className="metric-card__value">{asset.request_stats?.total_calls_24h?.toLocaleString() || asset.daily_avg_calls?.toLocaleString()}</div>
          <div className="metric-card__meta">日均 {asset.daily_avg_calls?.toLocaleString()} 次</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><GlobalOutlined /> 暴露面</div>
          <div className="metric-card__value" style={{ fontSize: 22 }}>{exposureType(asset)}</div>
          <div className="metric-card__meta">来源分布 {Object.values(asset.source_distribution || {}).join(' / ') || '待补充'}</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><DatabaseOutlined /> 数据风险</div>
          <div className="metric-card__value">{asset.sensitive_fields?.length || 0}</div>
          <div className="metric-card__meta">{asset.sensitivity_hint === 'high' ? '高敏接口，需 owner 确认' : '敏感度中低'}</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label">一致性</div>
          <div className="metric-card__value" style={{ fontSize: 22 }}>{asset.status === 'shadow' ? '文档缺失' : asset.status === 'zombie' ? '疑似废弃' : '已纳管'}</div>
          <div className="metric-card__meta">归一化置信度 {Math.round((asset.normalization_confidence || 0) * 100)}%</div>
        </Card>
      </div>

      <div className="two-column-grid">
        <Card title="资产身份与责任">
          <Descriptions column={1} size="small">
            <Descriptions.Item label="资产ID">{asset.asset_id}</Descriptions.Item>
            <Descriptions.Item label="主机 / 路由">{asset.host}</Descriptions.Item>
            <Descriptions.Item label="协议类型">{asset.protocol_type}</Descriptions.Item>
            <Descriptions.Item label="业务分组">{asset.group_path || '未分组'}</Descriptions.Item>
            <Descriptions.Item label="责任人">{asset.owner || <Tag color="warning">待认领</Tag>}</Descriptions.Item>
            <Descriptions.Item label="首次发现">{new Date(asset.first_seen).toLocaleString('zh-CN')}</Descriptions.Item>
            <Descriptions.Item label="最近访问">{new Date(asset.last_seen).toLocaleString('zh-CN')}</Descriptions.Item>
          </Descriptions>
        </Card>

        <Card title="内外网调用链摘要">
          <Timeline
            items={flowNodes.map((node, index) => ({
              color: index === 4 && asset.sensitive_fields?.length ? 'red' : '#117865',
              children: (
                <div>
                  <div className="section-title">{node.title}</div>
                  <div className="muted">{node.desc}</div>
                </div>
              ),
            }))}
          />
        </Card>
      </div>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={16}>
          <Card title="24 小时调用趋势">
            <ReactECharts option={hourlyOption} style={{ height: 260 }} />
          </Card>
        </Col>
        <Col xs={24} xl={8}>
          <Card title="状态码分布">
            <ReactECharts option={statusOption} style={{ height: 260 }} />
          </Card>
        </Col>
      </Row>

      <div className="two-column-grid">
        <Card title="数据字段与脱敏状态">
          <Space wrap>
            {(asset.sensitive_fields || []).map((field: string) => (
              <Tag key={field} color="red">{field}{sensitiveType(field) ? ` · ${sensitiveLabel(sensitiveType(field))}` : ''}</Tag>
            ))}
            {!asset.sensitive_fields?.length && <span className="muted">未发现敏感字段</span>}
          </Space>
          <div style={{ marginTop: 16 }}>
            <div className="section-title">治理完整度</div>
            <Progress percent={Math.round((governanceChecks.filter(c => c.ok).length / governanceChecks.length) * 100)} strokeColor="#117865" />
            <Space direction="vertical" size={2} style={{ marginTop: 8 }}>
              {governanceChecks.map(c => <span key={c.label} className="muted">{c.ok ? '✓' : '✗'} {c.label}</span>)}
            </Space>
          </div>
        </Card>

        <Card title="Top 调用方">
          <Table columns={callerColumns} dataSource={asset.request_stats?.top_callers || []} rowKey="ip" pagination={false} size="small" />
        </Card>
      </div>

      <Row gutter={[16, 16]}>
        <Col span={24}>
          <Card title={`关联告警 (${detail?.alerts?.length || 0})`}>
            {detail?.alerts?.length ? (
              <Table columns={alertsColumns} dataSource={detail.alerts} rowKey="alert_id" pagination={false} size="middle" />
            ) : <span className="muted">暂无关联告警</span>}
          </Card>
        </Col>
      </Row>

      <div className="two-column-grid">
        <Card title="变更记录">
          {detail?.change_history?.length ? (
            <Timeline items={detail.change_history.map((c: any) => ({
              color: c.severity === 'high' ? 'red' : '#117865',
              children: <div><div className="section-title">{changeLabel[c.change_type] || c.change_type}</div><div className="muted">{c.after}</div><div className="muted">{new Date(c.detected_at).toLocaleString('zh-CN')}</div></div>,
            }))} />
          ) : <span className="muted">暂无变更记录</span>}
        </Card>
        <Card title="同一服务下的其他接口">
          {detail?.related_assets?.length ? (
            <Space wrap>
              {detail.related_assets.map((id: string) => <Tag key={id} style={{ cursor: 'pointer' }} onClick={() => onNavigate('asset-detail', id)}>{id}</Tag>)}
            </Space>
          ) : <span className="muted">无</span>}
        </Card>
      </div>
    </div>
  )
}
