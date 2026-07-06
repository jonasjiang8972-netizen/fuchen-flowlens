import { useEffect, useState } from 'react'
import { Card, Descriptions, Tag, Table, Typography, Row, Col, Timeline, Button, Space, Statistic } from 'antd'
import { ArrowLeftOutlined, WarningOutlined, ApiOutlined } from '@ant-design/icons'
import ReactECharts from 'echarts-for-react'
import { assetService } from '../services/api'

const { Title, Paragraph } = Typography

interface Props {
  assetId: string
  onBack: () => void
  onNavigate: (page: string, id?: string) => void
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

  if (!asset) return <div style={{ color: '#F0F4F8' }}>加载中...</div>

  const hourlyOption = {
    backgroundColor: 'transparent',
    tooltip: { trigger: 'axis' },
    xAxis: {
      type: 'category',
      data: Array.from({ length: 24 }, (_, i) => `${i}:00`),
      axisLine: { lineStyle: { color: '#1E3A5F' } },
      axisLabel: { color: '#94A3B8', fontSize: 10 },
    },
    yAxis: {
      type: 'value',
      axisLine: { lineStyle: { color: '#1E3A5F' } },
      axisLabel: { color: '#94A3B8' },
      splitLine: { lineStyle: { color: '#1E3A5F' } },
    },
    series: [{
      name: '调用量', type: 'bar',
      data: asset.request_stats?.hourly_calls || [],
      itemStyle: { color: '#0D9373' },
    }],
    grid: { top: 20, right: 20, bottom: 30, left: 50 },
  }

  const alertsColumns = [
    { title: '告警ID', dataIndex: 'alert_id', key: 'id', width: 100,
      render: (id: string) => <a style={{ color: '#36CFC9' }} onClick={() => onNavigate('alert-detail', id)}>{id}</a> },
    { title: '标题', dataIndex: 'title', key: 'title' },
    {
      title: '等级', dataIndex: 'severity', key: 'severity', width: 80,
      render: (s: string) => {
        const colors: Record<string, string> = { critical: 'red', high: 'orange', medium: 'gold', low: 'blue' }
        return <Tag color={colors[s]}>{s}</Tag>
      },
    },
    {
      title: '状态', dataIndex: 'status', key: 'status', width: 100,
      render: (s: string) => {
        const map: Record<string, string> = { open: '待处理', acknowledged: '已确认', resolved: '已解决' }
        return <Tag>{map[s] || s}</Tag>
      },
    },
  ]

  const changesColumns = [
    { title: '变更类型', dataIndex: 'change_type', key: 'type', width: 150 },
    { title: '变更前', dataIndex: 'before', key: 'before' },
    { title: '变更后', dataIndex: 'after', key: 'after' },
    {
      title: '风险', dataIndex: 'severity', key: 'severity', width: 80,
      render: (s: string) => {
        const colors: Record<string, string> = { high: 'red', medium: 'orange', low: 'green' }
        return <Tag color={colors[s]}>{s}</Tag>
      },
    },
    { title: '检测时间', dataIndex: 'detected_at', key: 'time', width: 160,
      render: (t: string) => new Date(t).toLocaleString('zh-CN') },
  ]

  return (
    <div>
      <div style={{ marginBottom: 16 }}>
        <Button type="link" icon={<ArrowLeftOutlined />} onClick={onBack} style={{ color: '#36CFC9', padding: 0 }}>
          返回资产列表
        </Button>
      </div>

      <Row gutter={[16, 16]}>
        <Col span={24}>
          <Card className="dashboard-card" title={<span style={{ color: '#F0F4F8' }}>资产基本信息</span>}>
            <Descriptions bordered column={3} size="small" labelStyle={{ color: '#94A3B8', background: '#132F4C' }} contentStyle={{ color: '#F0F4F8' }}>
              <Descriptions.Item label="资产ID">{asset.asset_id}</Descriptions.Item>
              <Descriptions.Item label="路径">{asset.path_normalized}</Descriptions.Item>
              <Descriptions.Item label="方法"><Tag color="blue">{asset.method}</Tag></Descriptions.Item>
              <Descriptions.Item label="协议">{asset.protocol_type}</Descriptions.Item>
              <Descriptions.Item label="主机">{asset.host}</Descriptions.Item>
              <Descriptions.Item label="状态">
                <Tag color={asset.status === 'active' ? 'green' : asset.status === 'shadow' ? 'orange' : 'red'}>
                  {asset.status === 'active' ? '正常' : asset.status === 'shadow' ? '影子API' : '僵尸API'}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="敏感度">
                <Tag color={asset.sensitivity_hint === 'high' ? 'red' : asset.sensitivity_hint === 'medium' ? 'orange' : 'green'}>
                  {asset.sensitivity_hint}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="责任人">{asset.owner || '未认领'}</Descriptions.Item>
              <Descriptions.Item label="分组">{asset.group_path}</Descriptions.Item>
              <Descriptions.Item label="首次发现">{new Date(asset.first_seen).toLocaleString('zh-CN')}</Descriptions.Item>
              <Descriptions.Item label="最近访问">{new Date(asset.last_seen).toLocaleString('zh-CN')}</Descriptions.Item>
              <Descriptions.Item label="归一化置信度">{(asset.normalization_confidence * 100).toFixed(0)}%</Descriptions.Item>
            </Descriptions>
            {asset.sensitive_fields?.length > 0 && (
              <div style={{ marginTop: 12 }}>
                <span style={{ color: '#94A3B8', marginRight: 8 }}>敏感字段:</span>
                {asset.sensitive_fields.map((f: string) => <Tag key={f} color="red" style={{ marginRight: 4 }}>{f}</Tag>)}
              </div>
            )}
          </Card>
        </Col>
      </Row>

      {asset.request_stats && (
        <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
          <Col span={6}>
            <Card className="dashboard-card">
              <Statistic title={<span style={{ color: '#94A3B8' }}>24h 调用量</span>} value={asset.request_stats.total_calls_24h} valueStyle={{ color: '#F0F4F8', fontSize: '24px', fontWeight: 700 }} />
            </Card>
          </Col>
          <Col span={6}>
            <Card className="dashboard-card">
              <Statistic title={<span style={{ color: '#94A3B8' }}>24h 独立调用者</span>} value={asset.request_stats.unique_callers_24h} valueStyle={{ color: '#36CFC9', fontSize: '24px', fontWeight: 700 }} />
            </Card>
          </Col>
          <Col span={6}>
            <Card className="dashboard-card">
              <Statistic title={<span style={{ color: '#94A3B8' }}>24h 错误率</span>} value={asset.request_stats.error_rate_24h} suffix="%" valueStyle={{ color: asset.request_stats.error_rate_24h > 1 ? '#F5222D' : '#52C41A', fontSize: '24px', fontWeight: 700 }} />
            </Card>
          </Col>
          <Col span={6}>
            <Card className="dashboard-card">
              <Statistic title={<span style={{ color: '#94A3B8' }}>P95 延迟</span>} value={asset.request_stats.p95_latency_ms} suffix="ms" valueStyle={{ color: '#F0F4F8', fontSize: '24px', fontWeight: 700 }} />
            </Card>
          </Col>
        </Row>
      )}

      {asset.request_stats?.hourly_calls && (
        <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
          <Col span={24}>
            <Card className="dashboard-card" title={<span style={{ color: '#F0F4F8' }}>24小时调用趋势</span>}>
              <ReactECharts option={hourlyOption} style={{ height: '250px' }} />
            </Card>
          </Col>
        </Row>
      )}

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col span={12}>
          <Card className="dashboard-card" title={<span style={{ color: '#F0F4F8' }}>关联告警 ({detail?.alerts?.length || 0})</span>}>
            {detail?.alerts?.length > 0 ? (
              <Table columns={alertsColumns} dataSource={detail.alerts} rowKey="alert_id" pagination={false} size="small" />
            ) : <div style={{ color: '#94A3B8' }}>暂无关联告警</div>}
          </Card>
        </Col>
        <Col span={12}>
          <Card className="dashboard-card" title={<span style={{ color: '#F0F4F8' }}>变更历史 ({detail?.change_history?.length || 0})</span>}>
            {detail?.change_history?.length > 0 ? (
              <Table columns={changesColumns} dataSource={detail.change_history} rowKey="change_type" pagination={false} size="small" />
            ) : <div style={{ color: '#94A3B8' }}>暂无变更记录</div>}
          </Card>
        </Col>
      </Row>
    </div>
  )
}
