import { useEffect, useMemo, useState } from 'react'
import { Button, Card, Input, Select, Space, Table, Tag } from 'antd'
import { ApiOutlined, DatabaseOutlined, ExportOutlined, SearchOutlined, UserAddOutlined } from '@ant-design/icons'
import { assetService, claimAsset } from '../services/api'

interface Props {
  onNavigate: (page: string, id?: string) => void
}

const sensitivityLabel: Record<string, string> = {
  high: '高敏',
  medium: '中敏',
  low: '低敏',
}

const statusLabel: Record<string, string> = {
  active: '活跃',
  shadow: '影子',
  zombie: '僵尸',
  archived: '归档',
}

const claimLabel: Record<string, string> = {
  unclaimed: '待认领',
  claimed: '已认领',
  escalated: '已升级',
}

export default function Assets({ onNavigate }: Props) {
  const [assets, setAssets] = useState<any[]>([])
  const [keyword, setKeyword] = useState('')
  const [status, setStatus] = useState<string>('all')
  const [sensitivity, setSensitivity] = useState<string>('all')
  const [claimStatus, setClaimStatus] = useState<string>('all')

  useEffect(() => {
    assetService.list().then(setAssets)
  }, [])

  const handleClaim = (assetId: string) => {
    claimAsset(assetId, 'current.user@company.com')
    setAssets(prev => prev.map(a =>
      a.asset_id === assetId ? { ...a, claim_status: 'claimed', owner: 'current.user@company.com' } : a
    ))
  }

  const filteredAssets = useMemo(() => {
    const kw = keyword.trim().toLowerCase()
    return assets.filter(asset => {
      const matchKeyword = !kw || [asset.path_normalized, asset.host, asset.group_path, asset.owner].some(v => String(v || '').toLowerCase().includes(kw))
      const matchStatus = status === 'all' || asset.status === status
      const matchSensitivity = sensitivity === 'all' || asset.sensitivity_hint === sensitivity
      const matchClaim = claimStatus === 'all' || asset.claim_status === claimStatus
      return matchKeyword && matchStatus && matchSensitivity && matchClaim
    })
  }, [assets, keyword, status, sensitivity, claimStatus])

  const highAssets = assets.filter(a => a.sensitivity_hint === 'high')
  const shadowAssets = assets.filter(a => a.status === 'shadow')
  const zombieAssets = assets.filter(a => a.status === 'zombie')
  const unclaimedAssets = assets.filter(a => a.claim_status === 'unclaimed')

  const columns = [
    {
      title: 'API 资产',
      dataIndex: 'path_normalized',
      key: 'path',
      render: (path: string, record: any) => (
        <Space direction="vertical" size={3}>
          <span className="asset-path"><Tag color="blue">{record.method}</Tag>{path}</span>
          <span className="muted">{record.host} · {record.protocol_type} · 置信度 {Math.round((record.normalization_confidence || 0) * 100)}%</span>
        </Space>
      ),
    },
    {
      title: '敏感度',
      dataIndex: 'sensitivity_hint',
      key: 'sensitivity',
      width: 92,
      render: (value: string) => <Tag color={value === 'high' ? 'red' : value === 'medium' ? 'gold' : 'blue'}>{sensitivityLabel[value] || value}</Tag>,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 92,
      render: (value: string) => <Tag color={value === 'shadow' ? 'orange' : value === 'zombie' ? 'default' : 'success'}>{statusLabel[value] || value}</Tag>,
    },
    {
      title: '日均调用',
      dataIndex: 'daily_avg_calls',
      key: 'calls',
      width: 110,
      align: 'right' as const,
      render: (value: number) => value?.toLocaleString(),
      sorter: (a: any, b: any) => (a.daily_avg_calls || 0) - (b.daily_avg_calls || 0),
    },
    {
      title: '分组',
      dataIndex: 'group_path',
      key: 'group',
      render: (value: string) => <span className="muted">{value || '未分组'}</span>,
    },
    {
      title: '责任归属',
      dataIndex: 'claim_status',
      key: 'claim',
      width: 180,
      render: (value: string, record: any) => (
        <Space direction="vertical" size={2}>
          <Tag color={value === 'unclaimed' ? 'warning' : 'success'}>{claimLabel[value] || value}</Tag>
          <span className="muted">{record.owner || '暂无责任人'}</span>
        </Space>
      ),
    },
    {
      title: '操作',
      key: 'action',
      width: 150,
      render: (_: any, record: any) => (
        <Space>
          {record.claim_status === 'unclaimed' && (
            <Button size="small" icon={<UserAddOutlined />} onClick={(e) => { e.stopPropagation(); handleClaim(record.asset_id) }}>认领</Button>
          )}
          <Button size="small" type="primary" onClick={(e) => { e.stopPropagation(); onNavigate('asset-detail', record.asset_id) }}>详情</Button>
        </Space>
      ),
    },
  ]

  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">API 资产中心</div>
          <div className="page-heading__desc">统一管理自动发现的 API、影子接口、高敏数据暴露面和责任归属。</div>
        </div>
        <Space>
          <Button icon={<ExportOutlined />}>导出</Button>
          <Button type="primary" icon={<DatabaseOutlined />}>导入 OpenAPI</Button>
        </Space>
      </div>

      <div className="metric-grid">
        <Card className="metric-card">
          <div className="metric-card__label"><ApiOutlined /> API 总数</div>
          <div className="metric-card__value">{assets.length}</div>
          <div className="metric-card__meta">覆盖 REST / GraphQL / gRPC / WebSocket</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label">高敏资产</div>
          <div className="metric-card__value">{highAssets.length}</div>
          <div className="metric-card__meta">涉及身份、订单、支付和导出接口</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label">影子 / 僵尸</div>
          <div className="metric-card__value">{shadowAssets.length + zombieAssets.length}</div>
          <div className="metric-card__meta">{shadowAssets.length} 影子，{zombieAssets.length} 僵尸</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label">待认领</div>
          <div className="metric-card__value">{unclaimedAssets.length}</div>
          <div className="metric-card__meta">需要补齐业务 owner 和分组</div>
        </Card>
      </div>

      <div className="filter-bar">
        <Input
          allowClear
          prefix={<SearchOutlined />}
          placeholder="搜索路径、域名、分组、责任人"
          value={keyword}
          onChange={e => setKeyword(e.target.value)}
          style={{ width: 320 }}
        />
        <div className="filter-bar__controls">
          <Select value={status} onChange={setStatus} style={{ width: 128 }} options={[
            { value: 'all', label: '全部状态' },
            { value: 'active', label: '活跃' },
            { value: 'shadow', label: '影子 API' },
            { value: 'zombie', label: '僵尸 API' },
          ]} />
          <Select value={sensitivity} onChange={setSensitivity} style={{ width: 128 }} options={[
            { value: 'all', label: '全部敏感度' },
            { value: 'high', label: '高敏' },
            { value: 'medium', label: '中敏' },
            { value: 'low', label: '低敏' },
          ]} />
          <Select value={claimStatus} onChange={setClaimStatus} style={{ width: 128 }} options={[
            { value: 'all', label: '全部归属' },
            { value: 'unclaimed', label: '待认领' },
            { value: 'claimed', label: '已认领' },
          ]} />
        </div>
      </div>

      <Card title={`资产清单 (${filteredAssets.length})`}>
        <Table
          columns={columns}
          dataSource={filteredAssets}
          rowKey="asset_id"
          pagination={{ pageSize: 10, showSizeChanger: true }}
          size="middle"
          onRow={(record) => ({ onClick: () => onNavigate('asset-detail', record.asset_id), style: { cursor: 'pointer' } })}
        />
      </Card>
    </div>
  )
}
