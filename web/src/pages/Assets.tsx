import { useEffect, useState } from 'react'
import { Table, Tag, Button, Space, Typography, Card } from 'antd'
import { claimAsset, assetService } from '../services/api'

const { Title } = Typography

interface Props {
  onNavigate: (page: string, id?: string) => void
}

export default function Assets({ onNavigate }: Props) {
  const [assets, setAssets] = useState<any[]>([])

  useEffect(() => {
    assetService.list().then(setAssets)
  }, [])

  const handleClaim = (assetId: string) => {
    claimAsset(assetId, 'current.user@company.com')
    setAssets(prev => prev.map(a =>
      a.asset_id === assetId ? { ...a, claim_status: 'claimed', owner: 'current.user@company.com' } : a
    ))
  }

  const columns = [
    { title: '资产ID', dataIndex: 'asset_id', key: 'id', width: 100 },
    { title: '路径', dataIndex: 'path_normalized', key: 'path' },
    { title: '方法', dataIndex: 'method', key: 'method', width: 80,
      render: (m: string) => <Tag color="blue">{m}</Tag> },
    { title: '协议', dataIndex: 'protocol_type', key: 'protocol', width: 80,
      render: (p: string) => <Tag>{p}</Tag> },
    { title: '日均调用', dataIndex: 'daily_avg_calls', key: 'calls', width: 100,
      render: (c: number) => c.toLocaleString() },
    {
      title: '敏感度', dataIndex: 'sensitivity_hint', key: 'sensitivity', width: 80,
      render: (s: string) => {
        const colors: Record<string, string> = { high: 'red', medium: 'orange', low: 'green' }
        return <Tag color={colors[s]}>{s}</Tag>
      },
    },
    { title: '分组', dataIndex: 'group_path', key: 'group' },
    {
      title: '认领状态', dataIndex: 'claim_status', key: 'claim', width: 100,
      render: (s: string) => {
        const map: Record<string, any> = { unclaimed: { color: 'warning', text: '待认领' }, claimed: { color: 'success', text: '已认领' }, escalated: { color: 'error', text: '已升级' } }
        const info = map[s] || { color: 'default', text: s }
        return <Tag color={info.color}>{info.text}</Tag>
      },
    },
    { title: '责任人', dataIndex: 'owner', key: 'owner', width: 150 },
    {
      title: '操作', key: 'action', width: 100,
      render: (_: any, record: any) => (
        <Button size="small" type="primary" onClick={() => onNavigate('asset-detail', record.asset_id)}>详情</Button>
      ),
    },
  ]

  return (
    <Card className="dashboard-card" title={<span style={{ color: '#F0F4F8' }}>API 资产列表（点击行查看详情）</span>}>
      <Table
        columns={columns}
        dataSource={assets}
        rowKey="asset_id"
        pagination={{ pageSize: 20 }}
        size="middle"
        onRow={(record) => ({ onClick: () => onNavigate('asset-detail', record.asset_id), style: { cursor: 'pointer' } })}
      />
    </Card>
  )
}
