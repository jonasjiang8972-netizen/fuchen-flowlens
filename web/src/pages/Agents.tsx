import { useEffect, useState } from 'react'
import { Table, Tag, Typography, Card, Progress, Space } from 'antd'
import { CheckCircleFilled, WarningFilled, CloseCircleFilled } from '@ant-design/icons'

const { Text } = Typography

export default function Agents() {
  const [agents, setAgents] = useState<any[]>([])

  useEffect(() => {
    const { agentService } = require('../services/api')
    setAgents(agentService.list())
  }, [])

  const onlineCount = agents.filter(a => a.status === 'online').length
  const offlineCount = agents.filter(a => a.status === 'offline').length
  const degradedCount = agents.filter(a => a.status === 'degraded').length

  const columns = [
    { title: '采集器ID', dataIndex: 'agent_id', key: 'id' },
    { title: '主机名', dataIndex: 'hostname', key: 'hostname' },
    {
      title: '状态', dataIndex: 'status', key: 'status', width: 100,
      render: (s: string) => {
        const icons: Record<string, any> = {
          online: <CheckCircleFilled style={{ color: '#52C41A' }} />,
          offline: <CloseCircleFilled style={{ color: '#F5222D' }} />,
          degraded: <WarningFilled style={{ color: '#FAAD14' }} />,
        }
        const labels: Record<string, string> = { online: '在线', offline: '离线', degraded: '异常' }
        return <Space>{icons[s] || null}{labels[s] || s}</Space>
      },
    },
    { title: '采集模式', dataIndex: 'collect_mode', key: 'mode', width: 120,
      render: (m: string) => <Tag color="cyan">{m}</Tag> },
    { title: '集群', dataIndex: 'cluster', key: 'cluster' },
    { title: 'QPS', dataIndex: 'qps', key: 'qps', width: 100,
      render: (q: number) => q.toLocaleString() },
    { title: 'CPU', dataIndex: 'cpu_percent', key: 'cpu', width: 120,
      render: (v: number) => (
        <Progress percent={Math.round(v)} size="small" showInfo={false}
          strokeColor={v > 80 ? '#F5222D' : v > 50 ? '#FAAD14' : '#52C41A'} />
      ),
    },
    { title: '内存(MB)', dataIndex: 'memory_mb_used', key: 'mem', width: 100 },
    { title: '丢包率', dataIndex: 'drop_rate', key: 'drop', width: 100,
      render: (d: number) => <span style={{ color: d > 0.01 ? '#F5222D' : '#52C41A' }}>{(d * 100).toFixed(2)}%</span> },
    { title: '版本', dataIndex: 'agent_version', key: 'ver', width: 80 },
    { title: '最后心跳', dataIndex: 'last_heartbeat', key: 'hb', width: 160,
      render: (t: string) => {
        const diff = Math.floor((Date.now() - new Date(t).getTime()) / 1000)
        const color = diff > 60 ? '#F5222D' : diff > 30 ? '#FAAD14' : '#52C41A'
        return <span style={{ color }}>{diff}s 前</span>
      },
    },
  ]

  return (
    <div>
      <Card className="dashboard-card" style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', gap: '32px' }}>
          <div>
            <Text style={{ color: '#94A3B8' }}>总计</Text>
            <div style={{ fontSize: '24px', fontWeight: 700, color: '#F0F4F8' }}>{agents.length}</div>
          </div>
          <div>
            <Text style={{ color: '#94A3B8' }}>在线</Text>
            <div style={{ fontSize: '24px', fontWeight: 700, color: '#52C41A' }}>{onlineCount}</div>
          </div>
          <div>
            <Text style={{ color: '#94A3B8' }}>离线</Text>
            <div style={{ fontSize: '24px', fontWeight: 700, color: '#F5222D' }}>{offlineCount}</div>
          </div>
          <div>
            <Text style={{ color: '#94A3B8' }}>异常</Text>
            <div style={{ fontSize: '24px', fontWeight: 700, color: '#FAAD14' }}>{degradedCount}</div>
          </div>
        </div>
      </Card>

      <Card className="dashboard-card" title={<span style={{ color: '#F0F4F8' }}>采集器列表</span>}>
        <Table
          columns={columns}
          dataSource={agents}
          rowKey="agent_id"
          pagination={false}
          size="middle"
        />
      </Card>
    </div>
  )
}
