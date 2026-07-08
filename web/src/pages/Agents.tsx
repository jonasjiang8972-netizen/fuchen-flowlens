import { useEffect, useState } from 'react'
import { Card, Progress, Space, Table, Tag } from 'antd'
import { CheckCircleFilled, CloseCircleFilled, CloudServerOutlined, WarningFilled } from '@ant-design/icons'
import { agentService, ingestService } from '../services/api'

interface Props {
  onNavigate: (page: string, id?: string) => void
}

export default function Agents({ onNavigate }: Props) {
  const [agents, setAgents] = useState<any[]>([])
  const [ingest, setIngest] = useState<any>(null)

  useEffect(() => {
    agentService.list().then(setAgents)
    ingestService.metrics().then(setIngest)
  }, [])

  const onlineCount = agents.filter(a => a.status === 'online').length
  const offlineCount = agents.filter(a => a.status === 'offline').length
  const degradedCount = agents.filter(a => a.status === 'degraded').length
  const totalQps = agents.reduce((sum, item) => sum + (item.qps || 0), 0)
  const avgDropRate = agents.length ? agents.reduce((sum, item) => sum + (item.drop_rate || 0), 0) / agents.length : 0
  const queueDepth = ingest?.queue_depth || 0
  const queueSize = ingest?.queue_size || 20000
  const queueUsage = queueSize ? queueDepth / queueSize : 0
  const ingestDropRate = ingest?.accepted ? (ingest.dropped || 0) / ingest.accepted : avgDropRate

  const pipelineRows = [
    { stage: 'Agent 采集', status: degradedCount || offlineCount ? 'degraded' : 'online', latency: '18ms', throughput: `${totalQps.toLocaleString()} QPS`, detail: `${onlineCount}/${agents.length} 在线，平均丢弃率 ${(avgDropRate * 100).toFixed(2)}%` },
    { stage: 'Gateway Log / eBPF Normalizer', status: 'online', latency: '64ms', throughput: '156k events/min', detail: '路径归一化、账号/对象上下文补全' },
    { stage: 'Ingest Queue', status: queueUsage > 0.7 ? 'degraded' : 'online', latency: 'sub-second', throughput: `${queueDepth.toLocaleString()}/${queueSize.toLocaleString()}`, detail: `已接收 ${(ingest?.accepted || 0).toLocaleString()}，已处理 ${(ingest?.processed || 0).toLocaleString()}，重复 ${(ingest?.duplicates || 0).toLocaleString()}` },
    { stage: 'Detection Engine', status: 'online', latency: 'P95 182ms', throughput: 'BOLA / Auth / BFLA / DLP', detail: '高风险事件自动进入告警中心并回写策略命中' },
    { stage: 'Alert Store / Web Console', status: 'online', latency: '240ms', throughput: '实时刷新', detail: '告警、资产、链路视图可查询' },
  ]

  const columns = [
    {
      title: '采集器',
      dataIndex: 'agent_id',
      key: 'id',
      render: (value: string, record: any) => (
        <Space direction="vertical" size={2}>
          <span style={{ fontWeight: 650 }}>{value}</span>
          <span className="muted">{record.hostname} · {record.namespace || record.service_name || record.cluster}</span>
        </Space>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (value: string) => {
        const icons: Record<string, any> = {
          online: <CheckCircleFilled style={{ color: 'var(--fl-success)' }} />,
          offline: <CloseCircleFilled style={{ color: 'var(--fl-critical)' }} />,
          degraded: <WarningFilled style={{ color: 'var(--fl-medium)' }} />,
        }
        const labels: Record<string, string> = { online: '在线', offline: '离线', degraded: '异常' }
        return <Space>{icons[value]}{labels[value] || value}</Space>
      },
    },
    { title: '模式', dataIndex: 'collect_mode', key: 'mode', width: 120, render: (value: string) => <Tag color="cyan">{value}</Tag> },
    { title: '集群', dataIndex: 'cluster', key: 'cluster', width: 150 },
    { title: 'QPS', dataIndex: 'qps', key: 'qps', width: 110, align: 'right' as const, render: (value: number) => value?.toLocaleString() },
    {
      title: 'CPU',
      dataIndex: 'cpu_percent',
      key: 'cpu',
      width: 130,
      render: (value: number) => <Progress percent={Math.round(value)} size="small" showInfo={false} strokeColor={value > 80 ? 'var(--fl-critical)' : value > 50 ? 'var(--fl-medium)' : 'var(--fl-success)'} />,
    },
    { title: '内存', dataIndex: 'memory_mb_used', key: 'memory', width: 96, render: (value: number) => `${value} MB` },
    { title: '丢弃率', dataIndex: 'drop_rate', key: 'drop', width: 96, render: (value: number) => <span style={{ color: value > 0.01 ? 'var(--fl-critical)' : 'var(--fl-success)' }}>{(value * 100).toFixed(2)}%</span> },
    { title: '版本', dataIndex: 'agent_version', key: 'version', width: 86 },
    {
      title: '心跳',
      dataIndex: 'last_heartbeat',
      key: 'heartbeat',
      width: 120,
      render: (value: string) => {
        const diff = Math.floor((Date.now() - new Date(value).getTime()) / 1000)
        return <span style={{ color: diff > 60 ? 'var(--fl-critical)' : diff > 30 ? 'var(--fl-medium)' : 'var(--fl-success)' }}>{diff}s 前</span>
      },
    },
  ]

  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">采集与链路</div>
          <div className="page-heading__desc">面向运维和平台团队，确认 API 流量是否被覆盖、链路是否延迟、队列是否积压、采集证据是否可信。</div>
        </div>
      </div>

      <div className="metric-grid">
        <Card className="metric-card">
          <div className="metric-card__label"><CloudServerOutlined /> Agent 覆盖</div>
          <div className="metric-card__value">{onlineCount}/{agents.length}</div>
          <div className="metric-card__meta">{degradedCount} 异常，{offlineCount} 离线</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label">事件吞吐</div>
          <div className="metric-card__value">{totalQps.toLocaleString()}</div>
          <div className="metric-card__meta">当前采集 QPS</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label">队列水位</div>
          <div className="metric-card__value" style={{ fontSize: 24 }}>{(queueUsage * 100).toFixed(1)}%</div>
          <div className="metric-card__meta">{queueDepth.toLocaleString()} / {queueSize.toLocaleString()} events</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label">平台丢弃率</div>
          <div className="metric-card__value" style={{ color: ingestDropRate > 0.01 ? 'var(--fl-critical)' : 'var(--fl-success)' }}>{(ingestDropRate * 100).toFixed(2)}%</div>
          <div className="metric-card__meta">高于 1% 需要扩容 Worker 或队列</div>
        </Card>
      </div>

      <Card title="数据链路阶段">
        <Table
          columns={[
            { title: '阶段', dataIndex: 'stage', key: 'stage' },
            { title: '状态', dataIndex: 'status', key: 'status', width: 100, render: (value: string) => <Tag color={value === 'online' ? 'success' : 'warning'}>{value === 'online' ? '正常' : '需关注'}</Tag> },
            { title: '延迟', dataIndex: 'latency', key: 'latency', width: 130 },
            { title: '吞吐 / Topic', dataIndex: 'throughput', key: 'throughput', width: 170 },
            { title: '说明', dataIndex: 'detail', key: 'detail' },
          ]}
          dataSource={pipelineRows}
          rowKey="stage"
          pagination={false}
        />
      </Card>

      <Card title="采集器清单">
        <Table
          columns={columns}
          dataSource={agents}
          rowKey="agent_id"
          pagination={{ pageSize: 10 }}
          size="middle"
          onRow={(record) => ({ onClick: () => onNavigate('agent-detail', record.agent_id), style: { cursor: 'pointer' } })}
        />
      </Card>
    </div>
  )
}
