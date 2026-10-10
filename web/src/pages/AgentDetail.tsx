import { useEffect, useState } from 'react'
import { Card, Descriptions, Tag, Table, Typography, Row, Col, Button, Space, Statistic, Timeline } from 'antd'
import { ArrowLeftOutlined } from '@ant-design/icons'
import ReactECharts from 'echarts-for-react'
import { agentService } from '../services/api'

const { Title } = Typography

interface Props {
  agentId: string
  onBack: () => void
  onNavigate: (page: string, id?: string) => void
}

export default function AgentDetail({ agentId, onBack, onNavigate }: Props) {
  const [agent, setAgent] = useState<any>(null)
  const [detail, setDetail] = useState<any>(null)

  useEffect(() => {
    Promise.all([
      agentService.list(),
      agentService.detail(agentId),
    ]).then(([agents, detail]) => {
      const found = agents.find((a: any) => a.agent_id === agentId)
      if (found) setAgent(found)
      setDetail(detail)
    })
  }, [agentId])

  if (!agent) return <div style={{ color: 'var(--fl-text)' }}>加载中...</div>

  // Heartbeat sample times (every ~10 s) label the trend charts.
  const sampleLabels: string[] = (detail?.metrics?.sample_times || []).map((t: string) =>
    new Date(t).toLocaleTimeString('zh-CN', { hour12: false }))
  const hasSamples = sampleLabels.length > 0
  const uptime = (() => {
    const sec = detail?.metrics?.uptime_seconds || 0
    if (!sec) return '-'
    const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60)
    return d ? `${d} 天 ${h} 小时` : h ? `${h} 小时 ${m} 分钟` : `${m} 分钟`
  })()
  const emptyChart = <div style={{ height: 200, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--fl-text-muted)' }}>暂无心跳数据（采集器每 10 秒上报一次）</div>

  // Chart colors are literals: the canvas renderer cannot resolve CSS variables.
  const qpsOption = {
    backgroundColor: 'transparent',
    tooltip: { trigger: 'axis' },
    xAxis: {
      type: 'category',
      data: sampleLabels,
      axisLine: { lineStyle: { color: '#d9e2ec' } },
      axisLabel: { color: '#64748b', fontSize: 10 },
    },
    yAxis: {
      type: 'value',
      axisLine: { lineStyle: { color: '#d9e2ec' } },
      axisLabel: { color: '#64748b' },
      splitLine: { lineStyle: { color: '#edf1f6' } },
    },
    series: [{
      name: 'QPS', type: 'line', smooth: true,
      data: detail?.metrics?.qps_history || [],
      lineStyle: { color: '#0D9373', width: 2 },
      areaStyle: { color: 'rgba(13, 147, 115, 0.1)' },
      itemStyle: { color: '#0D9373' },
    }],
    grid: { top: 20, right: 20, bottom: 30, left: 50 },
  }

  const cpuOption = {
    backgroundColor: 'transparent',
    tooltip: { trigger: 'axis' },
    xAxis: {
      type: 'category',
      data: sampleLabels,
      axisLine: { lineStyle: { color: '#d9e2ec' } },
      axisLabel: { color: '#64748b', fontSize: 10 },
    },
    yAxis: {
      type: 'value', max: 100,
      axisLine: { lineStyle: { color: '#d9e2ec' } },
      axisLabel: { color: '#64748b' },
      splitLine: { lineStyle: { color: '#edf1f6' } },
    },
    series: [{
      name: 'CPU %', type: 'line', smooth: true,
      data: detail?.metrics?.cpu_history || [],
      lineStyle: { color: '#FAAD14', width: 2 },
      areaStyle: { color: 'rgba(250, 173, 20, 0.1)' },
      itemStyle: { color: '#FAAD14' },
    }],
    grid: { top: 20, right: 20, bottom: 30, left: 50 },
  }

  const logColumns = [
    {
      title: '级别', dataIndex: 'level', key: 'level', width: 80,
      render: (l: string) => {
        const colors: Record<string, string> = { info: 'blue', warn: 'orange', error: 'red', debug: 'default' }
        return <Tag color={colors[l]}>{l}</Tag>
      },
    },
    { title: '消息', dataIndex: 'message', key: 'message' },
    { title: '时间', dataIndex: 'timestamp', key: 'time', width: 160,
      render: (t: string) => new Date(t).toLocaleString('zh-CN') },
  ]

  return (
    <div>
      <div style={{ marginBottom: 16 }}>
        <Button type="link" icon={<ArrowLeftOutlined />} onClick={onBack} style={{ color: '#36CFC9', padding: 0 }}>
          返回采集器列表
        </Button>
      </div>

      <Row gutter={[16, 16]}>
        <Col span={24}>
          <Card className="dashboard-card" title={<span style={{ color: 'var(--fl-text)' }}>采集器基本信息</span>}>
            <Descriptions bordered column={3} size="small" labelStyle={{ color: 'var(--fl-text-muted)', background: 'var(--fl-surface-muted)' }} contentStyle={{ color: 'var(--fl-text)' }}>
              <Descriptions.Item label="采集器ID">{agent.agent_id}</Descriptions.Item>
              <Descriptions.Item label="主机名">{agent.hostname}</Descriptions.Item>
              <Descriptions.Item label="状态">
                <Tag color={({ online: 'green', offline: 'red', degraded: 'orange' } as Record<string, string>)[agent.status]}>
                  {({ online: '在线', offline: '离线', degraded: '异常' } as Record<string, string>)[agent.status] || agent.status}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="采集模式"><Tag color="cyan">{agent.collect_mode}</Tag></Descriptions.Item>
              <Descriptions.Item label="集群">{agent.cluster}</Descriptions.Item>
              <Descriptions.Item label="版本">{agent.agent_version}</Descriptions.Item>
              <Descriptions.Item label="操作系统">{agent.os}</Descriptions.Item>
              <Descriptions.Item label="CPU">{Number(agent.cpu_percent || 0).toFixed(1)}%</Descriptions.Item>
              <Descriptions.Item label="内存">{agent.memory_mb_used} MB</Descriptions.Item>
              <Descriptions.Item label="丢弃率">{((agent.drop_rate || 0) * 100).toFixed(2)}%</Descriptions.Item>
              <Descriptions.Item label="QPS">{Number(agent.qps || 0).toLocaleString(undefined, { maximumFractionDigits: 1 })}</Descriptions.Item>
              <Descriptions.Item label="运行时长">{uptime}</Descriptions.Item>
              <Descriptions.Item label="最后心跳">{new Date(agent.last_heartbeat).toLocaleString('zh-CN')}</Descriptions.Item>
              <Descriptions.Item label="架构">{agent.arch || '-'}</Descriptions.Item>
              <Descriptions.Item label="采集API数">{detail?.collected_apis || '-'}</Descriptions.Item>
            </Descriptions>
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col span={12}>
          <Card className="dashboard-card" title={<span style={{ color: 'var(--fl-text)' }}>QPS 趋势</span>}>
            {hasSamples ? <ReactECharts option={qpsOption} style={{ height: '200px' }} /> : emptyChart}
          </Card>
        </Col>
        <Col span={12}>
          <Card className="dashboard-card" title={<span style={{ color: 'var(--fl-text)' }}>CPU 使用率</span>}>
            {hasSamples ? <ReactECharts option={cpuOption} style={{ height: '200px' }} /> : emptyChart}
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col span={12}>
          <Card className="dashboard-card" title={<span style={{ color: 'var(--fl-text)' }}>运行配置（采集器注册时上报）</span>}>
            <Descriptions bordered column={1} size="small" labelStyle={{ color: 'var(--fl-text-muted)' }} contentStyle={{ color: 'var(--fl-text)' }}>
              <Descriptions.Item label="采集模式">{detail?.config?.mode || '-'}</Descriptions.Item>
              {detail?.config?.gateway_log_path ? (
                <>
                  <Descriptions.Item label="网关日志">{detail.config.gateway_log_path}</Descriptions.Item>
                  <Descriptions.Item label="日志格式">{detail.config.gateway_log_format || 'json'}</Descriptions.Item>
                </>
              ) : (
                <Descriptions.Item label="过滤端口">{detail?.config?.filter_ports?.join(', ') || '-'}</Descriptions.Item>
              )}
              <Descriptions.Item label="捕获请求头">{detail?.config?.capture_headers ? '是' : '否'}</Descriptions.Item>
              <Descriptions.Item label="捕获Body">{detail?.config?.capture_body ? '是' : '否'}</Descriptions.Item>
              <Descriptions.Item label="最大Body">{detail?.config?.max_body_size_kb ? `${detail.config.max_body_size_kb} KB` : '-'}</Descriptions.Item>
            </Descriptions>
          </Card>
        </Col>
        <Col span={12}>
          <Card className="dashboard-card" title={<span style={{ color: 'var(--fl-text)' }}>运行事件（平台记录）</span>}>
            <Table columns={logColumns} dataSource={detail?.recent_logs || []} rowKey={(_: any, i?: number) => `${i ?? 0}`} pagination={false} size="small"
              locale={{ emptyText: '平台重启后暂无事件' }} />
          </Card>
        </Col>
      </Row>
    </div>
  )
}
