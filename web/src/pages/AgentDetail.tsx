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

  if (!agent) return <div style={{ color: '#F0F4F8' }}>加载中...</div>

  const qpsOption = {
    backgroundColor: 'transparent',
    tooltip: { trigger: 'axis' },
    xAxis: {
      type: 'category',
      data: ['-7h', '-6h', '-5h', '-4h', '-3h', '-2h', '-1h', 'now'],
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
      data: ['-7h', '-6h', '-5h', '-4h', '-3h', '-2h', '-1h', 'now'],
      axisLine: { lineStyle: { color: '#1E3A5F' } },
      axisLabel: { color: '#94A3B8', fontSize: 10 },
    },
    yAxis: {
      type: 'value', max: 100,
      axisLine: { lineStyle: { color: '#1E3A5F' } },
      axisLabel: { color: '#94A3B8' },
      splitLine: { lineStyle: { color: '#1E3A5F' } },
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
          <Card className="dashboard-card" title={<span style={{ color: '#F0F4F8' }}>采集器基本信息</span>}>
            <Descriptions bordered column={3} size="small" labelStyle={{ color: '#94A3B8', background: '#132F4C' }} contentStyle={{ color: '#F0F4F8' }}>
              <Descriptions.Item label="采集器ID">{agent.agent_id}</Descriptions.Item>
              <Descriptions.Item label="主机名">{agent.hostname}</Descriptions.Item>
              <Descriptions.Item label="状态">
                <Tag color={{ online: 'green', offline: 'red', degraded: 'orange' }[agent.status]}>
                  {{ online: '在线', offline: '离线', degraded: '异常' }[agent.status]}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="采集模式"><Tag color="cyan">{agent.collect_mode}</Tag></Descriptions.Item>
              <Descriptions.Item label="集群">{agent.cluster}</Descriptions.Item>
              <Descriptions.Item label="版本">{agent.agent_version}</Descriptions.Item>
              <Descriptions.Item label="操作系统">{agent.os}</Descriptions.Item>
              <Descriptions.Item label="CPU">{agent.cpu_percent}%</Descriptions.Item>
              <Descriptions.Item label="内存">{agent.memory_mb_used} MB</Descriptions.Item>
              <Descriptions.Item label="丢包率">{(agent.drop_rate * 100).toFixed(2)}%</Descriptions.Item>
              <Descriptions.Item label="QPS">{agent.qps.toLocaleString()}</Descriptions.Item>
              <Descriptions.Item label="最后心跳">{new Date(agent.last_heartbeat).toLocaleString('zh-CN')}</Descriptions.Item>
              <Descriptions.Item label="云厂商">{agent.cloud_provider}</Descriptions.Item>
              <Descriptions.Item label="区域">{agent.region}</Descriptions.Item>
              <Descriptions.Item label="采集API数">{detail?.collected_apis || '-'}</Descriptions.Item>
            </Descriptions>
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col span={12}>
          <Card className="dashboard-card" title={<span style={{ color: '#F0F4F8' }}>QPS 趋势</span>}>
            <ReactECharts option={qpsOption} style={{ height: '200px' }} />
          </Card>
        </Col>
        <Col span={12}>
          <Card className="dashboard-card" title={<span style={{ color: '#F0F4F8' }}>CPU 使用率</span>}>
            <ReactECharts option={cpuOption} style={{ height: '200px' }} />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col span={12}>
          <Card className="dashboard-card" title={<span style={{ color: '#F0F4F8' }}>运行配置</span>}>
            <Descriptions bordered column={1} size="small" labelStyle={{ color: '#94A3B8' }} contentStyle={{ color: '#F0F4F8' }}>
              <Descriptions.Item label="采集模式">{detail?.config?.mode}</Descriptions.Item>
              <Descriptions.Item label="过滤端口">{detail?.config?.filter_ports?.join(', ') || '-'}</Descriptions.Item>
              <Descriptions.Item label="捕获请求头">{detail?.config?.capture_headers ? '是' : '否'}</Descriptions.Item>
              <Descriptions.Item label="捕获Body">{detail?.config?.capture_body ? '是' : '否'}</Descriptions.Item>
              <Descriptions.Item label="最大Body">{detail?.config?.max_body_size_kb || '-'} KB</Descriptions.Item>
              <Descriptions.Item label="Kafka Topic">{detail?.config?.kafka_topic || '-'}</Descriptions.Item>
            </Descriptions>
          </Card>
        </Col>
        <Col span={12}>
          <Card className="dashboard-card" title={<span style={{ color: '#F0F4F8' }}>最近日志</span>}>
            <Table columns={logColumns} dataSource={detail?.recent_logs || []} rowKey={(r: any, i: number) => `${i}`} pagination={false} size="small" />
          </Card>
        </Col>
      </Row>
    </div>
  )
}
