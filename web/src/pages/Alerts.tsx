import { useEffect, useMemo, useState } from 'react'
import { Button, Card, Dropdown, Input, Select, Space, Table, Tag, message } from 'antd'
import { AlertOutlined, CheckCircleOutlined, ExportOutlined, SearchOutlined, ThunderboltOutlined } from '@ant-design/icons'
import { alertActionLabel, alertActionStatus, alertService, executeAlertAction } from '../services/api'
import { errorMessage } from '../services/http'
import { useSession } from '../context/session'
import { downloadCSV } from '../utils/csv'

interface Props {
  onNavigate: (page: string, id?: string) => void
}

const severityLabel: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
}

const severityColor: Record<string, string> = {
  critical: 'red',
  high: 'orange',
  medium: 'gold',
  low: 'blue',
}

const statusLabel: Record<string, string> = {
  open: '待处理',
  acknowledged: '已确认',
  in_progress: '处置中',
  resolved: '已解决',
  false_positive: '误报',
}

const statusColor: Record<string, string> = {
  open: 'error',
  acknowledged: 'processing',
  in_progress: 'warning',
  resolved: 'success',
  false_positive: 'default',
}

export default function Alerts({ onNavigate }: Props) {
  const [alerts, setAlerts] = useState<any[]>([])
  const [keyword, setKeyword] = useState('')
  const [severity, setSeverity] = useState('all')
  const [status, setStatus] = useState('all')
  const [source, setSource] = useState('all')

  useEffect(() => {
    alertService.list().then(setAlerts)
  }, [])

  const { can } = useSession()
  const canHandle = can('alert.handle')

  const [selected, setSelected] = useState<string[]>([])
  const [batchBusy, setBatchBusy] = useState(false)

  // Applies one handling action to every selected alert, one at a time.
  const batchAction = async (action: string) => {
    setBatchBusy(true)
    let done = 0
    const failed: string[] = []
    for (const id of selected) {
      try {
        const updated = await executeAlertAction(id, action)
        setAlerts(prev => prev.map(a => (a.alert_id === id ? (updated?.alert_id ? updated : { ...a, status: alertActionStatus[action] }) : a)))
        done++
      } catch (err) {
        failed.push(`${id}: ${errorMessage(err)}`)
      }
    }
    setBatchBusy(false)
    setSelected([])
    if (failed.length) message.error(`${done} 条成功，${failed.length} 条失败：${failed[0]}`)
    else message.success(`已对 ${done} 条告警${alertActionLabel[action]}`)
  }

  const exportAlerts = () => {
    downloadCSV(`告警-${new Date().toISOString().slice(0, 10)}.csv`,
      ['告警ID', '产生时间', '等级', '状态', '标题', '原因', '规则', '风险评分', '命中次数', '来源IP', '账号/调用方', '涉及接口'],
      filteredAlerts.map(a => [a.alert_id, new Date(a.timestamp).toLocaleString('zh-CN'), severityLabel[a.severity] || a.severity,
        statusLabel[a.status] || a.status, a.title, a.description, a.source_requirement, a.risk_score, a.occurrence_count || 1,
        a.source_ip, a.account_id, (a.endpoints || []).join(' ')]))
  }

  const handleAction = async (alertId: string, action: string) => {
    let updated: any
    try {
      updated = await executeAlertAction(alertId, action)
    } catch (err) {
      message.error(errorMessage(err))
      return
    }
    setAlerts(prev => prev.map(a =>
      a.alert_id === alertId ? (updated?.alert_id ? updated : { ...a, status: alertActionStatus[action] }) : a
    ))
    // The platform records disposals; enforcing them is up to the gateway,
    // WAF or SOAR that receives the forwarded event.
    message.success(alertActionStatus[action] === 'in_progress'
      ? `已记录处置：${alertActionLabel[action]}。请在网关或 WAF 执行`
      : `已${alertActionLabel[action]}`)
  }

  const sources = useMemo(() => {
    return Array.from(new Set(alerts.map(a => a.source_requirement).filter(Boolean))).map(item => ({ value: item, label: item }))
  }, [alerts])

  const filteredAlerts = useMemo(() => {
    const kw = keyword.trim().toLowerCase()
    return alerts.filter(alert => {
      const matchKeyword = !kw || [alert.title, alert.description, alert.source_ip, alert.account_id].some(v => String(v || '').toLowerCase().includes(kw))
      const matchSeverity = severity === 'all' || alert.severity === severity
      const matchStatus = status === 'all' || alert.status === status
      const matchSource = source === 'all' || alert.source_requirement === source
      return matchKeyword && matchSeverity && matchStatus && matchSource
    })
  }, [alerts, keyword, severity, status, source])

  const openAlerts = alerts.filter(a => a.status === 'open')
  const criticalAlerts = alerts.filter(a => a.severity === 'critical')
  const inProgressAlerts = alerts.filter(a => a.status === 'in_progress')
  const resolvedAlerts = alerts.filter(a => a.status === 'resolved')

  const columns = [
    {
      title: '风险',
      dataIndex: 'risk_score',
      key: 'score',
      width: 86,
      sorter: (a: any, b: any) => (a.risk_score || 0) - (b.risk_score || 0),
      render: (score: number) => <div className="score-pill">{score}</div>,
    },
    {
      title: '告警',
      dataIndex: 'title',
      key: 'title',
      render: (title: string, record: any) => (
        <Space direction="vertical" size={3}>
          <Space size={6}>
            <span style={{ fontWeight: 650 }}>{title}</span>
            {record.occurrence_count > 1 && <Tag color="orange">×{record.occurrence_count} 次</Tag>}
          </Space>
          <span className="muted">{record.description}</span>
        </Space>
      ),
    },
    {
      title: '等级',
      dataIndex: 'severity',
      key: 'severity',
      width: 90,
      render: (value: string) => <Tag color={severityColor[value] || 'default'}>{severityLabel[value] || value}</Tag>,
    },
    {
      title: '来源',
      dataIndex: 'source_requirement',
      key: 'source',
      width: 116,
      render: (value: string) => <Tag>{value}</Tag>,
    },
    {
      title: '主体',
      key: 'principal',
      width: 172,
      render: (_: any, record: any) => (
        <Space direction="vertical" size={2}>
          <span>{record.source_ip || '-'}</span>
          <span className="muted">{record.account_id || record.device_fingerprint || '无账号上下文'}</span>
        </Space>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 96,
      render: (value: string) => <Tag color={statusColor[value] || 'default'}>{statusLabel[value] || value}</Tag>,
    },
    {
      title: '发生时间',
      dataIndex: 'timestamp',
      key: 'time',
      width: 170,
      render: (value: string, record: any) => (
        <Space direction="vertical" size={0}>
          <span>{new Date(value).toLocaleString('zh-CN')}</span>
          {record.occurrence_count > 1 && record.last_seen && (
            <span className="muted">最近 {new Date(record.last_seen).toLocaleString('zh-CN')}</span>
          )}
        </Space>
      ),
    },
    {
      title: '处置',
      key: 'action',
      width: 180,
      render: (_: any, record: any) => (
        <Space>
          <Button size="small" onClick={(e) => { e.stopPropagation(); onNavigate('alert-detail', record.alert_id) }}>详情</Button>
          {record.status === 'open' && canHandle && (
            <Button size="small" onClick={(e) => { e.stopPropagation(); handleAction(record.alert_id, 'acknowledge') }}>确认</Button>
          )}
          {(record.status === 'open' || record.status === 'acknowledged') && canHandle && (
            <Button size="small" type="primary" danger onClick={(e) => { e.stopPropagation(); handleAction(record.alert_id, 'ip_block') }}>封禁</Button>
          )}
        </Space>
      ),
    },
  ]

  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">告警中心</div>
          <div className="page-heading__desc">按风险优先级组织告警研判、证据核查和处置动作，形成可审计的运营闭环。</div>
        </div>
        <Space>
          <Button icon={<ExportOutlined />} onClick={exportAlerts} disabled={!filteredAlerts.length}>导出 CSV</Button>
          {canHandle && (
            <Dropdown
              disabled={!selected.length}
              menu={{ items: ['acknowledge', 'resolve', 'false_positive'].map(k => ({ key: k, label: alertActionLabel[k] })), onClick: ({ key }) => batchAction(key) }}
            >
              <Button type="primary" icon={<ThunderboltOutlined />} loading={batchBusy}>批量处置{selected.length ? `（${selected.length}）` : ''}</Button>
            </Dropdown>
          )}
        </Space>
      </div>

      <div className="metric-grid">
        <Card className="metric-card">
          <div className="metric-card__label"><AlertOutlined /> 待处理</div>
          <div className="metric-card__value">{openAlerts.length}</div>
          <div className="metric-card__meta">需要安全运营人员确认</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label">严重告警</div>
          <div className="metric-card__value">{criticalAlerts.length}</div>
          <div className="metric-card__meta">建议优先核查攻击路径</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label">处置中</div>
          <div className="metric-card__value">{inProgressAlerts.length}</div>
          <div className="metric-card__meta">封禁、限流或会话失效中</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><CheckCircleOutlined /> 已关闭</div>
          <div className="metric-card__value">{resolvedAlerts.length}</div>
          <div className="metric-card__meta">已解决和误报将在审计中保留</div>
        </Card>
      </div>

      <div className="filter-bar">
        <Input
          allowClear
          prefix={<SearchOutlined />}
          placeholder="搜索标题、描述、来源 IP、账号"
          value={keyword}
          onChange={e => setKeyword(e.target.value)}
          style={{ width: 340 }}
        />
        <div className="filter-bar__controls">
          <Select value={severity} onChange={setSeverity} style={{ width: 120 }} options={[
            { value: 'all', label: '全部等级' },
            { value: 'critical', label: '严重' },
            { value: 'high', label: '高危' },
            { value: 'medium', label: '中危' },
            { value: 'low', label: '低危' },
          ]} />
          <Select value={status} onChange={setStatus} style={{ width: 120 }} options={[
            { value: 'all', label: '全部状态' },
            { value: 'open', label: '待处理' },
            { value: 'acknowledged', label: '已确认' },
            { value: 'in_progress', label: '处置中' },
            { value: 'resolved', label: '已解决' },
          ]} />
          <Select value={source} onChange={setSource} style={{ width: 140 }} options={[{ value: 'all', label: '全部来源' }, ...sources]} />
        </div>
      </div>

      <Card title={`告警队列 (${filteredAlerts.length})`}>
        <Table scroll={{ x: 'max-content' }}
          columns={columns}
          dataSource={filteredAlerts}
          rowKey="alert_id"
          rowSelection={canHandle ? { selectedRowKeys: selected, onChange: keys => setSelected(keys as string[]) } : undefined}
          pagination={{ pageSize: 10, showSizeChanger: true }}
          size="middle"
          onRow={(record) => ({ onClick: () => onNavigate('alert-detail', record.alert_id), style: { cursor: 'pointer' } })}
        />
      </Card>
    </div>
  )
}
