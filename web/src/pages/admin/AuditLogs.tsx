import { useEffect, useState } from 'react'
import { Alert, Button, Card, DatePicker, Descriptions, Input, Select, Space, Table, Tag, message } from 'antd'
import { DownloadOutlined, ReloadOutlined, SafetyCertificateOutlined, SearchOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import type { Dayjs } from 'dayjs'
import { adminService } from '../../services/admin'
import type { AuditQuery, AuditRecord, FullVerifyStatus, VerifyResult } from '../../services/admin'
import { DEMO, errorMessage } from '../../services/http'

export const eventLabels: Record<string, string> = {
  'auth.login': '登录', 'auth.logout': '退出登录', 'auth.password_change': '修改口令',
  'user.create': '新建账号', 'user.update': '修改账号', 'user.delete': '删除账号', 'user.enable': '启用账号',
  'user.disable': '停用账号', 'user.unlock': '解锁账号', 'user.lock': '账号锁定', 'user.reset_password': '重置口令',
  'user.auto_disable': '长期未登录自动停用', 'user.bootstrap': '创建初始账号',
  'policy.update': '修改安全策略', 'access.denied': '越权访问被拒绝',
  'audit.query': '查询审计日志', 'audit.verify': '校验审计完整性', 'audit.verify_full': '全量校验审计完整性', 'audit.verify_full_start': '发起全量校验', 'audit.export': '导出审计日志', 'audit.purge': '清理过期审计日志',
  'rule.update': '修改检测策略', 'rule.hit': '规则命中登记', 'alert.action': '告警处置', 'asset.claim': '认领资产',
  'detect.record': '登记检测样本', 'agent.register': '采集器注册',
}

const eventFilters = [
  { value: 'auth.', label: '登录与口令' },
  { value: 'user.', label: '账号管理' },
  { value: 'policy.', label: '安全策略' },
  { value: 'access.', label: '越权访问' },
  { value: 'audit.', label: '审计操作' },
  { value: 'rule.', label: '检测策略' },
  { value: 'alert.', label: '告警处置' },
  { value: 'asset.', label: '资产' },
  { value: 'agent.', label: '采集器' },
]

const consoleLabels: Record<string, string> = { admin: '管理后台', security: '安全平台', auth: '登录', agent: '采集器', system: '系统' }

const PAGE = 50

export default function AuditLogs() {
  const [rows, setRows] = useState<AuditRecord[]>([])
  const [total, setTotal] = useState(0)
  const [totalCapped, setTotalCapped] = useState(false)
  const [full, setFull] = useState<FullVerifyStatus | null>(null)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [username, setUsername] = useState('')
  const [eventType, setEventType] = useState<string>()
  const [result, setResult] = useState<string>()
  const [range, setRange] = useState<[Dayjs | null, Dayjs | null] | null>(null)
  const [verify, setVerify] = useState<VerifyResult | null>(null)
  const [verifying, setVerifying] = useState(false)

  const query = (p = page): AuditQuery => ({
    username: username.trim() || undefined,
    event_type: eventType,
    result,
    from: range?.[0] ? range[0].startOf('day').toISOString() : undefined,
    to: range?.[1] ? range[1].endOf('day').toISOString() : undefined,
    limit: PAGE,
    offset: (p - 1) * PAGE,
  })

  const load = async (p = page) => {
    setLoading(true)
    try {
      const res = await adminService.audit(query(p))
      setRows(res.items)
      setTotal(res.total)
      setTotalCapped(!!res.total_capped)
      setPage(p)
    } catch (err) {
      message.error(errorMessage(err))
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => { load(1) }, [])

  // Full verification runs in the background; poll while it is running.
  const loadFull = () => adminService.fullVerifyStatus().then(setFull).catch(() => {})
  useEffect(() => { loadFull() }, [])
  useEffect(() => {
    if (!full?.running) return
    const t = setInterval(loadFull, 2000)
    return () => clearInterval(t)
  }, [full?.running])

  const startFull = async () => {
    try {
      const res = await adminService.startFullVerify()
      setFull(res.status)
      message.info(res.started ? '已开始全量校验，完成后结果会显示在此处' : '全量校验正在进行中')
    } catch (err) {
      message.error(errorMessage(err))
    }
  }

  const runVerify = async () => {
    setVerifying(true)
    try {
      setVerify(await adminService.verifyAudit())
    } catch (err) {
      message.error(errorMessage(err))
    } finally {
      setVerifying(false)
    }
  }

  const exportCsv = () => {
    if (DEMO) { message.info('演示环境不提供导出'); return }
    // A plain navigation carries the session cookie; the file downloads.
    window.location.href = adminService.auditExportUrl(query(1))
  }

  const columns = [
    { title: '序号', dataIndex: 'seq', key: 'seq', width: 80, render: (v: number) => <span className="mono">{v}</span> },
    { title: '时间', dataIndex: 'time', key: 'time', width: 170, render: (t: string) => <span className="mono">{dayjs(t).format('YYYY-MM-DD HH:mm:ss')}</span> },
    {
      title: '操作人', key: 'user', width: 150, render: (_: unknown, r: AuditRecord) => (
        <Space direction="vertical" size={0}>
          <span>{r.username || '—'}</span>
          {r.role && <span className="muted" style={{ fontSize: 12 }}>{r.role}</span>}
        </Space>
      ),
    },
    { title: '源 IP', dataIndex: 'source_ip', key: 'ip', width: 130, render: (v: string) => <span className="mono">{v || '—'}</span> },
    { title: '来源', dataIndex: 'console', key: 'console', width: 90, render: (v: string) => consoleLabels[v] || v },
    {
      title: '事件', dataIndex: 'event_type', key: 'event', width: 180, render: (v: string) => (
        <Space direction="vertical" size={0}>
          <span>{eventLabels[v] || v}</span>
          <span className="muted mono" style={{ fontSize: 12 }}>{v}</span>
        </Space>
      ),
    },
    { title: '操作对象', dataIndex: 'target', key: 'target', ellipsis: true, render: (v: string) => <span className="mono">{v || '—'}</span> },
    { title: '结果', dataIndex: 'result', key: 'result', width: 80, render: (v: string) => (v === 'success' ? <Tag color="success">成功</Tag> : <Tag color="error">失败</Tag>) },
    { title: '原因 / 详情', key: 'reason', ellipsis: true, render: (_: unknown, r: AuditRecord) => r.reason || r.detail || '—' },
  ]

  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">审计日志</div>
          <div className="page-heading__desc">记录所有登录、账号与权限变更、策略变更、越权访问和 API 安全操作。记录只能追加，每条都用 SM3 与上一条链接，任何修改或删除都能被校验发现。</div>
        </div>
        <Space>
          <Button icon={<SafetyCertificateOutlined />} loading={verifying} onClick={runVerify}>校验完整性</Button>
          <Button loading={full?.running} onClick={startFull}>{full?.running ? `全量校验中（${(full.checked || 0).toLocaleString()} 条）` : '全量校验（后台）'}</Button>
          <Button icon={<DownloadOutlined />} onClick={exportCsv}>导出 CSV</Button>
        </Space>
      </div>

      {verify && (verify.ok ? (
        <Alert type="success" showIcon closable onClose={() => setVerify(null)}
          message={verify.mode === 'incremental'
            ? `哈希链完整：已校验上次检查点之后的 ${verify.checked} 条记录（序号 ${verify.first_seq}–${verify.last_seq}），未发现修改或删除。`
            : `哈希链完整：已校验全部 ${verify.checked} 条记录（序号 ${verify.first_seq}–${verify.last_seq}），未发现修改或删除。`} />
      ) : (
        <Alert type="error" showIcon closable onClose={() => setVerify(null)}
          message={`完整性校验失败：自序号 ${verify.broken_at} 起哈希链断裂`} description={verify.reason} />
      ))}

      {full?.last && (
        <div className="muted" style={{ fontSize: 12 }}>
          上次全量校验：{dayjs(full.last.finished_at).format('YYYY-MM-DD HH:mm')} ·{' '}
          {full.last.ok ? `完整（${full.last.checked.toLocaleString()} 条）` : <span style={{ color: 'var(--fl-critical)' }}>发现问题：{full.last.reason}</span>}
          。“校验完整性”只检查上次检查点之后的新记录，全量校验每天自动执行一次。
        </div>
      )}

      <Card title={`审计记录 (${totalCapped ? `${total.toLocaleString()}+` : total.toLocaleString()})`}>
        <div className="filter-bar">
          <Input allowClear prefix={<SearchOutlined />} placeholder="操作人用户名" value={username} onChange={e => setUsername(e.target.value)} style={{ width: 160 }} onPressEnter={() => load(1)} />
          <Select allowClear placeholder="事件类别" value={eventType} onChange={setEventType} options={eventFilters} style={{ width: 140 }} />
          <Select allowClear placeholder="结果" value={result} onChange={setResult} style={{ width: 100 }}
            options={[{ value: 'success', label: '成功' }, { value: 'failure', label: '失败' }]} />
          <DatePicker.RangePicker value={range} onChange={v => setRange(v as [Dayjs | null, Dayjs | null] | null)} placeholder={['开始日期', '结束日期']} />
          <Button type="primary" onClick={() => load(1)}>查询</Button>
          <Button icon={<ReloadOutlined />} onClick={() => load(page)} aria-label="刷新" />
        </div>
        <Table
          rowKey="seq"
          columns={columns}
          dataSource={rows}
          loading={loading}
          scroll={{ x: 1250 }}
          pagination={{
            current: page, pageSize: PAGE, total, showSizeChanger: false, onChange: p => load(p),
            showTotal: () => (totalCapped ? `匹配超过 ${total.toLocaleString()} 条，仅显示最新的 ${total.toLocaleString()} 条，请缩小时间范围或增加筛选条件` : ''),
          }}
          expandable={{
            expandedRowRender: (r: AuditRecord) => (
              <Descriptions size="small" column={1} bordered>
                {r.method && <Descriptions.Item label="请求">{r.method} <span className="mono">{r.path}</span></Descriptions.Item>}
                {r.detail && <Descriptions.Item label="详情"><span className="mono" style={{ wordBreak: 'break-all' }}>{r.detail}</span></Descriptions.Item>}
                <Descriptions.Item label="上一条哈希"><span className="mono" style={{ wordBreak: 'break-all' }}>{r.prev_hash || '（链首）'}</span></Descriptions.Item>
                <Descriptions.Item label="本条哈希 (SM3)"><span className="mono" style={{ wordBreak: 'break-all' }}>{r.hash}</span></Descriptions.Item>
              </Descriptions>
            ),
          }}
        />
      </Card>
    </div>
  )
}
