import { useEffect, useState } from 'react'
import { Button, Card, Checkbox, Form, Input, InputNumber, Modal, Popconfirm, Select, Space, Switch, Table, Tag, message } from 'antd'
import { PlusOutlined } from '@ant-design/icons'
import { adminService } from '../../services/admin'
import type { ForwardStats, ForwardTarget } from '../../services/admin'
import { errorMessage } from '../../services/http'

const eventOptions = [
  { value: 'alert.created', label: '新告警' },
  { value: 'alert.handled', label: '告警处置（确认、封禁、限流、关闭等）' },
  { value: 'audit', label: '审计日志' },
]
const eventLabel: Record<string, string> = { 'alert.created': '新告警', 'alert.handled': '告警处置', audit: '审计日志' }
const severityOptions = [
  { value: 'low', label: '低危及以上' }, { value: 'medium', label: '中危及以上' },
  { value: 'high', label: '高危及以上' }, { value: 'critical', label: '仅严重' },
]

const emptyTarget: ForwardTarget = {
  name: '', type: 'syslog', enabled: true, events: ['alert.created', 'audit'], min_severity: 'low',
  address: '', protocol: 'udp', format: 'json', facility: 13,
}

export default function Forwarding() {
  const [targets, setTargets] = useState<ForwardTarget[]>([])
  const [stats, setStats] = useState<Record<string, ForwardStats>>({})
  const [editing, setEditing] = useState<{ index: number; target: ForwardTarget } | null>(null)
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [form] = Form.useForm<ForwardTarget>()

  const load = () => adminService.forwarding().then(r => { setTargets(r.targets || []); setStats(r.stats || {}) })
    .catch(err => message.error(errorMessage(err)))
  useEffect(() => { load() }, [])

  const save = async (next: ForwardTarget[]) => {
    setSaving(true)
    try {
      const r = await adminService.updateForwarding(next)
      setTargets(r.targets || [])
      setStats(r.stats || {})
      message.success('已保存，立即生效')
      return true
    } catch (err) {
      message.error(errorMessage(err))
      return false
    } finally {
      setSaving(false)
    }
  }

  const openEditor = (index: number) => {
    const target = index >= 0 ? targets[index] : { ...emptyTarget }
    setEditing({ index, target })
    form.setFieldsValue(target)
  }

  const formTarget = async (): Promise<ForwardTarget | null> => {
    try {
      const v = await form.validateFields()
      return { ...editing!.target, ...v }
    } catch {
      return null
    }
  }

  const submit = async () => {
    const t = await formTarget()
    if (!t || !editing) return
    const next = [...targets]
    if (editing.index >= 0) next[editing.index] = t
    else next.push(t)
    if (await save(next)) setEditing(null)
  }

  const test = async () => {
    const t = await formTarget()
    if (!t) return
    setTesting(true)
    try {
      const r = await adminService.testForwarding(t)
      if (r.ok) message.success('测试消息已送达')
      else message.error(`发送失败：${r.error}`)
    } catch (err) {
      message.error(errorMessage(err))
    } finally {
      setTesting(false)
    }
  }

  const type = Form.useWatch('type', form)

  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">外发配置</div>
          <div className="page-heading__desc">把告警、告警处置和审计日志推送到 SIEM / SOC（syslog）或 SOAR、工单系统（Webhook）。外发异步进行，不影响平台运行。</div>
        </div>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => openEditor(-1)}>新增外发目标</Button>
      </div>

      <Card title="外发目标">
        <Table
          rowKey={(r: ForwardTarget) => r.id || r.name}
          dataSource={targets}
          pagination={false}
          locale={{ emptyText: '尚未配置外发目标' }}
          columns={[
            { title: '名称', dataIndex: 'name', key: 'name' },
            { title: '类型', key: 'type', width: 230, render: (_: any, r: ForwardTarget) => r.type === 'syslog'
              ? <span><Tag>syslog</Tag>{r.protocol?.toUpperCase()} {r.address} · {r.format?.toUpperCase()}</span>
              : <span><Tag color="blue">Webhook</Tag><span className="mono">{r.url}</span></span> },
            { title: '事件', dataIndex: 'events', key: 'events', render: (v: string[]) => v.map(e => <Tag key={e}>{eventLabel[e] || e}</Tag>) },
            { title: '告警等级', dataIndex: 'min_severity', key: 'sev', width: 110, render: (v: string) => severityOptions.find(o => o.value === v)?.label },
            { title: '启用', key: 'enabled', width: 70, render: (_: any, r: ForwardTarget, i: number) => (
              <Switch size="small" checked={r.enabled} loading={saving}
                onChange={v => save(targets.map((t, j) => (j === i ? { ...t, enabled: v } : t)))} />
            ) },
            { title: '发送情况（平台启动以来）', key: 'stats', width: 260, render: (_: any, r: ForwardTarget) => {
              const s = r.id ? stats[r.id] : undefined
              if (!s) return <span className="muted">-</span>
              return (
                <div>
                  <div>成功 {s.sent.toLocaleString()} · 失败 <span style={{ color: s.failed ? 'var(--fl-critical)' : undefined }}>{s.failed.toLocaleString()}</span>{s.dropped ? ` · 丢弃 ${s.dropped.toLocaleString()}` : ''}</div>
                  {s.last_error && <div className="muted" style={{ fontSize: 12 }}>最近错误：{s.last_error}</div>}
                </div>
              )
            } },
            { title: '操作', key: 'op', width: 120, render: (_: any, _r: ForwardTarget, i: number) => (
              <Space>
                <Button type="link" size="small" onClick={() => openEditor(i)}>编辑</Button>
                <Popconfirm title="删除该外发目标？" onConfirm={() => save(targets.filter((_, j) => j !== i))}>
                  <Button type="link" size="small" danger>删除</Button>
                </Popconfirm>
              </Space>
            ) },
          ]}
        />
      </Card>

      <Card title="接收方说明">
        <Space direction="vertical" size={8}>
          <span><b>syslog</b>：RFC 5424 格式，消息体为 JSON 或 CEF（ArcSight / QRadar 等 SIEM 可直接解析）。TCP、TLS 以换行分隔消息。</span>
          <span><b>Webhook</b>：POST JSON，请求头 <span className="mono">X-FlowLens-Event</span> 为事件类型。配置签名密钥后附带 <span className="mono">X-FlowLens-Timestamp</span> 和 <span className="mono">X-FlowLens-Signature: sha256=HMAC(密钥, 时间戳 + "." + 请求体)</span>，接收方可校验来源。失败时重试 3 次。</span>
          <span><b>告警处置</b>事件包含处置动作（ip_block、rate_limit、account_lock 等）、来源 IP、账号和接口，SOAR 可据此在网关或 WAF 上执行。</span>
        </Space>
      </Card>

      <Modal
        open={!!editing}
        title={editing && editing.index >= 0 ? '编辑外发目标' : '新增外发目标'}
        onCancel={() => setEditing(null)}
        width={620}
        footer={[
          <Button key="test" loading={testing} onClick={test}>发送测试消息</Button>,
          <Button key="cancel" onClick={() => setEditing(null)}>取消</Button>,
          <Button key="ok" type="primary" loading={saving} onClick={submit}>保存</Button>,
        ]}
      >
        <Form form={form} layout="vertical" requiredMark={false}>
          <Form.Item name="name" label="名称" rules={[{ required: true, message: '请输入名称' }, { max: 64 }]}>
            <Input placeholder="例如：SOC syslog" />
          </Form.Item>
          <Form.Item name="type" label="类型">
            <Select options={[{ value: 'syslog', label: 'syslog（SIEM / SOC）' }, { value: 'webhook', label: 'Webhook（SOAR / 工单 / IM 机器人）' }]} />
          </Form.Item>
          {type === 'webhook' ? (
            <>
              <Form.Item name="url" label="Webhook 地址" rules={[{ required: true, pattern: /^https?:\/\/.+/, message: '请输入 http:// 或 https:// 开头的地址' }]}>
                <Input placeholder="https://soar.example.com/hooks/flowlens" />
              </Form.Item>
              <Form.Item name="secret" label="签名密钥（可选）" extra="已保存的密钥显示为 ******，不修改则保留原值">
                <Input.Password placeholder="用于 HMAC-SHA256 签名" autoComplete="new-password" />
              </Form.Item>
            </>
          ) : (
            <Space style={{ width: '100%' }} size={12} wrap>
              <Form.Item name="address" label="地址（主机:端口）" rules={[{ required: true, pattern: /^.+:\d+$/, message: '例如 10.0.0.5:514' }]} style={{ width: 230 }}>
                <Input placeholder="10.0.0.5:514" />
              </Form.Item>
              <Form.Item name="protocol" label="协议" style={{ width: 100 }}>
                <Select options={[{ value: 'udp', label: 'UDP' }, { value: 'tcp', label: 'TCP' }, { value: 'tls', label: 'TLS' }]} />
              </Form.Item>
              <Form.Item name="format" label="格式" style={{ width: 100 }}>
                <Select options={[{ value: 'json', label: 'JSON' }, { value: 'cef', label: 'CEF' }]} />
              </Form.Item>
              <Form.Item name="facility" label="Facility" style={{ width: 90 }}>
                <InputNumber min={0} max={23} />
              </Form.Item>
            </Space>
          )}
          <Form.Item name="events" label="外发事件" rules={[{ required: true, type: 'array', min: 1, message: '至少选择一类事件' }]}>
            <Checkbox.Group options={eventOptions} />
          </Form.Item>
          <Form.Item name="min_severity" label="告警最低等级（对告警和处置事件生效）">
            <Select options={severityOptions} />
          </Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}
