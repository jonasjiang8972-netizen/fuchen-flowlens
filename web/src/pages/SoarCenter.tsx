import { useEffect, useState } from 'react'
import { Alert, Button, Card, Empty, Form, Input, InputNumber, message, Popconfirm, Space, Table, Tag } from 'antd'
import { ApiOutlined, ReloadOutlined, StopOutlined, UnlockOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import relativeTime from 'dayjs/plugin/relativeTime'
import 'dayjs/locale/zh-cn'
import { useSession } from '../context/session'
import { errorMessage } from '../services/http'
import { soarService } from '../services/soar'
import type { Block, ConnectorStatus, ConnectorsInfo } from '../services/soar'

dayjs.extend(relativeTime)
dayjs.locale('zh-cn')

interface Props {
  onNavigate: (page: string, id?: string) => void
}

const STATE: Record<string, { label: string; color: string }> = {
  active: { label: '生效中', color: 'red' },
  dry_run: { label: '演练（未真实封禁）', color: 'gold' },
  released: { label: '已解除', color: 'default' },
  failed: { label: '执行失败', color: 'volcano' },
}

const CONN_STATUS: Record<string, { label: string; color: string }> = {
  unchecked: { label: '未检测', color: 'default' },
  ok: { label: '连接正常', color: 'success' },
  error: { label: '连接异常', color: 'error' },
}

export default function SoarCenter({ onNavigate }: Props) {
  const { can } = useSession()
  const canHandle = can('alert.handle')
  const canTest = can('rule.manage')

  const [info, setInfo] = useState<ConnectorsInfo | null>(null)
  const [blocks, setBlocks] = useState<Block[]>([])
  const [loading, setLoading] = useState(true)
  const [testing, setTesting] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [form] = Form.useForm()

  const load = async () => {
    setLoading(true)
    try {
      const [i, b] = await Promise.all([soarService.connectors(), soarService.blocks()])
      setInfo(i)
      setBlocks(b)
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => { load() }, [])

  const test = async (c: ConnectorStatus) => {
    setTesting(c.name)
    try {
      const st = await soarService.test(c.name)
      message[st.status === 'ok' ? 'success' : 'error'](st.status === 'ok' ? `${c.label} 连接正常` : `${c.label} 连接失败：${st.error}`)
    } catch (err) {
      message.error(errorMessage(err))
    } finally {
      setTesting('')
      load()
    }
  }

  const submitBlock = async (v: { ip: string; ttl_minutes?: number; reason?: string }) => {
    setSubmitting(true)
    try {
      const b = await soarService.block({ ip: v.ip.trim(), ttl_minutes: v.ttl_minutes, reason: v.reason })
      message.success(b.state === 'dry_run' ? `已记录 ${b.ip}（演练模式，未真实封禁）` : `已封禁 ${b.ip}`)
      form.resetFields()
      load()
    } catch (err) {
      message.error(errorMessage(err))
    } finally {
      setSubmitting(false)
    }
  }

  const unblock = async (ip: string) => {
    try {
      await soarService.unblock(ip)
      message.success(`已解除 ${ip} 的封禁`)
    } catch (err) {
      message.error(errorMessage(err))
    }
    load()
  }

  const inForce = blocks.filter(b => b.state === 'active' || b.state === 'dry_run')
  const history = blocks.filter(b => b.state !== 'active' && b.state !== 'dry_run')
  const policy = info?.policy

  const resultTags = (b: Block) => (
    <Space size={4} wrap>
      {b.results.map(r => (
        <Tag key={r.connector} color={r.released ? 'default' : r.ok ? 'success' : 'error'} title={r.error || ''}>
          {r.connector}{r.released ? ' 已解除' : r.ok ? '' : ' 失败'}
        </Tag>
      ))}
    </Space>
  )

  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">联动处置</div>
          <div className="page-heading__desc">把告警处置落到网关、WAF 和自动化平台上真正生效，到期自动解除，所有动作留痕审计。</div>
        </div>
        <Button icon={<ReloadOutlined />} onClick={load} loading={loading}>刷新</Button>
      </div>

      {policy?.dry_run && (
        <Alert type="warning" showIcon style={{ marginBottom: 12 }} message="当前是演练模式"
          description="封禁只会被记录，不会发送到任何联动系统。生产环境请取消 FLOWLENS_SOAR_DRY_RUN。" />
      )}
      {info && !info.enabled && (
        <Alert type="info" showIcon style={{ marginBottom: 12 }} message="还没有配置联动系统"
          description="告警里的“封禁”按钮暂时不可用。通过环境变量接入 Kong、APISIX、Nginx、阿里云 WAF 或通用 Webhook，详见 docs/SOAR.md。" />
      )}

      <Card title="联动系统" extra={policy && (
        <span className="muted">默认封禁 {policy.default_ttl_minutes} 分钟，最长 {policy.max_ttl_minutes} 分钟 · 每小时最多 {policy.max_blocks_per_hour} 次 · {policy.allow_private ? '允许封禁内网地址' : '不封禁内网地址'}</span>
      )}>
        <Table<ConnectorStatus>
          rowKey="name" size="middle" pagination={false} loading={loading}
          locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="未配置联动系统" /> }}
          dataSource={info?.connectors ?? []}
          columns={[
            { title: '系统', dataIndex: 'label', render: (v: string, c) => <Space><ApiOutlined />{v}{c.experimental && <Tag color="orange" title="尚未在真实环境验证，上线前请先测试并用演练模式联调">实验性</Tag>}</Space> },
            { title: '状态', dataIndex: 'status', width: 120, render: (v: string, c) => <Tag color={CONN_STATUS[v]?.color} title={c.error}>{CONN_STATUS[v]?.label}</Tag> },
            { title: '最近检测', dataIndex: 'last_checked', width: 140, render: (v?: string) => (v ? dayjs(v).fromNow() : <span className="muted">—</span>) },
            { title: '说明', dataIndex: 'error', render: (v?: string) => (v ? <span style={{ color: 'var(--fl-critical, #c9352b)' }}>{v}</span> : '') },
            { title: '生效封禁', dataIndex: 'active_blocks', width: 100, align: 'right' as const },
            { title: '', key: 'op', width: 110, render: (_: unknown, c) => canTest && <Button size="small" loading={testing === c.name} onClick={() => test(c)}>测试连接</Button> },
          ]}
        />
      </Card>

      <Card title={`生效中的封禁（${inForce.length}）`}>
        <Table<Block>
          rowKey="id" size="middle" pagination={{ pageSize: 8, hideOnSinglePage: true }} loading={loading}
          locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="当前没有生效的封禁" /> }}
          dataSource={inForce}
          columns={[
            { title: '地址', dataIndex: 'ip', width: 160, render: (v: string) => <span className="asset-path">{v}</span> },
            { title: '状态', dataIndex: 'state', width: 160, render: (v: string) => <Tag color={STATE[v]?.color}>{STATE[v]?.label}</Tag> },
            { title: '联动结果', key: 'results', render: (_: unknown, b) => resultTags(b) },
            { title: '原因', dataIndex: 'reason', ellipsis: true },
            { title: '来源告警', dataIndex: 'alert_id', width: 140, render: (v?: string) => (v ? <a onClick={() => onNavigate('alert-detail', v)}>{v.slice(0, 16)}</a> : '手动') },
            { title: '操作人', dataIndex: 'operator', width: 100 },
            { title: '到期', dataIndex: 'expires_at', width: 110, render: (v: string) => <span title={dayjs(v).format('YYYY-MM-DD HH:mm:ss')}>{dayjs(v).fromNow()}</span> },
            {
              title: '', key: 'op', width: 90,
              render: (_: unknown, b) => canHandle && (
                <Popconfirm title={`解除 ${b.ip} 的封禁？`} okText="解除" cancelText="取消" onConfirm={() => unblock(b.ip)}>
                  <Button size="small" icon={<UnlockOutlined />}>解封</Button>
                </Popconfirm>
              ),
            },
          ]}
        />
      </Card>

      {canHandle && (
        <Card title="手动封禁">
          <Form form={form} layout="inline" onFinish={submitBlock} initialValues={{ ttl_minutes: policy?.default_ttl_minutes ?? 60 }} style={{ rowGap: 12 }}>
            <Form.Item name="ip" rules={[{ required: true, message: '请输入 IP 地址' }]}>
              <Input placeholder="IP 地址，如 198.51.100.9" style={{ width: 220 }} />
            </Form.Item>
            <Form.Item name="ttl_minutes" label="时长（分钟）">
              <InputNumber min={1} max={policy?.max_ttl_minutes} style={{ width: 110 }} />
            </Form.Item>
            <Form.Item name="reason">
              <Input placeholder="原因（可选）" style={{ width: 240 }} maxLength={200} />
            </Form.Item>
            <Form.Item>
              <Popconfirm
                title="确认封禁？" description="封禁会立即在联动系统上生效，可能影响正常用户。" okText="封禁" cancelText="取消"
                disabled={!info?.enabled} onConfirm={() => form.submit()}
              >
                <Button type="primary" danger icon={<StopOutlined />} loading={submitting} disabled={!info?.enabled}>封禁</Button>
              </Popconfirm>
            </Form.Item>
          </Form>
          <div className="muted" style={{ marginTop: 8 }}>不会封禁内网、回环和受保护网段的地址。</div>
        </Card>
      )}

      <Card title="历史记录">
        <Table<Block>
          rowKey="id" size="small" pagination={{ pageSize: 8, hideOnSinglePage: true }} loading={loading}
          locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无历史" /> }}
          dataSource={history}
          columns={[
            { title: '地址', dataIndex: 'ip', width: 160, render: (v: string) => <span className="asset-path">{v}</span> },
            { title: '结果', dataIndex: 'state', width: 120, render: (v: string) => <Tag color={STATE[v]?.color}>{STATE[v]?.label}</Tag> },
            { title: '联动结果', key: 'results', render: (_: unknown, b) => resultTags(b) },
            { title: '时间', dataIndex: 'created_at', width: 170, render: (v: string) => dayjs(v).format('MM-DD HH:mm:ss') },
            { title: '解除', key: 'rel', width: 190, render: (_: unknown, b) => (b.released_at ? `${dayjs(b.released_at).format('MM-DD HH:mm')} · ${b.released_by === 'system' ? '到期自动' : b.released_by}` : '') },
          ]}
        />
      </Card>
    </div>
  )
}
