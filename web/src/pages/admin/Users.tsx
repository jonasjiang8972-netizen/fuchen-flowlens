import { useEffect, useMemo, useState } from 'react'
import { Alert, Button, Card, DatePicker, Form, Input, Modal, Popconfirm, Select, Space, Table, Tag, Tooltip, Typography, message } from 'antd'
import { PlusOutlined, ReloadOutlined, SearchOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import { adminService } from '../../services/admin'
import type { RoleInfo } from '../../services/admin'
import { ROLE_NAMES } from '../../services/auth'
import type { Role, UserView } from '../../services/auth'
import { DEMO, errorMessage } from '../../services/http'
import { useSession } from '../../context/session'

const roleColor: Record<Role, string> = {
  sys_admin: 'geekblue', audit_admin: 'purple', sec_admin: 'volcano', analyst: 'orange', viewer: 'default',
}

const fmt = (t?: string) => (t ? dayjs(t).format('YYYY-MM-DD HH:mm') : '—')

// generatePassword returns a random password meeting the default policy.
function generatePassword() {
  const sets = ['ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!@#%^*-_=+']
  const all = sets.join('')
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (b, i) => (i < sets.length ? sets[i] : all)[b % (i < sets.length ? sets[i].length : all.length)]).join('')
}

type Editing = { mode: 'create' } | { mode: 'edit'; user: UserView } | { mode: 'reset'; user: UserView } | null

export default function Users() {
  const { session } = useSession()
  const [users, setUsers] = useState<UserView[]>([])
  const [roles, setRoles] = useState<RoleInfo[]>([])
  const [loading, setLoading] = useState(false)
  const [keyword, setKeyword] = useState('')
  const [editing, setEditing] = useState<Editing>(null)
  const [saving, setSaving] = useState(false)
  const [issued, setIssued] = useState<{ username: string; password: string } | null>(null)
  const [form] = Form.useForm()

  const load = async () => {
    setLoading(true)
    try {
      const [u, r] = await Promise.all([adminService.users(), adminService.roles()])
      setUsers(u)
      setRoles(r)
    } catch (err) {
      message.error(errorMessage(err))
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => { load() }, [])

  const demoGuard = () => {
    if (DEMO) message.info('演示环境不会保存修改')
    return DEMO
  }

  const run = async (fn: () => Promise<unknown>, ok: string) => {
    if (demoGuard()) return
    try {
      await fn()
      message.success(ok)
      load()
    } catch (err) {
      message.error(errorMessage(err))
    }
  }

  const openCreate = () => {
    form.resetFields()
    form.setFieldsValue({ role: 'analyst', password: generatePassword() })
    setEditing({ mode: 'create' })
  }
  const openEdit = (user: UserView) => {
    form.resetFields()
    form.setFieldsValue({ display_name: user.display_name, email: user.email, role: user.role, expires_at: user.expires_at ? dayjs(user.expires_at) : null })
    setEditing({ mode: 'edit', user })
  }
  const openReset = (user: UserView) => {
    form.resetFields()
    form.setFieldsValue({ password: generatePassword() })
    setEditing({ mode: 'reset', user })
  }

  const submit = async () => {
    const v = await form.validateFields()
    if (!editing || demoGuard()) { setEditing(null); return }
    setSaving(true)
    try {
      const expires = v.expires_at ? dayjs(v.expires_at).endOf('day').toISOString() : null
      if (editing.mode === 'create') {
        await adminService.createUser({ username: v.username, display_name: v.display_name || '', email: v.email || '', role: v.role, expires_at: expires, password: v.password })
        setIssued({ username: v.username, password: v.password })
      } else if (editing.mode === 'edit') {
        await adminService.updateUser(editing.user.id, { display_name: v.display_name || '', email: v.email || '', role: v.role, expires_at: expires })
        message.success('已保存')
      } else {
        await adminService.resetPassword(editing.user.id, v.password)
        setIssued({ username: editing.user.username, password: v.password })
      }
      setEditing(null)
      load()
    } catch (err) {
      message.error(errorMessage(err))
    } finally {
      setSaving(false)
    }
  }

  const filtered = useMemo(() => {
    const kw = keyword.trim().toLowerCase()
    return kw ? users.filter(u => [u.username, u.display_name, u.email].some(v => (v || '').toLowerCase().includes(kw))) : users
  }, [users, keyword])

  const counts = useMemo(() => ({
    total: users.length,
    locked: users.filter(u => u.locked).length,
    disabled: users.filter(u => u.status === 'disabled').length,
    mustChange: users.filter(u => u.must_change_password).length,
  }), [users])

  const statusTags = (u: UserView) => (
    <Space size={4} wrap>
      {u.status === 'disabled' ? <Tag color="default">已停用</Tag> : <Tag color="success">启用</Tag>}
      {u.locked && <Tooltip title={`锁定至 ${fmt(u.locked_until)}`}><Tag color="error">已锁定</Tag></Tooltip>}
      {u.must_change_password && <Tag color="warning">须改口令</Tag>}
      {u.expires_at && dayjs(u.expires_at).isBefore(dayjs()) && <Tag color="default">已过期</Tag>}
    </Space>
  )

  const columns = [
    {
      title: '账号', key: 'user', render: (_: unknown, u: UserView) => (
        <Space direction="vertical" size={0}>
          <span style={{ fontWeight: 600 }}>{u.display_name || u.username}{u.id === session?.user.id && <Tag style={{ marginLeft: 6 }}>当前账号</Tag>}</span>
          <span className="muted mono">{u.username}{u.email ? ` · ${u.email}` : ''}</span>
        </Space>
      ),
    },
    { title: '角色', dataIndex: 'role', key: 'role', width: 130, render: (r: Role) => <Tag color={roleColor[r]}>{ROLE_NAMES[r] || r}</Tag> },
    { title: '进入', dataIndex: 'console', key: 'console', width: 120, render: (c: string) => (c === 'admin' ? '系统管理后台' : 'API 安全平台') },
    { title: '状态', key: 'status', width: 190, render: (_: unknown, u: UserView) => statusTags(u) },
    {
      title: '最后登录', key: 'last', width: 170, render: (_: unknown, u: UserView) => (
        <Space direction="vertical" size={0}>
          <span>{u.last_login_at ? fmt(u.last_login_at) : '从未登录'}</span>
          {u.last_login_ip && <span className="muted mono">{u.last_login_ip}</span>}
        </Space>
      ),
    },
    { title: '账号有效期', dataIndex: 'expires_at', key: 'expires', width: 130, render: (t?: string) => (t ? dayjs(t).format('YYYY-MM-DD') : '长期') },
    {
      title: '操作', key: 'actions', width: 260, render: (_: unknown, u: UserView) => {
        const self = u.id === session?.user.id
        return (
          <Space size={0} wrap>
            <Button type="link" size="small" onClick={() => openEdit(u)}>编辑</Button>
            <Button type="link" size="small" disabled={self} onClick={() => openReset(u)}>重置口令</Button>
            {u.locked && <Button type="link" size="small" onClick={() => run(() => adminService.userAction(u.id, 'unlock'), '已解锁')}>解锁</Button>}
            {u.status === 'active' ? (
              <Popconfirm title={`停用 ${u.username}？`} description="停用后该账号立即退出登录，且不能再登录。" disabled={self}
                onConfirm={() => run(() => adminService.userAction(u.id, 'disable'), '已停用')} okText="停用" cancelText="取消">
                <Button type="link" size="small" danger disabled={self}>停用</Button>
              </Popconfirm>
            ) : (
              <Button type="link" size="small" onClick={() => run(() => adminService.userAction(u.id, 'enable'), '已启用')}>启用</Button>
            )}
            <Popconfirm title={`删除 ${u.username}？`} description="删除后无法恢复，其历史操作仍保留在审计日志中。" disabled={self}
              onConfirm={() => run(() => adminService.deleteUser(u.id), '已删除')} okText="删除" okButtonProps={{ danger: true }} cancelText="取消">
              <Button type="link" size="small" danger disabled={self}>删除</Button>
            </Popconfirm>
          </Space>
        )
      },
    },
  ]

  const selectedRole = Form.useWatch('role', form) as Role | undefined
  const roleInfo = roles.find(r => r.role === selectedRole)

  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">用户管理</div>
          <div className="page-heading__desc">为每位操作人员建立独立账号，按职责分配唯一角色。新账号和重置后的口令须在首次登录时修改；账号停用、角色变更后立即退出登录。</div>
        </div>
        <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>新建账号</Button>
      </div>

      <div className="metric-grid">
        <Card className="metric-card"><div className="metric-card__label">账号总数</div><div className="metric-card__value">{counts.total}</div><div className="metric-card__meta">每人一个账号，禁止共用</div></Card>
        <Card className="metric-card"><div className="metric-card__label">锁定中</div><div className="metric-card__value" style={{ color: counts.locked ? 'var(--fl-critical)' : undefined }}>{counts.locked}</div><div className="metric-card__meta">连续登录失败触发</div></Card>
        <Card className="metric-card"><div className="metric-card__label">已停用</div><div className="metric-card__value">{counts.disabled}</div><div className="metric-card__meta">含长期未登录自动停用</div></Card>
        <Card className="metric-card"><div className="metric-card__label">待修改初始口令</div><div className="metric-card__value">{counts.mustChange}</div><div className="metric-card__meta">修改前不能进行任何操作</div></Card>
      </div>

      <Card title={`账号列表 (${filtered.length})`}>
        <div className="filter-bar">
          <Input allowClear prefix={<SearchOutlined />} placeholder="搜索用户名、姓名、邮箱" value={keyword} onChange={e => setKeyword(e.target.value)} style={{ width: 240, maxWidth: '100%' }} />
          <Button icon={<ReloadOutlined />} onClick={load}>刷新</Button>
        </div>
        <Table rowKey="id" columns={columns} dataSource={filtered} loading={loading} pagination={{ pageSize: 20 }} scroll={{ x: 1100 }} />
      </Card>

      <Modal
        open={!!editing}
        title={editing?.mode === 'create' ? '新建账号' : editing?.mode === 'edit' ? `编辑账号：${editing.user.username}` : editing?.mode === 'reset' ? `重置口令：${editing.user.username}` : ''}
        onOk={submit}
        confirmLoading={saving}
        onCancel={() => setEditing(null)}
        okText={editing?.mode === 'reset' ? '重置' : '保存'}
        cancelText="取消"
        destroyOnClose
        width={560}
      >
        <Form form={form} layout="vertical" autoComplete="off">
          {editing?.mode === 'create' && (
            <Form.Item label="用户名" name="username" rules={[
              { required: true, message: '请输入用户名' },
              { pattern: /^[A-Za-z0-9._-]{3,32}$/, message: '3–32 位字母、数字或 . _ -' },
            ]}>
              <Input placeholder="例如 zhang.wei" />
            </Form.Item>
          )}
          {editing?.mode !== 'reset' && (
            <>
              <Form.Item label="姓名" name="display_name" rules={[{ max: 64, message: '不超过 64 个字符' }]}><Input /></Form.Item>
              <Form.Item label="邮箱" name="email" rules={[{ type: 'email', message: '邮箱格式不正确' }]}><Input /></Form.Item>
              <Form.Item label="角色" name="role" rules={[{ required: true, message: '请选择角色' }]}
                extra={editing?.mode === 'edit' && editing.user.id === session?.user.id ? '不能修改自己的角色' : roleInfo?.description}>
                <Select
                  disabled={editing?.mode === 'edit' && editing.user.id === session?.user.id}
                  options={roles.map(r => ({ value: r.role, label: `${r.name}（${r.console === 'admin' ? '系统管理后台' : 'API 安全平台'}）` }))}
                />
              </Form.Item>
              <Form.Item label="账号有效期" name="expires_at" extra="外包、临时人员请设置到期日；到期后自动不能登录。留空表示长期有效。">
                <DatePicker style={{ width: '100%' }} disabledDate={d => d.isBefore(dayjs().startOf('day'))} />
              </Form.Item>
            </>
          )}
          {editing?.mode !== 'edit' && (
            <Form.Item label={editing?.mode === 'reset' ? '新的临时口令' : '初始口令'} required
              extra="已按口令策略随机生成。请通过安全渠道交给本人，首次登录时必须修改。">
              <Space.Compact style={{ width: '100%' }}>
                <Form.Item name="password" noStyle rules={[{ required: true, message: '请输入口令' }, { min: 8, message: '至少 8 位' }]}>
                  <Input className="mono" />
                </Form.Item>
                <Button onClick={() => form.setFieldValue('password', generatePassword())}>重新生成</Button>
              </Space.Compact>
            </Form.Item>
          )}
          {editing?.mode === 'reset' && <Alert type="warning" showIcon message="重置后该账号所有登录立即失效。" />}
        </Form>
      </Modal>

      <Modal open={!!issued} title="请记录临时口令" onOk={() => setIssued(null)} onCancel={() => setIssued(null)}
        okText="我已记录" cancelButtonProps={{ style: { display: 'none' } }}>
        {issued && (
          <Space direction="vertical" style={{ width: '100%' }}>
            <span>账号 <b>{issued.username}</b> 的临时口令如下，关闭后将不再显示：</span>
            <Typography.Paragraph copyable className="mono" style={{ fontSize: 16, margin: 0 }}>{issued.password}</Typography.Paragraph>
            <Alert type="info" showIcon message="本人首次登录时须修改该口令。" />
          </Space>
        )}
      </Modal>
    </div>
  )
}
