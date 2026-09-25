import { Suspense, useState } from 'react'
import type { ReactNode } from 'react'
import { Avatar, Breadcrumb, Button, Form, Input, Layout, Menu, Modal, Select, Space, Spin, Tag, message } from 'antd'
import { KeyOutlined, LogoutOutlined } from '@ant-design/icons'
import { useSession } from '../context/session'
import { DEMO, errorMessage } from '../services/http'
import { ROLE_NAMES, authService } from '../services/auth'
import type { Role } from '../services/auth'

export interface ShellMenuItem {
  key: string
  icon: ReactNode
  label: string
}

interface Props {
  variant: 'security' | 'admin'
  brandIcon: ReactNode
  brandSub: string
  menuItems: ShellMenuItem[]
  activeKey: string
  onNavigate: (key: string) => void
  breadcrumb: { title: ReactNode }[]
  headerExtra?: ReactNode
  children: ReactNode
}

export default function ConsoleShell(props: Props) {
  const { session, logout, switchDemoRole } = useSession()
  const [collapsed, setCollapsed] = useState(false)
  const [pwOpen, setPwOpen] = useState(false)
  const [pwLoading, setPwLoading] = useState(false)
  const [form] = Form.useForm()
  const user = session?.user

  const changePassword = async () => {
    const v = await form.validateFields()
    setPwLoading(true)
    try {
      await authService.changePassword(v.old, v.next)
      message.success('口令已修改，其他设备上的登录已退出')
      setPwOpen(false)
      form.resetFields()
    } catch (err) {
      message.error(errorMessage(err))
    } finally {
      setPwLoading(false)
    }
  }

  return (
    <Layout className={`flow-shell flow-shell--${props.variant}`}>
      <Layout.Sider collapsed={collapsed} onCollapse={setCollapsed} collapsible width={248} className="flow-sider">
        <div className="flow-brand">
          <div className="flow-brand__mark">{props.brandIcon}</div>
          {!collapsed && (
            <div>
              <div className="flow-brand__name">FlowLens</div>
              <div className="flow-brand__sub">{props.brandSub}</div>
            </div>
          )}
        </div>
        <Menu
          mode="inline"
          selectedKeys={[props.activeKey]}
          className="flow-menu"
          onClick={({ key }) => props.onNavigate(String(key))}
          items={props.menuItems.map(({ key, icon, label }) => ({ key, icon, label }))}
        />
        <div className="flow-user">
          {!collapsed && user && (
            <>
              <Space align="center">
                <Avatar size={32}>{(user.display_name || user.username).slice(0, 1).toUpperCase()}</Avatar>
                <div>
                  <div className="flow-user__name">{user.display_name || user.username}</div>
                  <div className="flow-user__role">{user.role_name || ROLE_NAMES[user.role]} · {user.username}</div>
                </div>
              </Space>
              <Space.Compact block>
                {!DEMO && <Button size="small" icon={<KeyOutlined />} onClick={() => setPwOpen(true)} style={{ width: '50%' }}>修改口令</Button>}
                <Button size="small" icon={<LogoutOutlined />} onClick={logout} style={{ width: DEMO ? '100%' : '50%' }}>退出登录</Button>
              </Space.Compact>
            </>
          )}
        </div>
      </Layout.Sider>
      <Layout>
        <Layout.Header className="flow-header">
          <Breadcrumb items={props.breadcrumb} />
          <Space size={12} wrap>
            {DEMO && (
              <Space size={6}>
                <Tag color="blue">在线演示 · 示例数据</Tag>
                <Select
                  size="small"
                  value={user?.role}
                  onChange={(r: Role) => switchDemoRole(r)}
                  style={{ width: 150 }}
                  aria-label="切换演示身份"
                  options={(Object.keys(ROLE_NAMES) as Role[]).map(r => ({ value: r, label: `演示身份：${ROLE_NAMES[r]}` }))}
                />
              </Space>
            )}
            {props.headerExtra}
            <span className="flow-version">v0.7.0</span>
          </Space>
        </Layout.Header>
        <Layout.Content className="flow-content">
          <Suspense fallback={<div className="flow-page-loading"><Spin size="large" /></div>}>
            {props.children}
          </Suspense>
        </Layout.Content>
      </Layout>

      <Modal title="修改口令" open={pwOpen} onOk={changePassword} confirmLoading={pwLoading}
        onCancel={() => { setPwOpen(false); form.resetFields() }} okText="修改" cancelText="取消" destroyOnClose>
        <Form form={form} layout="vertical" autoComplete="off">
          <Form.Item label="当前口令" name="old" rules={[{ required: true, message: '请输入当前口令' }]}>
            <Input.Password autoComplete="current-password" />
          </Form.Item>
          <Form.Item label="新口令" name="next" rules={[{ required: true, message: '请输入新口令' }]}
            extra="至少 8 位，包含大写字母、小写字母、数字、特殊字符中的至少 3 类，不能与最近使用过的口令相同">
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item label="确认新口令" name="confirm" dependencies={['next']} rules={[
            { required: true, message: '请再次输入新口令' },
            ({ getFieldValue }) => ({ validator: (_, v) => (v === getFieldValue('next') ? Promise.resolve() : Promise.reject(new Error('两次输入的口令不一致'))) }),
          ]}>
            <Input.Password autoComplete="new-password" />
          </Form.Item>
        </Form>
      </Modal>
    </Layout>
  )
}
