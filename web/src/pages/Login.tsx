import { useState } from 'react'
import { Card, Form, Input, Button, Typography, Message } from '@arco-design/web-react'
import { IconUser, IconLock, IconEye } from '@arco-design/web-react/icon'

const FormItem = Form.Item

const API_BASE = '/api/v1'

export default function Login({ onLogin }: { onLogin: (token: string, user: string, role: string) => void }) {
  const [loading, setLoading] = useState(false)
  const [form] = Form.useForm()

  const handleSubmit = async (values: any) => {
    setLoading(true)
    try {
      const resp = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(values),
      })
      if (!resp.ok) { Message.error('登录失败，请检查用户名和密码'); return }
      const data = await resp.json()
      localStorage.setItem('flowlens_token', data.token)
      localStorage.setItem('flowlens_user', data.user)
      localStorage.setItem('flowlens_role', data.role)
      onLogin(data.token, data.user, data.role)
      Message.success(`欢迎回来，${data.user}`)
    } catch { Message.error('连接服务器失败') }
    finally { setLoading(false) }
  }

  return (
    <div style={{ minHeight: '100vh', background: '#0B1420', display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
      <div style={{ position: 'relative', overflow: 'hidden', width: 420, background: '#101B2D', border: '1px solid #25344A', borderRadius: 4, padding: 40 }}>
        <div className="sweep-scan" style={{ position: 'absolute', inset: 0, pointerEvents: 'none' }} />
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <IconEye style={{ fontSize: 48, color: '#3FBDAA' }} />
          <div style={{ color: '#EDEAE0', fontWeight: 700, fontSize: 22, marginTop: 16 }}>拂尘 FlowLens</div>
          <div style={{ color: '#8A93A3', fontSize: 13, marginTop: 4 }}>API 安全旁路风险监测平台</div>
        </div>
        <Form form={form} onSubmit={handleSubmit} size="large" layout="vertical">
          <FormItem field="username" rules={[{ required: true, message: '请输入用户名' }]}>
            <Input prefix={<IconUser />} placeholder="用户名" style={{ background: '#0B1420', border: '1px solid #25344A' }} />
          </FormItem>
          <FormItem field="password" rules={[{ required: true, message: '请输入密码' }]}>
            <Input.Password prefix={<IconLock />} placeholder="密码" style={{ background: '#0B1420', border: '1px solid #25344A' }} />
          </FormItem>
          <FormItem>
            <Button type="primary" htmlType="submit" loading={loading} long style={{ background: '#0F6E56', border: 'none' }}>
              登录
            </Button>
          </FormItem>
        </Form>
      </div>
    </div>
  )
}
