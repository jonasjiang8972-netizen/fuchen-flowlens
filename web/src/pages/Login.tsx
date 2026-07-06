import { useState } from 'react'
import { Card, Form, Input, Button, Typography, message } from 'antd'
import { SafetyOutlined, UserOutlined, LockOutlined } from '@ant-design/icons'

const { Title } = Typography

const API_BASE = '/api/v1'

export default function Login({ onLogin }: { onLogin: (token: string, user: string, role: string) => void }) {
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (values: { username: string; password: string }) => {
    setLoading(true)
    try {
      const resp = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(values),
      })
      if (!resp.ok) {
        message.error('登录失败，请检查用户名和密码')
        return
      }
      const data = await resp.json()
      localStorage.setItem('flowlens_token', data.token)
      localStorage.setItem('flowlens_user', data.user)
      localStorage.setItem('flowlens_role', data.role)
      onLogin(data.token, data.user, data.role)
      message.success(`欢迎回来，${data.user}`)
    } catch {
      message.error('连接服务器失败')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ minHeight: '100vh', background: '#0A1929', display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
      <Card style={{ width: 420, background: '#132F4C', border: '1px solid #1E3A5F', borderRadius: 12 }}>
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <SafetyOutlined style={{ fontSize: 48, color: '#36CFC9' }} />
          <Title level={3} style={{ color: '#F0F4F8', marginTop: 16, marginBottom: 4 }}>拂尘 FlowLens</Title>
          <div style={{ color: '#94A3B8', fontSize: 14 }}>API 安全旁路风险监测平台</div>
        </div>
        <Form onFinish={handleSubmit} size="large">
          <Form.Item name="username" rules={[{ required: true, message: '请输入用户名' }]}>
            <Input prefix={<UserOutlined />} placeholder="用户名" style={{ background: '#0A1929', border: '1px solid #1E3A5F', color: '#F0F4F8' }} />
          </Form.Item>
          <Form.Item name="password" rules={[{ required: true, message: '请输入密码' }]}>
            <Input.Password prefix={<LockOutlined />} placeholder="密码" style={{ background: '#0A1929', border: '1px solid #1E3A5F', color: '#F0F4F8' }} />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit" loading={loading} block style={{ background: '#0D9373', borderColor: '#0D9373' }}>
              登录
            </Button>
          </Form.Item>
        </Form>
        <div style={{ textAlign: 'center', color: '#64748B', fontSize: 12 }}>
          演示账号: admin / admin123
        </div>
      </Card>
    </div>
  )
}
