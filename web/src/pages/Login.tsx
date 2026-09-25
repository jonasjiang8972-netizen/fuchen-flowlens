import { useState } from 'react'
import { Alert, Button, Form, Input } from '@arco-design/web-react'
import { IconEye, IconLock, IconUser } from '@arco-design/web-react/icon'
import { useSession } from '../context/session'
import { errorMessage } from '../services/http'

const FormItem = Form.Item

export default function Login() {
  const { login, notice } = useSession()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [form] = Form.useForm()

  const handleSubmit = async (values: { username: string; password: string }) => {
    setLoading(true)
    setError('')
    try {
      await login(values.username.trim(), values.password)
    } catch (err) {
      setError(errorMessage(err))
      form.setFieldValue('password', '')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="auth-screen">
      <div className="auth-card">
        <div className="sweep-scan" style={{ position: 'absolute', inset: 0, pointerEvents: 'none' }} />
        <div className="auth-card__head">
          <IconEye style={{ fontSize: 44, color: '#3FBDAA' }} />
          <div className="auth-card__title">拂尘 FlowLens</div>
          <div className="auth-card__sub">API 安全管理平台 · 系统管理后台</div>
        </div>
        {notice && !error && <Alert type="warning" content={notice} style={{ marginBottom: 16 }} />}
        {error && <Alert type="error" content={error} style={{ marginBottom: 16 }} />}
        <Form form={form} onSubmit={handleSubmit} size="large" layout="vertical" autoComplete="off">
          <FormItem field="username" rules={[{ required: true, message: '请输入用户名' }]}>
            <Input prefix={<IconUser />} placeholder="用户名" autoComplete="username" />
          </FormItem>
          <FormItem field="password" rules={[{ required: true, message: '请输入口令' }]}>
            <Input.Password prefix={<IconLock />} placeholder="口令" autoComplete="current-password" />
          </FormItem>
          <FormItem>
            <Button type="primary" htmlType="submit" loading={loading} long>登录</Button>
          </FormItem>
        </Form>
        <div className="auth-card__foot">登录后按账号角色进入 API 安全管理平台或系统管理后台。连续多次输错口令将锁定账号。</div>
      </div>
    </div>
  )
}
