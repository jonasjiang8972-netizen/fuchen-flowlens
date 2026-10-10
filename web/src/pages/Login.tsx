import { useState } from 'react'
import { Alert, Button, Form, Input } from '@arco-design/web-react'
import { IconEye, IconLock, IconSafe, IconUser } from '@arco-design/web-react/icon'
import { useSession } from '../context/session'
import { errorMessage } from '../services/http'

const FormItem = Form.Item

export default function Login() {
  const { login, completeMfaLogin, notice } = useSession()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  // Set once the password passed and the account needs its second factor.
  const [mfaToken, setMfaToken] = useState('')
  const [form] = Form.useForm()
  const [codeForm] = Form.useForm()

  const handleSubmit = async (values: { username: string; password: string }) => {
    setLoading(true)
    setError('')
    try {
      const token = await login(values.username.trim(), values.password)
      if (token) setMfaToken(token)
    } catch (err) {
      setError(errorMessage(err))
      form.setFieldValue('password', '')
    } finally {
      setLoading(false)
    }
  }

  const handleCode = async (values: { code: string }) => {
    setLoading(true)
    setError('')
    try {
      await completeMfaLogin(mfaToken, values.code.trim())
    } catch (err) {
      const msg = errorMessage(err)
      setError(msg)
      codeForm.setFieldValue('code', '')
      // An expired or used-up challenge, or a lock, means starting over.
      if (!msg.includes('动态验证码错误')) {
        setMfaToken('')
        form.setFieldValue('password', '')
      }
    } finally {
      setLoading(false)
    }
  }

  const restart = () => {
    setMfaToken('')
    setError('')
    form.setFieldValue('password', '')
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
        {mfaToken ? (
          <Form form={codeForm} onSubmit={handleCode} size="large" layout="vertical" autoComplete="off">
            <div className="auth-card__foot" style={{ marginTop: 0, marginBottom: 12 }}>该账号已启用双因素认证，请输入身份验证器上的 6 位动态验证码。</div>
            <FormItem field="code" rules={[{ required: true, match: /^\d{6}$/, message: '请输入 6 位数字验证码' }]}>
              <Input prefix={<IconSafe />} placeholder="动态验证码" autoComplete="one-time-code" inputMode="numeric" maxLength={6} autoFocus />
            </FormItem>
            <FormItem>
              <Button type="primary" htmlType="submit" loading={loading} long>验证并登录</Button>
            </FormItem>
            <Button type="text" long onClick={restart}>返回重新输入口令</Button>
          </Form>
        ) : (
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
        )}
        <div className="auth-card__foot">登录后按账号角色进入 API 安全管理平台或系统管理后台。连续多次输错口令将锁定账号。</div>
      </div>
    </div>
  )
}
