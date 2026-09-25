import { useState } from 'react'
import { Alert, Button, Form, Input } from '@arco-design/web-react'
import { IconLock } from '@arco-design/web-react/icon'
import { useSession } from '../context/session'
import { authService } from '../services/auth'
import { errorMessage } from '../services/http'

const FormItem = Form.Item

// Shown when the account still has its initial password or the password
// has expired. Nothing else is reachable until it is changed.
export default function ChangePassword() {
  const { session, refresh, logout } = useSession()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [form] = Form.useForm()
  const p = session?.policy

  const rules = p
    ? [`至少 ${p.password_min_length} 位`, `包含大写字母、小写字母、数字、特殊字符中的至少 ${p.password_min_classes} 类`,
      '不能包含用户名', `不能与最近 ${p.password_history} 次使用过的口令相同`, `每 ${p.password_max_age_days} 天须更换一次`]
    : ['至少 8 位，包含大写字母、小写字母、数字、特殊字符中的至少 3 类']

  const handleSubmit = async (v: { old: string; next: string; confirm: string }) => {
    setError('')
    setLoading(true)
    try {
      await authService.changePassword(v.old, v.next)
      await refresh()
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="auth-screen">
      <div className="auth-card">
        <div className="auth-card__head">
          <IconLock style={{ fontSize: 40, color: '#E6A23C' }} />
          <div className="auth-card__title">请先修改口令</div>
          <div className="auth-card__sub">
            {session?.user.display_name || session?.user.username}，您的口令是初始口令或已过期，修改后才能继续使用。
          </div>
        </div>
        <ul className="auth-rules">{rules.map(r => <li key={r}>{r}</li>)}</ul>
        {error && <Alert type="error" content={error} style={{ marginBottom: 16 }} />}
        <Form form={form} onSubmit={handleSubmit} layout="vertical" autoComplete="off">
          <FormItem label="当前口令" field="old" rules={[{ required: true, message: '请输入当前口令' }]}>
            <Input.Password autoComplete="current-password" />
          </FormItem>
          <FormItem label="新口令" field="next" rules={[{ required: true, message: '请输入新口令' }]}>
            <Input.Password autoComplete="new-password" />
          </FormItem>
          <FormItem label="确认新口令" field="confirm" rules={[
            { required: true, message: '请再次输入新口令' },
            { validator: (v, cb) => (v !== form.getFieldValue('next') ? cb('两次输入的口令不一致') : cb()) },
          ]}>
            <Input.Password autoComplete="new-password" />
          </FormItem>
          <FormItem>
            <Button type="primary" htmlType="submit" loading={loading} long>修改口令</Button>
          </FormItem>
        </Form>
        <Button type="text" long onClick={logout}>退出登录</Button>
      </div>
    </div>
  )
}
