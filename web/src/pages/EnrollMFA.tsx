import { Button } from 'antd'
import { SafetyCertificateOutlined } from '@ant-design/icons'
import { useSession } from '../context/session'
import MfaEnroll from '../components/MfaEnroll'

// Shown when the security policy requires the account's role to use
// two-factor authentication and no authenticator is bound yet. Nothing else
// is reachable until it is.
export default function EnrollMFA() {
  const { session, refresh, logout } = useSession()
  return (
    <div className="auth-screen">
      <div className="auth-card">
        <div className="auth-card__head">
          <SafetyCertificateOutlined style={{ fontSize: 40, color: '#E6A23C' }} />
          <div className="auth-card__title">请绑定双因素认证</div>
          <div className="auth-card__sub">
            {session?.user.display_name || session?.user.username}，安全策略要求管理员登录时使用口令加动态验证码，绑定后才能继续使用。
          </div>
        </div>
        <MfaEnroll onDone={refresh} />
        <Button type="link" block onClick={logout} style={{ marginTop: 12, color: '#8fa3bf' }}>退出登录</Button>
      </div>
    </div>
  )
}
