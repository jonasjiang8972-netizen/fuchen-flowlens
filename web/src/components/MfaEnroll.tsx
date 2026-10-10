import { useEffect, useState } from 'react'
import { Alert, Button, Input, Space, Spin } from 'antd'
import QRCode from 'qrcode'
import { authService } from '../services/auth'
import type { MFASetup } from '../services/auth'
import { errorMessage } from '../services/http'

// Binds a TOTP authenticator app: shows the QR code and confirms with the
// first code. The secret takes effect only after confirmation.
export default function MfaEnroll({ onDone }: { onDone: () => void }) {
  const [setup, setSetup] = useState<MFASetup | null>(null)
  const [qr, setQr] = useState('')
  const [code, setCode] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    authService.mfaSetup()
      .then(async s => {
        setSetup(s)
        setQr(await QRCode.toDataURL(s.otpauth_uri, { width: 200, margin: 1 }))
      })
      .catch(err => setError(errorMessage(err)))
  }, [])

  const confirm = async () => {
    setError('')
    setLoading(true)
    try {
      await authService.mfaEnable(code.trim())
      onDone()
    } catch (err) {
      setError(errorMessage(err))
      setCode('')
    } finally {
      setLoading(false)
    }
  }

  if (!setup) return error ? <Alert type="error" message={error} /> : <div style={{ textAlign: 'center', padding: 24 }}><Spin /></div>

  return (
    <Space direction="vertical" size={12} style={{ width: '100%' }}>
      <div>1. 在手机上安装身份验证器（如 Microsoft Authenticator、Google Authenticator、FreeOTP 或企业微信/钉钉自带的验证器），扫描下方二维码。</div>
      <div style={{ textAlign: 'center' }}>
        {qr && <img src={qr} alt="双因素认证绑定二维码" width={200} height={200} style={{ background: '#fff', padding: 6, borderRadius: 6 }} />}
        <div className="muted" style={{ fontSize: 12, marginTop: 6 }}>无法扫码时手动输入密钥：</div>
        <div className="mono" style={{ wordBreak: 'break-all', userSelect: 'all' }}>{setup.secret.replace(/(.{4})/g, '$1 ').trim()}</div>
      </div>
      <div>2. 输入身份验证器显示的 6 位动态验证码完成绑定。</div>
      <Input
        value={code}
        onChange={e => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
        onPressEnter={() => code.length === 6 && confirm()}
        placeholder="6 位动态验证码"
        inputMode="numeric"
        autoComplete="one-time-code"
        maxLength={6}
        size="large"
        style={{ letterSpacing: 6, textAlign: 'center' }}
      />
      {error && <Alert type="error" message={error} />}
      <Button type="primary" block loading={loading} onClick={() => (code.length === 6 ? confirm() : setError('请输入 6 位数字验证码'))}>完成绑定</Button>
    </Space>
  )
}
