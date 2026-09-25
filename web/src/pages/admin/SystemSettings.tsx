import { useEffect, useState } from 'react'
import { Alert, Card, Descriptions, Tag, message } from 'antd'
import { adminService } from '../../services/admin'
import { errorMessage } from '../../services/http'

export default function SystemSettings() {
  const [info, setInfo] = useState<any>(null)

  useEffect(() => {
    adminService.systemInfo().then(setInfo).catch(err => message.error(errorMessage(err)))
  }, [])

  const ingest = info?.ingest || {}

  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">系统设置</div>
          <div className="page-heading__desc">平台运行状态、存储和安全配置概览。部署参数通过环境变量设置，详见 README 的“安全配置”一节。</div>
        </div>
      </div>

      {info && info.storage !== 'postgresql' && (
        <Alert type="error" showIcon message="当前使用内存存储"
          description="账号、会话和审计日志在平台重启后会丢失，不满足审计日志留存要求。生产环境请配置 FLOWLENS_DB_DSN 使用 PostgreSQL。" />
      )}
      {info && !info.secure_cookie && (
        <Alert type="warning" showIcon message="会话 Cookie 未启用 Secure 标记"
          description="控制台通过 HTTPS 访问时，请设置 FLOWLENS_COOKIE_SECURE=true（平台直接配置 TLS 证书时会自动启用）。" />
      )}

      <Card title="平台信息">
        <Descriptions column={{ xs: 1, md: 2 }} bordered size="small">
          <Descriptions.Item label="版本">{info?.version || '—'}</Descriptions.Item>
          <Descriptions.Item label="数据存储">{info?.storage === 'postgresql' ? <Tag color="success">PostgreSQL</Tag> : <Tag color="error">内存（仅限开发）</Tag>}</Descriptions.Item>
          <Descriptions.Item label="会话 Cookie">{info?.secure_cookie ? <Tag color="success">HttpOnly · Secure · SameSite=Strict</Tag> : <Tag color="warning">HttpOnly · SameSite=Strict（未启用 Secure）</Tag>}</Descriptions.Item>
          <Descriptions.Item label="运行模式">{info?.demo_mode ? <Tag color="error">演示模式（无登录）</Tag> : <Tag color="success">正式</Tag>}</Descriptions.Item>
        </Descriptions>
      </Card>

      <Card title="流量接入">
        <Descriptions column={{ xs: 1, md: 3 }} bordered size="small">
          <Descriptions.Item label="已接收事件">{(ingest.accepted || 0).toLocaleString()}</Descriptions.Item>
          <Descriptions.Item label="已处理事件">{(ingest.processed || 0).toLocaleString()}</Descriptions.Item>
          <Descriptions.Item label="丢弃事件">{(ingest.dropped || 0).toLocaleString()}</Descriptions.Item>
          <Descriptions.Item label="重复事件">{(ingest.duplicates || 0).toLocaleString()}</Descriptions.Item>
          <Descriptions.Item label="队列水位">{(ingest.queue_depth || 0).toLocaleString()} / {(ingest.queue_size || 0).toLocaleString()}</Descriptions.Item>
        </Descriptions>
      </Card>

      <Card title="单点登录（SSO）">
        <div className="muted">SAML 2.0 / OIDC 对接规划在后续版本提供。接入后仍按本平台的角色进行授权，并保留本地审计。</div>
      </Card>
    </div>
  )
}
