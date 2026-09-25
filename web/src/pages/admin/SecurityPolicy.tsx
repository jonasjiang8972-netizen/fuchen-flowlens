import { useEffect, useState } from 'react'
import { Alert, Button, Card, Form, InputNumber, Space, message } from 'antd'
import { adminService } from '../../services/admin'
import type { Policy } from '../../services/auth'
import { DEMO, errorMessage } from '../../services/http'

type Field = { name: keyof Policy; label: string; min: number; max: number; unit: string; help: string }

// Ranges mirror the platform's compliance floors (iam.Policy.Validate); the
// platform rejects anything outside them regardless of this form.
const groups: { title: string; basis: string; fields: Field[] }[] = [
  {
    title: '口令策略', basis: 'GB/T 22239-2019 8.1.4.1 a）',
    fields: [
      { name: 'password_min_length', label: '最小长度', min: 8, max: 64, unit: '位', help: '不少于 8 位' },
      { name: 'password_min_classes', label: '字符类别', min: 3, max: 4, unit: '类', help: '大写字母、小写字母、数字、特殊字符中至少包含几类' },
      { name: 'password_history', label: '禁止重复使用', min: 3, max: 24, unit: '次', help: '不能与最近几次用过的口令相同' },
      { name: 'password_max_age_days', label: '有效期', min: 1, max: 90, unit: '天', help: '到期后登录时强制修改，最长 90 天' },
    ],
  },
  {
    title: '登录失败处理', basis: 'GB/T 22239-2019 8.1.4.1 b）',
    fields: [
      { name: 'lockout_threshold', label: '锁定阈值', min: 3, max: 10, unit: '次', help: '连续输错口令达到此次数即锁定账号' },
      { name: 'lockout_minutes', label: '锁定时长', min: 10, max: 1440, unit: '分钟', help: '锁定期满自动解锁，系统管理员也可手动解锁' },
      { name: 'login_rate_per_ip_minute', label: '单 IP 登录频率', min: 5, max: 600, unit: '次/分钟', help: '同一来源 IP 每分钟最多尝试登录的次数' },
    ],
  },
  {
    title: '会话与账号', basis: 'GB/T 22239-2019 8.1.4.1 b）、8.1.4.2 c）',
    fields: [
      { name: 'session_idle_minutes', label: '空闲超时', min: 5, max: 30, unit: '分钟', help: '无操作超过此时间自动退出登录' },
      { name: 'session_max_hours', label: '会话最长有效期', min: 1, max: 12, unit: '小时', help: '无论是否活跃，到期必须重新登录' },
      { name: 'account_inactive_days', label: '长期未登录停用', min: 0, max: 365, unit: '天', help: '超过此天数未登录的账号自动停用；0 表示关闭（开启时须 30–365）' },
    ],
  },
  {
    title: '审计', basis: '《网络安全法》第二十一条',
    fields: [
      { name: 'audit_retention_days', label: '审计日志保留期', min: 180, max: 3650, unit: '天', help: '不少于 180 天（六个月）；到期记录每日自动清理' },
    ],
  },
]

export default function SecurityPolicy() {
  const [form] = Form.useForm<Policy>()
  const [defaults, setDefaults] = useState<Policy | null>(null)
  const [saving, setSaving] = useState(false)

  const load = () => adminService.policy()
    .then(r => { form.setFieldsValue(r.policy); setDefaults(r.defaults) })
    .catch(err => message.error(errorMessage(err)))
  useEffect(() => { load() }, [])

  const save = async () => {
    const values = await form.validateFields()
    if (DEMO) { message.info('演示环境不会保存修改'); return }
    setSaving(true)
    try {
      await adminService.updatePolicy(values)
      message.success('安全策略已更新，已记录到审计日志')
    } catch (err) {
      message.error(errorMessage(err))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">安全策略</div>
          <div className="page-heading__desc">平台自身的口令、登录、会话和审计策略。取值不能低于合规下限，每次修改都会记录修改前后的值。</div>
        </div>
        <Space>
          {defaults && <Button onClick={() => form.setFieldsValue(defaults)}>恢复默认值</Button>}
          <Button type="primary" loading={saving} onClick={save}>保存</Button>
        </Space>
      </div>

      <Alert type="info" showIcon message="修改后约 30 秒内在所有平台实例生效。已登录的会话按新的超时设置计算。" />

      <Form form={form} layout="vertical">
        <div className="policy-grid">
          {groups.map(g => (
            <Card key={g.title} title={g.title} extra={<span className="muted" style={{ fontSize: 12 }}>{g.basis}</span>}>
              {g.fields.map(f => (
                <Form.Item key={f.name} name={f.name} label={f.label} extra={f.help}
                  rules={[
                    { required: true, message: `请输入${f.label}` },
                    { type: 'number', min: f.min, max: f.max, message: `须在 ${f.min}–${f.max} 之间` },
                    ...(f.name === 'account_inactive_days' ? [{
                      validator: (_: unknown, v: number) => (v === 0 || (v >= 30 && v <= 365) ? Promise.resolve() : Promise.reject(new Error('须为 0 或 30–365'))),
                    }] : []),
                  ]}>
                  <InputNumber min={f.min} max={f.max} addonAfter={f.unit} style={{ width: '100%' }} />
                </Form.Item>
              ))}
            </Card>
          ))}
        </div>
      </Form>
    </div>
  )
}
