import { Card, Table, Tag, Tabs, Typography } from '@arco-design/web-react'

const mockUsers = [
  { username: 'admin', email: 'admin@flowlens.io', role: 'super_admin', status: 'active', lastLogin: '刚刚' },
  { username: 'sec-ops', email: 'sec-ops@flowlens.io', role: 'security_admin', status: 'active', lastLogin: '5分钟前' },
  { username: 'zhang.wei', email: 'zw@company.com', role: 'operator', status: 'active', lastLogin: '1小时前' },
  { username: 'auditor', email: 'audit@company.com', role: 'auditor', status: 'disabled', lastLogin: '3天前' },
]

const mockAudit = [
  { time: new Date(Date.now() - 60000).toLocaleString('zh-CN'), user: 'admin', action: 'POST', resource: '/api/v1/assets/ast-001/claim', detail: '认领资产' },
  { time: new Date(Date.now() - 120000).toLocaleString('zh-CN'), user: 'sec-ops', action: 'POST', resource: '/api/v1/alerts/alt-001/ip_block', detail: '封禁IP' },
  { time: new Date(Date.now() - 300000).toLocaleString('zh-CN'), user: 'admin', action: 'GET', resource: '/api/v1/agents', detail: '查看采集器列表' },
]

export default function Settings({ onNavigate }: { onNavigate: (page: string, id?: string) => void }) {
  return (
    <div className="page-enter">
      <Tabs defaultActiveTab="users">
        <Tabs.TabPane key="users" title="用户与角色">
          <Card className="panel-card" title={<span style={{ color: '#EDEAE0' }}>用户管理</span>}>
            <Table
              columns={[
                { title: '用户名', dataIndex: 'username', key: 'username' },
                { title: '邮箱', dataIndex: 'email', key: 'email' },
                { title: '角色', dataIndex: 'role', key: 'role', width: 140,
                  render: (r: string) => {
                    const colors: Record<string, string> = { super_admin: 'red', security_admin: 'orange', operator: 'blue', auditor: 'purple', readonly: 'gray' }
                    return <Tag color={colors[r]}>{r}</Tag>
                  },
                },
                { title: '状态', dataIndex: 'status', key: 'status', width: 100,
                  render: (s: string) => <Tag color={s === 'active' ? 'green' : 'red'}>{s === 'active' ? '启用' : '禁用'}</Tag> },
                { title: '最后登录', dataIndex: 'lastLogin', key: 'lastLogin', width: 120 },
              ]}
              data={mockUsers}
              pagination={false}
            />
          </Card>
        </Tabs.TabPane>

        <Tabs.TabPane key="audit" title="审计日志">
          <Card className="panel-card" title={<span style={{ color: '#EDEAE0' }}>审计日志（只读）</span>}>
            <Table
              columns={[
                { title: '时间', dataIndex: 'time', key: 'time', width: 160, render: (t: string) => <span className="mono">{t}</span> },
                { title: '操作人', dataIndex: 'user', key: 'user', width: 100 },
                { title: '动作', dataIndex: 'action', key: 'action', width: 80 },
                { title: '资源', dataIndex: 'resource', key: 'resource', render: (r: string) => <span className="mono">{r}</span> },
                { title: '详情', dataIndex: 'detail', key: 'detail' },
              ]}
              data={mockAudit}
              pagination={false}
            />
          </Card>
        </Tabs.TabPane>

        <Tabs.TabPane key="sso" title="SSO 配置">
          <Card className="panel-card">
            <div style={{ color: '#8A93A3', fontSize: 14 }}>
              SSO 配置功能将在 V1.0 版本提供。
              <br />支持 SAML 2.0 / OIDC 协议。
            </div>
          </Card>
        </Tabs.TabPane>
      </Tabs>
    </div>
  )
}
