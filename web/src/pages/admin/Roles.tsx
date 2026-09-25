import { useEffect, useState } from 'react'
import { Alert, Card, Table, Tag, message } from 'antd'
import { CheckOutlined } from '@ant-design/icons'
import { adminService } from '../../services/admin'
import type { RoleInfo } from '../../services/admin'
import { errorMessage } from '../../services/http'

const permissionRows: { perm: string; name: string; area: string }[] = [
  { perm: 'user.manage', name: '账号与角色管理', area: '系统管理后台' },
  { perm: 'policy.manage', name: '安全策略（口令、会话、锁定、审计保留期）', area: '系统管理后台' },
  { perm: 'agent.manage', name: '采集器管理', area: '系统管理后台' },
  { perm: 'system.manage', name: '系统设置', area: '系统管理后台' },
  { perm: 'audit.read', name: '审计日志查询、完整性校验、导出', area: '系统管理后台' },
  { perm: 'security.read', name: '查看 API 资产、告警、链路、检测策略', area: 'API 安全平台' },
  { perm: 'rule.manage', name: '检测策略配置', area: 'API 安全平台' },
  { perm: 'alert.handle', name: '告警研判与处置（封禁、限流）', area: 'API 安全平台' },
  { perm: 'asset.manage', name: '资产认领与归属', area: 'API 安全平台' },
]

export default function Roles() {
  const [roles, setRoles] = useState<RoleInfo[]>([])

  useEffect(() => {
    adminService.roles().then(setRoles).catch(err => message.error(errorMessage(err)))
  }, [])

  const columns = [
    {
      title: '权限', key: 'perm', fixed: 'left' as const, width: 300, render: (_: unknown, r: typeof permissionRows[number]) => (
        <div>
          <div>{r.name}</div>
          <div className="muted mono" style={{ fontSize: 12 }}>{r.perm}</div>
        </div>
      ),
    },
    { title: '所属', dataIndex: 'area', key: 'area', width: 120, render: (a: string) => <Tag color={a === 'API 安全平台' ? 'cyan' : 'geekblue'}>{a}</Tag> },
    ...roles.map(role => ({
      title: role.name, key: role.role, align: 'center' as const, width: 110,
      render: (_: unknown, r: typeof permissionRows[number]) =>
        role.permissions.includes(r.perm) ? <CheckOutlined style={{ color: 'var(--fl-success)' }} aria-label="有此权限" /> : <span className="muted">—</span>,
    })),
  ]

  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">角色与权限</div>
          <div className="page-heading__desc">角色由平台内置，按等保三级“三权分立”要求划分，不能自定义或合并。每个账号只能拥有一个角色。</div>
        </div>
      </div>

      <Alert
        type="info"
        showIcon
        message="职责分离规则"
        description={
          <ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>
            <li>系统管理员、审计管理员、安全管理员三类职责互不重叠；平台不设能绕过权限检查的超级管理员。</li>
            <li>系统管理员不能查看审计日志，也不能操作 API 安全业务；审计管理员只能查看审计日志。</li>
            <li>不能停用、删除或变更最后一个启用的系统管理员或审计管理员；不能修改自己的角色。</li>
            <li>所有越权访问都会被拒绝，并记录到审计日志中。</li>
          </ul>
        }
      />

      <Card title="角色说明">
        <Table rowKey="role" pagination={false} dataSource={roles} columns={[
          { title: '角色', dataIndex: 'name', key: 'name', width: 130 },
          { title: '登录后进入', dataIndex: 'console', key: 'console', width: 140, render: (c: string) => (c === 'admin' ? '系统管理后台' : 'API 安全平台') },
          { title: '职责', dataIndex: 'description', key: 'description' },
        ]} />
      </Card>

      <Card title="权限矩阵">
        <Table rowKey="perm" pagination={false} dataSource={permissionRows} columns={columns} scroll={{ x: 980 }} />
      </Card>
    </div>
  )
}
