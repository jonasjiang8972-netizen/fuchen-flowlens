import { lazy, useEffect, useMemo, useState } from 'react'
import { Result } from 'antd'
import {
  AuditOutlined, CloudServerOutlined, SafetyOutlined, SettingOutlined, SolutionOutlined, TeamOutlined, ToolOutlined,
} from '@ant-design/icons'
import ConsoleShell from '../components/ConsoleShell'
import type { ShellMenuItem } from '../components/ConsoleShell'
import { useSession } from '../context/session'
import type { Permission } from '../services/auth'

const Users = lazy(() => import('../pages/admin/Users'))
const Roles = lazy(() => import('../pages/admin/Roles'))
const SecurityPolicy = lazy(() => import('../pages/admin/SecurityPolicy'))
const AuditLogs = lazy(() => import('../pages/admin/AuditLogs'))
const SystemSettings = lazy(() => import('../pages/admin/SystemSettings'))
const Agents = lazy(() => import('../pages/Agents'))
const AgentDetail = lazy(() => import('../pages/AgentDetail'))

// Platform administration, separate from API security operations. Each
// entry is shown only to roles holding its permission, so the system and
// audit administrators see disjoint menus.
const allItems: (ShellMenuItem & { perm: Permission })[] = [
  { key: 'users', icon: <TeamOutlined />, label: '用户管理', perm: 'user.manage' },
  { key: 'roles', icon: <SolutionOutlined />, label: '角色与权限', perm: 'user.manage' },
  { key: 'policy', icon: <SafetyOutlined />, label: '安全策略', perm: 'policy.manage' },
  { key: 'agents', icon: <CloudServerOutlined />, label: '采集器管理', perm: 'agent.manage' },
  { key: 'system', icon: <SettingOutlined />, label: '系统设置', perm: 'system.manage' },
  { key: 'audit', icon: <AuditOutlined />, label: '审计日志', perm: 'audit.read' },
]

const labels: Record<string, string> = {
  users: '用户管理', roles: '角色与权限', policy: '安全策略', agents: '采集器管理', system: '系统设置', audit: '审计日志',
  'agent-detail': '采集器详情',
}

export default function AdminConsole() {
  const { can } = useSession()
  const items = useMemo(() => allItems.filter(i => can(i.perm)), [can])
  const [active, setActive] = useState(items[0]?.key || '')
  const [detailId, setDetailId] = useState('')

  // Reset when the visible menu changes (e.g. demo identity switch).
  useEffect(() => {
    if (!items.some(i => i.key === active) && active !== 'agent-detail') setActive(items[0]?.key || '')
  }, [items, active])

  const navigateTo = (page: string, id?: string) => {
    if (page === 'agent-detail' ? !can('agent.manage') : !items.some(i => i.key === page)) return
    setActive(page)
    if (id) setDetailId(id)
  }

  const renderPage = () => {
    switch (active) {
      case 'users': return <Users />
      case 'roles': return <Roles />
      case 'policy': return <SecurityPolicy />
      case 'agents': return <Agents onNavigate={navigateTo} />
      case 'agent-detail': return <AgentDetail agentId={detailId} onBack={() => navigateTo('agents')} onNavigate={navigateTo} />
      case 'system': return <SystemSettings />
      case 'audit': return <AuditLogs />
      default: return <Result status="403" title="没有可用的管理功能" subTitle="当前账号没有系统管理后台的任何权限，请联系系统管理员。" />
    }
  }

  const breadcrumb: { title: React.ReactNode }[] = [{ title: '系统管理后台' }]
  if (active === 'agent-detail') {
    breadcrumb.push({ title: <a onClick={() => navigateTo('agents')}>采集器管理</a> })
    breadcrumb.push({ title: `采集器详情 (${detailId})` })
  } else if (labels[active]) {
    breadcrumb.push({ title: labels[active] })
  }

  return (
    <ConsoleShell
      variant="admin"
      brandIcon={<ToolOutlined />}
      brandSub="系统管理后台"
      menuItems={items}
      activeKey={active === 'agent-detail' ? 'agents' : active}
      onNavigate={navigateTo}
      breadcrumb={breadcrumb}
    >
      {renderPage()}
    </ConsoleShell>
  )
}
