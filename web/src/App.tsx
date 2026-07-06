import { useState, useEffect } from 'react'
import { Layout, Menu, Breadcrumb, Notification, Button } from '@arco-design/web-react'
import {
  IconDashboard, IconApps, IconSafe, IconSettings, IconCloud,
  IconUser, IconSend, IconEye, IconStop,
} from '@arco-design/web-react/icon'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Assets from './pages/Assets'
import AssetDetail from './pages/AssetDetail'
import Alerts from './pages/Alerts'
import AlertDetail from './pages/AlertDetail'
import Agents from './pages/Agents'
import AgentDetail from './pages/AgentDetail'
import DataGovernance from './pages/DataGovernance/DataGovernance'
import RiskOps from './pages/RiskOps/RiskOps'
import Settings from './pages/Settings/Settings'

const Sider = Layout.Sider
const Header = Layout.Header
const Content = Layout.Content

type PageKey = 'dashboard' | 'assets' | 'asset-detail' | 'threats' | 'alert-detail'
  | 'agents' | 'agent-detail' | 'data-gov' | 'risk-ops' | 'settings'

const menuItems = [
  { key: 'dashboard',  icon: <IconDashboard />,  label: '总览大屏' },
  { key: 'assets',     icon: <IconApps />,       label: '资产中心' },
  { key: 'threats',    icon: <IconSafe />,       label: '威胁检测' },
  { key: 'data-gov',   icon: <IconSend />,       label: '敏感数据治理' },
  { key: 'agents',     icon: <IconCloud />,      label: '采集器管理' },
  { key: 'risk-ops',   icon: <IconStop />,       label: '风控告警中心' },
  { key: 'settings',   icon: <IconSettings />,   label: '系统管理' },
]

export default function App() {
  const [authenticated, setAuthenticated] = useState(false)
  const [token, setToken] = useState('')
  const [user, setUser] = useState('')
  const [role, setRole] = useState('')
  const [activePage, setActivePage] = useState<PageKey>('dashboard')
  const [detailId, setDetailId] = useState('')
  const [collapsed, setCollapsed] = useState(false)

  useEffect(() => {
    const savedToken = localStorage.getItem('flowlens_token')
    if (savedToken) {
      setToken(savedToken)
      setUser(localStorage.getItem('flowlens_user') || '')
      setRole(localStorage.getItem('flowlens_role') || '')
      setAuthenticated(true)
    }
  }, [])

  const handleLogin = (newToken: string, newUser: string, newRole: string) => {
    setToken(newToken); setUser(newUser); setRole(newRole); setAuthenticated(true)
  }
  const handleLogout = () => {
    localStorage.clear(); setAuthenticated(false); setToken('')
  }

  const navigateTo = (page: PageKey, id?: string) => {
    setActivePage(page)
    if (id) setDetailId(id)
  }

  const renderPage = () => {
    switch (activePage) {
      case 'dashboard':    return <Dashboard onNavigate={navigateTo} />
      case 'assets':       return <Assets onNavigate={navigateTo} />
      case 'asset-detail': return <AssetDetail assetId={detailId} onBack={() => navigateTo('assets')} onNavigate={navigateTo} />
      case 'threats':      return <Alerts onNavigate={navigateTo} />
      case 'alert-detail': return <AlertDetail alertId={detailId} onBack={() => navigateTo('threats')} onNavigate={navigateTo} />
      case 'agents':       return <Agents onNavigate={navigateTo} />
      case 'agent-detail': return <AgentDetail agentId={detailId} onBack={() => navigateTo('agents')} onNavigate={navigateTo} />
      case 'data-gov':     return <DataGovernance onNavigate={navigateTo} />
      case 'risk-ops':     return <RiskOps onNavigate={navigateTo} />
      case 'settings':     return <Settings onNavigate={navigateTo} />
      default:             return <Dashboard onNavigate={navigateTo} />
    }
  }

  if (!authenticated) return <Login onLogin={handleLogin} />

  const getBreadcrumb = () => {
    const labelMap: Record<string, string> = {
      dashboard: '总览大屏', assets: '资产中心', threats: '威胁检测', 'data-gov': '敏感数据治理',
      agents: '采集器管理', 'risk-ops': '风控告警中心', settings: '系统管理',
      'asset-detail': '资产详情', 'alert-detail': '告警详情', 'agent-detail': '采集器详情',
    }
    const items: any[] = []
    if (activePage.includes('detail')) {
      const parent = activePage.replace('-detail', '') as PageKey
      items.push({ title: <a onClick={() => navigateTo(parent)}>{labelMap[parent]}</a> })
      items.push({ title: `${labelMap[activePage]} (${detailId})` })
    } else {
      items.push({ title: labelMap[activePage] || activePage })
    }
    return items
  }

  return (
    <Layout style={{ minHeight: '100vh', background: 'var(--color-bg-canvas)' }}>
      <Sider collapsed={collapsed} onCollapse={setCollapsed} collapsible
        style={{ background: 'var(--color-bg-canvas)', borderRight: '1px solid var(--color-border-hairline)' }}>
        <div style={{ padding: '20px 16px', display: 'flex', alignItems: 'center', gap: 10 }}>
          <IconEye style={{ fontSize: 26, color: 'var(--color-brand-primary)' }} />
          {!collapsed && <span style={{ color: 'var(--color-text-primary)', fontWeight: 600, fontSize: 16 }}>FlowLens</span>}
        </div>
        <Menu theme="dark"
          selectedKeys={[activePage.includes('detail') ? activePage.replace('-detail', '') : activePage]}
          style={{ background: 'transparent', border: 'none' }}
          onClick={(key) => navigateTo(key as PageKey)}
        >
          {menuItems.map(m => (
            <Menu.Item key={m.key}>
              {m.icon}<span style={{ marginLeft: 10 }}>{m.label}</span>
            </Menu.Item>
          ))}
        </Menu>
        <div style={{ position: 'absolute', bottom: 16, left: 16, right: 16, padding: '12px 0', borderTop: '1px solid var(--color-border-hairline)' }}>
          {!collapsed && (
            <>
              <div style={{ color: 'var(--color-text-secondary)', fontSize: 12 }}>{user}</div>
              <div style={{ color: 'var(--color-brand-primary)', fontSize: 12, cursor: 'pointer' }} onClick={handleLogout}>退出</div>
            </>
          )}
        </div>
      </Sider>
      <Layout>
        <Header style={{ background: 'var(--color-bg-canvas)', borderBottom: '1px solid var(--color-border-hairline)', padding: '0 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', height: 52 }}>
          <Breadcrumb routes={getBreadcrumb()} style={{ background: 'transparent' }} />
          <span style={{ color: 'var(--color-text-secondary)', fontSize: 12 }}>v0.4.0 · {role}</span>
        </Header>
        <Content style={{ padding: 20, background: 'var(--color-bg-canvas)' }}>
          {renderPage()}
        </Content>
      </Layout>
    </Layout>
  )
}
