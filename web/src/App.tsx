import { useState, useEffect } from 'react'
import { Layout, Menu, Typography, Breadcrumb } from 'antd'
import {
  DashboardOutlined,
  ApiOutlined,
  AlertOutlined,
  CloudServerOutlined,
  SafetyOutlined,
} from '@ant-design/icons'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Assets from './pages/Assets'
import AssetDetail from './pages/AssetDetail'
import Alerts from './pages/Alerts'
import AlertDetail from './pages/AlertDetail'
import Agents from './pages/Agents'
import AgentDetail from './pages/AgentDetail'

const { Header, Sider, Content } = Layout
const { Title } = Typography

type PageKey = 'dashboard' | 'assets' | 'asset-detail' | 'alerts' | 'alert-detail' | 'agents' | 'agent-detail'

const menuItems = [
  { key: 'dashboard', icon: <DashboardOutlined />, label: '总览大屏' },
  { key: 'assets', icon: <ApiOutlined />, label: '资产中心' },
  { key: 'alerts', icon: <AlertOutlined />, label: '威胁检测' },
  { key: 'agents', icon: <CloudServerOutlined />, label: '采集器管理' },
]

export default function App() {
  const [authenticated, setAuthenticated] = useState(false)
  const [token, setToken] = useState('')
  const [user, setUser] = useState('')
  const [role, setRole] = useState('')
  const [activePage, setActivePage] = useState<PageKey>('dashboard')
  const [detailId, setDetailId] = useState('')

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
    setToken(newToken)
    setUser(newUser)
    setRole(newRole)
    setAuthenticated(true)
  }

  const handleLogout = () => {
    localStorage.removeItem('flowlens_token')
    localStorage.removeItem('flowlens_user')
    localStorage.removeItem('flowlens_role')
    setAuthenticated(false)
    setToken('')
  }

  const navigateTo = (page: PageKey, id?: string) => {
    setActivePage(page)
    if (id) setDetailId(id)
  }

  const renderPage = () => {
    switch (activePage) {
      case 'dashboard': return <Dashboard onNavigate={navigateTo} />
      case 'assets': return <Assets onNavigate={navigateTo} />
      case 'asset-detail': return <AssetDetail assetId={detailId} onBack={() => navigateTo('assets')} onNavigate={navigateTo} />
      case 'alerts': return <Alerts onNavigate={navigateTo} />
      case 'alert-detail': return <AlertDetail alertId={detailId} onBack={() => navigateTo('alerts')} onNavigate={navigateTo} />
      case 'agents': return <Agents onNavigate={navigateTo} />
      case 'agent-detail': return <AgentDetail agentId={detailId} onBack={() => navigateTo('agents')} onNavigate={navigateTo} />
      default: return <Dashboard onNavigate={navigateTo} />
    }
  }

  if (!authenticated) {
    return <Login onLogin={handleLogin} />
  }

  const getBreadcrumb = () => {
    const items: { title: string; onClick?: () => void }[] = []
    const labelMap: Record<string, string> = {
      dashboard: '总览大屏', assets: '资产中心', alerts: '威胁检测', agents: '采集器管理',
      'asset-detail': '资产详情', 'alert-detail': '告警详情', 'agent-detail': '采集器详情',
    }
    if (activePage.includes('detail')) {
      const parent = activePage.replace('-detail', '') as PageKey
      items.push({ title: labelMap[parent] || '', onClick: () => navigateTo(parent) })
      items.push({ title: `${labelMap[activePage] || ''} (${detailId})` })
    } else {
      items.push({ title: labelMap[activePage] || '' })
    }
    return items
  }

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider width={220} style={{ background: '#0A1929', borderRight: '1px solid #1E3A5F' }}>
        <div style={{ padding: '20px 16px', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <SafetyOutlined style={{ fontSize: '28px', color: '#36CFC9' }} />
          <div>
            <Title level={5} style={{ color: '#F0F4F8', margin: 0, fontSize: '16px' }}>拂尘 FlowLens</Title>
          </div>
        </div>
        <Menu theme="dark" mode="inline"
          selectedKeys={[activePage.includes('detail') ? activePage.replace('-detail', '') : activePage]}
          style={{ background: 'transparent', border: 'none' }}
          items={menuItems}
          onClick={({ key }) => navigateTo(key as PageKey)}
        />
        <div style={{ position: 'absolute', bottom: 20, left: 16, right: 16, padding: '12px', borderTop: '1px solid #1E3A5F' }}>
          <div style={{ color: '#94A3B8', fontSize: 12 }}>{user}</div>
          <div style={{ color: '#36CFC9', fontSize: 12, cursor: 'pointer' }} onClick={handleLogout}>退出登录</div>
        </div>
      </Sider>
      <Layout>
        <Header style={{ background: '#0A1929', borderBottom: '1px solid #1E3A5F', padding: '0 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Breadcrumb items={getBreadcrumb()} style={{ margin: 0 }}
            itemRender={(item) => item.onClick ? <a onClick={item.onClick} style={{ color: '#36CFC9' }}>{item.title}</a> : <span style={{ color: '#F0F4F8' }}>{item.title}</span>}
          />
          <span style={{ color: '#94A3B8', fontSize: '13px' }}>v0.3.0 · {role}</span>
        </Header>
        <Content style={{ padding: '24px', background: '#050B14' }}>
          {renderPage()}
        </Content>
      </Layout>
    </Layout>
  )
}
