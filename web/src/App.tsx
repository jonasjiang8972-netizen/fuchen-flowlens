import { useState, useEffect } from 'react'
import { Avatar, Breadcrumb, Button, Layout, Menu, Space, Tag } from 'antd'
import {
  AlertOutlined,
  ApiOutlined,
  AppstoreOutlined,
  AreaChartOutlined,
  AuditOutlined,
  CloudServerOutlined,
  ControlOutlined,
  DashboardOutlined,
  DatabaseOutlined,
  EyeOutlined,
  FileDoneOutlined,
  LinkOutlined,
  LogoutOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
  TeamOutlined,
  WarningOutlined,
} from '@ant-design/icons'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Assets from './pages/Assets'
import AssetDetail from './pages/AssetDetail'
import Alerts from './pages/Alerts'
import AlertDetail from './pages/AlertDetail'
import Agents from './pages/Agents'
import AgentDetail from './pages/AgentDetail'
import Rules from './pages/Rules'
import DataGovernance from './pages/DataGovernance/DataGovernance'
import RiskOps from './pages/RiskOps/RiskOps'
import Settings from './pages/Settings/Settings'
import FlowMap from './pages/FlowMap'
import AIGovernance from './pages/AIGovernance'
import IdentityCenter from './pages/IdentityCenter'
import GovernanceDashboard from './pages/GovernanceDashboard'
import ContractCenter from './pages/ContractCenter'
import CoverageCenter from './pages/CoverageCenter'
import WorkOrderCenter from './pages/WorkOrderCenter'

type PageKey = 'dashboard' | 'assets' | 'asset-detail' | 'alerts' | 'alert-detail'
  | 'agents' | 'agent-detail' | 'data-gov' | 'risk-ops' | 'settings' | 'rules'
  | 'flow-map' | 'identity-center' | 'ai-governance'
  | 'governance' | 'contracts' | 'coverage' | 'work-orders'

const menuItems = [
  { key: 'governance', icon: <AreaChartOutlined />, label: '治理驾驶舱' },
  { key: 'dashboard',  icon: <DashboardOutlined />,  label: '安全工作台' },
  { key: 'assets',     icon: <ApiOutlined />,        label: 'API 资产' },
  { key: 'alerts',     icon: <SafetyCertificateOutlined />, label: '告警中心' },
  { key: 'flow-map',   icon: <LinkOutlined />,        label: '调用链路' },
  { key: 'contracts',  icon: <FileDoneOutlined />,   label: '契约一致性' },
  { key: 'identity-center', icon: <TeamOutlined />,   label: '身份与调用方' },
  { key: 'rules',      icon: <ControlOutlined />,    label: '检测策略' },
  { key: 'data-gov',   icon: <DatabaseOutlined />,   label: '数据治理' },
  { key: 'coverage',   icon: <WarningOutlined />,    label: '覆盖率盲区' },
  { key: 'agents',     icon: <CloudServerOutlined />, label: '采集与链路' },
  { key: 'work-orders', icon: <AuditOutlined />,      label: '处置闭环' },
  { key: 'ai-governance', icon: <AppstoreOutlined />, label: 'AI 应用治理' },
  { key: 'risk-ops',   icon: <AlertOutlined />,      label: '业务风控' },
  { key: 'settings',   icon: <SettingOutlined />,    label: '系统设置' },
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
    const previewMode = import.meta.env.DEV && new URLSearchParams(window.location.search).get('preview') === '1'
    if (previewMode) {
      setToken('local-preview-token')
      setUser('preview@flowlens.local')
      setRole('security_admin')
      setAuthenticated(true)
      return
    }

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

  const navigateTo = (page: string, id?: string) => {
    const allowedPages: PageKey[] = [
      'dashboard', 'assets', 'asset-detail', 'alerts', 'alert-detail',
      'agents', 'agent-detail', 'data-gov', 'risk-ops', 'settings', 'rules',
      'flow-map', 'identity-center', 'ai-governance',
      'governance', 'contracts', 'coverage', 'work-orders',
    ]
    if (!allowedPages.includes(page as PageKey)) return
    setActivePage(page as PageKey)
    if (id) setDetailId(id)
  }

  const renderPage = () => {
    switch (activePage) {
      case 'governance':   return <GovernanceDashboard onNavigate={navigateTo} />
      case 'dashboard':    return <Dashboard onNavigate={navigateTo} />
      case 'assets':       return <Assets onNavigate={navigateTo} />
      case 'asset-detail': return <AssetDetail assetId={detailId} onBack={() => navigateTo('assets')} onNavigate={navigateTo} />
      case 'alerts':       return <Alerts onNavigate={navigateTo} />
      case 'alert-detail': return <AlertDetail alertId={detailId} onBack={() => navigateTo('alerts')} onNavigate={navigateTo} />
      case 'flow-map':     return <FlowMap onNavigate={navigateTo} />
      case 'contracts':    return <ContractCenter onNavigate={navigateTo} />
      case 'identity-center': return <IdentityCenter />
      case 'agents':       return <Agents onNavigate={navigateTo} />
      case 'agent-detail': return <AgentDetail agentId={detailId} onBack={() => navigateTo('agents')} onNavigate={navigateTo} />
      case 'data-gov':     return <DataGovernance onNavigate={navigateTo} />
      case 'coverage':     return <CoverageCenter onNavigate={navigateTo} />
      case 'work-orders':  return <WorkOrderCenter onNavigate={navigateTo} />
      case 'ai-governance': return <AIGovernance />
      case 'risk-ops':     return <RiskOps onNavigate={navigateTo} />
      case 'rules':        return <Rules onNavigate={navigateTo} />
      case 'settings':     return <Settings onNavigate={navigateTo} />
      default:             return <Dashboard onNavigate={navigateTo} />
    }
  }

  if (!authenticated) return <Login onLogin={handleLogin} />

  const getBreadcrumb = () => {
    const labelMap: Record<string, string> = {
      governance: '治理驾驶舱', dashboard: '安全工作台', assets: 'API 资产', alerts: '告警中心', 'flow-map': '调用链路', contracts: '契约一致性', 'identity-center': '身份与调用方', rules: '检测策略', 'data-gov': '数据治理',
      coverage: '覆盖率盲区', agents: '采集与链路', 'work-orders': '处置闭环', 'ai-governance': 'AI 应用治理', 'risk-ops': '业务风控', settings: '系统设置',
      'asset-detail': '资产详情', 'alert-detail': '告警详情', 'agent-detail': '采集器详情',
    }
    const items: any[] = [{ title: 'FlowLens' }]
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
    <Layout className="flow-shell">
      <Layout.Sider collapsed={collapsed} onCollapse={setCollapsed} collapsible width={248}
        className="flow-sider">
        <div className="flow-brand">
          <div className="flow-brand__mark"><EyeOutlined /></div>
          {!collapsed && (
            <div>
              <div className="flow-brand__name">FlowLens</div>
              <div className="flow-brand__sub">API Security Operations</div>
            </div>
          )}
        </div>
        {!collapsed && (
          <div className="flow-sider__section">
            <Tag color="processing">POC</Tag>
            <span>上海生产环境</span>
          </div>
        )}
        <Menu
          mode="inline"
          selectedKeys={[activePage.includes('detail') ? activePage.replace('-detail', '') : activePage]}
          className="flow-menu"
          onClick={({ key }) => navigateTo(String(key))}
          items={menuItems}
        />
        <div className="flow-user">
          {!collapsed && (
            <>
              <Space align="center">
                <Avatar size={32}>{(user || 'U').slice(0, 1).toUpperCase()}</Avatar>
                <div>
                  <div className="flow-user__name">{user}</div>
                  <div className="flow-user__role">{role}</div>
                </div>
              </Space>
              <Button block size="small" icon={<LogoutOutlined />} onClick={handleLogout}>退出登录</Button>
            </>
          )}
        </div>
      </Layout.Sider>
      <Layout>
        <Layout.Header className="flow-header">
          <Breadcrumb items={getBreadcrumb()} />
          <Space size={12}>
            <Tag color="success">采集正常</Tag>
            <span className="flow-version">v0.6.0</span>
          </Space>
        </Layout.Header>
        <Layout.Content className="flow-content">
          {renderPage()}
        </Layout.Content>
      </Layout>
    </Layout>
  )
}
