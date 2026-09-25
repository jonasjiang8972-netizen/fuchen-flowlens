import { lazy, useState } from 'react'
import { Tag } from 'antd'
import {
  AlertOutlined, ApiOutlined, AppstoreOutlined, AreaChartOutlined, AuditOutlined, ControlOutlined,
  DashboardOutlined, DatabaseOutlined, EyeOutlined, FileDoneOutlined, LinkOutlined,
  SafetyCertificateOutlined, TeamOutlined, WarningOutlined,
} from '@ant-design/icons'
import ConsoleShell from '../components/ConsoleShell'
import type { ShellMenuItem } from '../components/ConsoleShell'

const Dashboard = lazy(() => import('../pages/Dashboard'))
const Assets = lazy(() => import('../pages/Assets'))
const AssetDetail = lazy(() => import('../pages/AssetDetail'))
const Alerts = lazy(() => import('../pages/Alerts'))
const AlertDetail = lazy(() => import('../pages/AlertDetail'))
const Rules = lazy(() => import('../pages/Rules'))
const DataGovernance = lazy(() => import('../pages/DataGovernance/DataGovernance'))
const RiskOps = lazy(() => import('../pages/RiskOps/RiskOps'))
const FlowMap = lazy(() => import('../pages/FlowMap'))
const AIGovernance = lazy(() => import('../pages/AIGovernance'))
const IdentityCenter = lazy(() => import('../pages/IdentityCenter'))
const GovernanceDashboard = lazy(() => import('../pages/GovernanceDashboard'))
const ContractCenter = lazy(() => import('../pages/ContractCenter'))
const CoverageCenter = lazy(() => import('../pages/CoverageCenter'))
const WorkOrderCenter = lazy(() => import('../pages/WorkOrderCenter'))

type PageKey = 'dashboard' | 'assets' | 'asset-detail' | 'alerts' | 'alert-detail'
  | 'data-gov' | 'risk-ops' | 'rules' | 'flow-map' | 'identity-center' | 'ai-governance'
  | 'governance' | 'contracts' | 'coverage' | 'work-orders'

// API security operations and policy only. Accounts, the audit trail,
// collectors and system settings live in the management console.
const menuItems: ShellMenuItem[] = [
  { key: 'governance', icon: <AreaChartOutlined />, label: '治理驾驶舱' },
  { key: 'dashboard', icon: <DashboardOutlined />, label: '安全工作台' },
  { key: 'assets', icon: <ApiOutlined />, label: 'API 资产' },
  { key: 'alerts', icon: <SafetyCertificateOutlined />, label: '告警中心' },
  { key: 'flow-map', icon: <LinkOutlined />, label: '调用链路' },
  { key: 'contracts', icon: <FileDoneOutlined />, label: '契约一致性' },
  { key: 'identity-center', icon: <TeamOutlined />, label: '身份与调用方' },
  { key: 'rules', icon: <ControlOutlined />, label: '检测策略' },
  { key: 'data-gov', icon: <DatabaseOutlined />, label: '数据治理' },
  { key: 'coverage', icon: <WarningOutlined />, label: '覆盖率盲区' },
  { key: 'work-orders', icon: <AuditOutlined />, label: '处置闭环' },
  { key: 'ai-governance', icon: <AppstoreOutlined />, label: 'AI 应用治理' },
  { key: 'risk-ops', icon: <AlertOutlined />, label: '业务风控' },
]

const labels: Record<string, string> = {
  governance: '治理驾驶舱', dashboard: '安全工作台', assets: 'API 资产', alerts: '告警中心', 'flow-map': '调用链路',
  contracts: '契约一致性', 'identity-center': '身份与调用方', rules: '检测策略', 'data-gov': '数据治理',
  coverage: '覆盖率盲区', 'work-orders': '处置闭环', 'ai-governance': 'AI 应用治理', 'risk-ops': '业务风控',
  'asset-detail': '资产详情', 'alert-detail': '告警详情',
}

const pages = new Set<string>(Object.keys(labels))

export default function SecurityConsole() {
  const [active, setActive] = useState<PageKey>('dashboard')
  const [detailId, setDetailId] = useState('')

  const navigateTo = (page: string, id?: string) => {
    if (!pages.has(page)) return
    setActive(page as PageKey)
    if (id) setDetailId(id)
  }

  const renderPage = () => {
    switch (active) {
      case 'governance': return <GovernanceDashboard onNavigate={navigateTo} />
      case 'assets': return <Assets onNavigate={navigateTo} />
      case 'asset-detail': return <AssetDetail assetId={detailId} onBack={() => navigateTo('assets')} onNavigate={navigateTo} />
      case 'alerts': return <Alerts onNavigate={navigateTo} />
      case 'alert-detail': return <AlertDetail alertId={detailId} onBack={() => navigateTo('alerts')} onNavigate={navigateTo} />
      case 'flow-map': return <FlowMap onNavigate={navigateTo} />
      case 'contracts': return <ContractCenter onNavigate={navigateTo} />
      case 'identity-center': return <IdentityCenter />
      case 'data-gov': return <DataGovernance onNavigate={navigateTo} />
      case 'coverage': return <CoverageCenter onNavigate={navigateTo} />
      case 'work-orders': return <WorkOrderCenter onNavigate={navigateTo} />
      case 'ai-governance': return <AIGovernance />
      case 'risk-ops': return <RiskOps onNavigate={navigateTo} />
      case 'rules': return <Rules onNavigate={navigateTo} />
      default: return <Dashboard onNavigate={navigateTo} />
    }
  }

  const breadcrumb: { title: React.ReactNode }[] = [{ title: 'API 安全管理平台' }]
  if (active.endsWith('-detail')) {
    const parent = active.replace('-detail', '')
    breadcrumb.push({ title: <a onClick={() => navigateTo(parent)}>{labels[parent]}</a> })
    breadcrumb.push({ title: `${labels[active]} (${detailId})` })
  } else {
    breadcrumb.push({ title: labels[active] })
  }

  return (
    <ConsoleShell
      variant="security"
      brandIcon={<EyeOutlined />}
      brandSub="API 安全管理平台"
      menuItems={menuItems}
      activeKey={active.endsWith('-detail') ? active.replace('-detail', '') : active}
      onNavigate={navigateTo}
      breadcrumb={breadcrumb}
      headerExtra={<Tag color="success">采集正常</Tag>}
    >
      {renderPage()}
    </ConsoleShell>
  )
}
