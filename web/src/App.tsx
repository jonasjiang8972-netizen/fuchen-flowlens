import { useState } from 'react'
import { Layout, Menu, Typography } from 'antd'
import {
  DashboardOutlined,
  ApiOutlined,
  AlertOutlined,
  SafetyOutlined,
  CloudServerOutlined,
  SettingOutlined,
} from '@ant-design/icons'
import Dashboard from './pages/Dashboard'
import Assets from './pages/Assets'
import Alerts from './pages/Alerts'
import Agents from './pages/Agents'

const { Header, Sider, Content } = Layout
const { Title } = Typography

type PageKey = 'dashboard' | 'assets' | 'alerts' | 'agents'

const menuItems = [
  { key: 'dashboard', icon: <DashboardOutlined />, label: '总览大屏' },
  { key: 'assets', icon: <ApiOutlined />, label: '资产中心' },
  { key: 'alerts', icon: <AlertOutlined />, label: '威胁检测' },
  { key: 'agents', icon: <CloudServerOutlined />, label: '采集器管理' },
]

export default function App() {
  const [activePage, setActivePage] = useState<PageKey>('dashboard')

  const renderPage = () => {
    switch (activePage) {
      case 'dashboard': return <Dashboard />
      case 'assets': return <Assets />
      case 'alerts': return <Alerts />
      case 'agents': return <Agents />
      default: return <Dashboard />
    }
  }

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider
        width={220}
        style={{
          background: '#0A1929',
          borderRight: '1px solid #1E3A5F',
        }}
      >
        <div style={{ padding: '20px 16px', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <SafetyOutlined style={{ fontSize: '28px', color: '#36CFC9' }} />
          <div>
            <Title level={5} style={{ color: '#F0F4F8', margin: 0, fontSize: '16px' }}>
              拂尘 FlowLens
            </Title>
          </div>
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[activePage]}
          style={{ background: 'transparent', border: 'none' }}
          items={menuItems}
          onClick={({ key }) => setActivePage(key as PageKey)}
        />
      </Sider>
      <Layout>
        <Header
          style={{
            background: '#0A1929',
            borderBottom: '1px solid #1E3A5F',
            padding: '0 24px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <Title level={4} style={{ color: '#F0F4F8', margin: 0 }}>
            {menuItems.find(m => m.key === activePage)?.label}
          </Title>
          <span style={{ color: '#94A3B8', fontSize: '13px' }}>
            v0.1.0 · API 旁路安全监测平台
          </span>
        </Header>
        <Content style={{ padding: '24px', background: '#050B14' }}>
          {renderPage()}
        </Content>
      </Layout>
    </Layout>
  )
}
