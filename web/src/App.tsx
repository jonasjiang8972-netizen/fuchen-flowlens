import { Spin } from 'antd'
import { SessionProvider, useSession } from './context/session'
import Login from './pages/Login'
import ChangePassword from './pages/ChangePassword'
import SecurityConsole from './consoles/SecurityConsole'
import AdminConsole from './consoles/AdminConsole'

// Signed-in operators land in the console their role belongs to: system and
// audit administrators in the management console, security roles in the API
// security platform. The platform enforces the same split on every API call.
function Root() {
  const { status, session } = useSession()
  if (status === 'loading') return <div className="flow-page-loading" style={{ minHeight: '100vh' }}><Spin size="large" /></div>
  if (status === 'anonymous' || !session) return <Login />
  if (status === 'must-change') return <ChangePassword />
  return session.console === 'admin' ? <AdminConsole /> : <SecurityConsole />
}

export default function App() {
  return (
    <SessionProvider>
      <Root />
    </SessionProvider>
  )
}
