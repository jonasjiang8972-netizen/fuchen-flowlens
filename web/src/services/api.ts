const API_BASE = '/api/v1'

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const resp = await fetch(`${API_BASE}${url}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export const agentService = {
  list: () => {
    const mockData = [
      { agent_id: 'agent-prod-k8s-01', hostname: 'k8s-node-01', status: 'online', collect_mode: 'ebpf', cluster: 'shanghai-1', qps: 15230, last_heartbeat: new Date(Date.now() - 5000).toISOString(), agent_version: '0.1.0', os: 'linux', cpu_percent: 12.3, memory_mb_used: 512, drop_rate: 0.001 },
      { agent_id: 'agent-prod-k8s-02', hostname: 'k8s-node-02', status: 'online', collect_mode: 'ebpf', cluster: 'shanghai-1', qps: 14800, last_heartbeat: new Date(Date.now() - 3000).toISOString(), agent_version: '0.1.0', os: 'linux', cpu_percent: 15.1, memory_mb_used: 498, drop_rate: 0.002 },
      { agent_id: 'agent-bj-backup', hostname: 'vm-backup-01', status: 'degraded', collect_mode: 'gateway_log', cluster: 'beijing-1', qps: 22300, last_heartbeat: new Date(Date.now() - 45000).toISOString(), agent_version: '0.1.0', os: 'linux', cpu_percent: 45.2, memory_mb_used: 2048, drop_rate: 0.05 },
    ]
    return mockData
  },
}

export const assetService = {
  list: () => [
    { asset_id: 'ast-001', path_normalized: '/api/v1/user/{id}', method: 'GET', protocol_type: 'REST', host: 'api.example.com', first_seen: '2026-06-01T08:12:03Z', last_seen: '2026-07-06T09:45:21Z', daily_avg_calls: 15230, sensitivity_hint: 'medium', claim_status: 'claimed', owner: 'zhang.wei@company.com', group_path: '零售事业部/交易系统/用户模块', normalization_confidence: 0.94 },
    { asset_id: 'ast-002', path_normalized: '/api/v1/order/{id}', method: 'GET', protocol_type: 'REST', host: 'api.example.com', first_seen: '2026-06-06T10:00:00Z', last_seen: '2026-07-06T09:50:00Z', daily_avg_calls: 8720, sensitivity_hint: 'high', claim_status: 'claimed', owner: 'li.ming@company.com', group_path: '零售事业部/交易系统/订单模块', normalization_confidence: 0.91 },
    { asset_id: 'ast-003', path_normalized: '/api/v1/payment/checkout', method: 'POST', protocol_type: 'REST', host: 'api.example.com', first_seen: '2026-06-10T14:00:00Z', last_seen: '2026-07-06T09:48:00Z', daily_avg_calls: 3200, sensitivity_hint: 'high', claim_status: 'unclaimed', owner: '', group_path: '零售事业部/交易系统/支付模块', normalization_confidence: 0.99 },
  ],
}

export const alertService = {
  list: () => [
    { alert_id: 'alt-001', timestamp: new Date(Date.now() - 300000).toISOString(), severity: 'high', title: '疑似 BOLA 攻击：账号 usr-88213 高频遍历订单对象', description: '账号 usr-88213 在过去 5 分钟内连续访问了 847 个不同订单 ID，遍历速率 12.4/s，远超历史基线。', source_requirement: 'FR-DET-001', risk_score: 91, confidence: 0.92, status: 'open', source_ip: '203.0.113.18', account_id: 'usr-88213', device_fingerprint: '', affected_asset_count: 1, attack_path: [{ sequence: 1, timestamp: new Date(Date.now() - 300000).toISOString(), action: 'login', detail: '正常登录', source_ip: '203.0.113.18', path: '/api/v1/auth/login', status_code: 200 }, { sequence: 2, timestamp: new Date(Date.now() - 240000).toISOString(), action: 'traverse', detail: '开始遍历订单 ID', source_ip: '203.0.113.18', path: '/api/v1/order/{id}', status_code: 200 }] },
    { alert_id: 'alt-002', timestamp: new Date(Date.now() - 900000).toISOString(), severity: 'critical', title: '撞库攻击：单 IP 尝试 68 个不同账号', description: 'IP 198.51.100.22 在过去 10 分钟内对登录接口发起 247 次失败尝试，涉及 68 个不同用户名。', source_requirement: 'FR-DET-002', risk_score: 88, confidence: 0.95, status: 'acknowledged', source_ip: '198.51.100.22', account_id: '', device_fingerprint: '', affected_asset_count: 1, attack_path: [{ sequence: 1, timestamp: new Date(Date.now() - 900000).toISOString(), action: 'brute_force', detail: '高频登录失败', source_ip: '198.51.100.22', path: '/api/v1/auth/login', status_code: 401 }] },
    { alert_id: 'alt-003', timestamp: new Date(Date.now() - 7200000).toISOString(), severity: 'medium', title: '影子 API 发现：/api/v1/legacy/export 未在 CMDB 注册', description: '发现接口 /api/v1/legacy/export 有实际流量但未在官方 API 目录中注册，疑似遗留接口。', source_requirement: 'FR-AST-002', risk_score: 55, confidence: 0.88, status: 'open', source_ip: '', account_id: '', device_fingerprint: '', affected_asset_count: 1, attack_path: [] },
  ],
}

export const claimAsset = async (assetId: string, owner: string) => {
  return request(`/assets/${assetId}/claim`, {
    method: 'POST',
    body: JSON.stringify({ owner }),
  })
}

export const executeAlertAction = async (alertId: string, action: string) => {
  return request(`/alerts/${alertId}/${action}`, { method: 'POST' })
}
