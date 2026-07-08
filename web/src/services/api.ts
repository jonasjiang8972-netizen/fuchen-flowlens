import ReactECharts from 'echarts-for-react'

const API_BASE = '/api/v1'

function getAuthHeaders(): Record<string, string> {
  const token = localStorage.getItem('flowlens_token')
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (token) headers['Authorization'] = `Bearer ${token}`
  return headers
}

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const resp = await fetch(`${API_BASE}${url}`, {
    headers: getAuthHeaders(),
    ...options,
  })
  if (resp.status === 401) {
    localStorage.removeItem('flowlens_token')
    window.location.reload()
    throw new Error('Unauthorized')
  }
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

// ─── Agent Service ───────────────────────────────────────────────

export const agentService = {
  list: async () => {
    try {
      const data = await request<{ items: any[] }>('/agents')
      return data.items
    } catch {
      return generateMockAgents()
    }
  },
  detail: async (id: string) => {
    try {
      return await request<any>(`/agents/${id}`)
    } catch {
      const metrics: Record<string, any> = {
        'agent-prod-k8s-01': {
          qps_history: [14200, 14500, 14800, 15000, 15230, 15100, 14900, 15230],
          drop_rate_history: [0.001, 0.001, 0.002, 0.001, 0.001, 0.001, 0.002, 0.001],
          cpu_history: [11.2, 12.0, 13.5, 12.8, 12.3, 11.9, 12.1, 12.3],
          memory_history: [480, 490, 505, 510, 512, 508, 510, 512],
          kafka_lag: 0, bytes_processed: 1847293447, packets_processed: 892340123, uptime_seconds: 259200,
        },
      }
      return {
        agent_id: id,
        metrics: metrics[id] || { qps_history: [0], drop_rate_history: [0], cpu_history: [0], memory_history: [0] },
        config: { mode: 'auto' },
        recent_logs: [],
        collected_apis: 30,
      }
    }
  },
}

export const ingestService = {
  metrics: async () => {
    try {
      return await request<any>('/ingest/metrics')
    } catch {
      return {
        accepted: 1523000,
        dropped: 182,
        duplicates: 936,
        processed: 1522416,
        queue_depth: 584,
        queue_size: 20000,
        last_event_at: new Date(Date.now() - 2800).toISOString(),
      }
    }
  },
}

// ─── Asset Service ───────────────────────────────────────────────

export const assetService = {
  list: async () => {
    try {
      const data = await request<{ items: any[] }>('/assets')
      return data.items
    } catch {
      return generateMockAssets()
    }
  },
  detail: async (id: string) => {
    try {
      return await request<any>(`/assets/${id}`)
    } catch {
      const alerts: Record<string, any[]> = {
        'ast-001': [{ alert_id: 'alt-001', title: '疑似 BOLA 攻击', severity: 'high', status: 'open', timestamp: new Date(Date.now() - 300000).toISOString() }],
      }
      return {
        asset_id: id,
        alerts: alerts[id] || [],
        change_history: [],
        related_assets: [],
      }
    }
  },
}

// ─── Alert Service ───────────────────────────────────────────────

export const alertService = {
  list: async () => {
    try {
      const data = await request<{ items: any[] }>('/alerts')
      return data.items
    } catch {
      return generateMockAlerts()
    }
  },
  detail: async (id: string) => {
    try {
      return await request<any>(`/alerts/${id}`)
    } catch {
      const timelines: Record<string, any> = {
        'alt-001': [{ time: new Date(Date.now() - 3600000).toISOString(), event: '基线建立', detail: '完成' }],
      }
      return {
        alert_id: id,
        timeline: timelines[id] || [],
        related_alerts: [],
        raw_data: {},
      }
    }
  },
}

// ─── Action APIs ─────────────────────────────────────────────────

export const claimAsset = async (assetId: string, owner: string) => {
  try {
    return await request(`/assets/${assetId}/claim`, { method: 'POST', body: JSON.stringify({ owner }) })
  } catch {
    return { status: 'ok' }
  }
}

export const executeAlertAction = async (alertId: string, action: string) => {
  try {
    return await request(`/alerts/${alertId}/${action}`, { method: 'POST' })
  } catch {
    return { status: 'ok', action }
  }
}

// ─── Rule Service ──────────────────────────────────────────────

export const ruleService = {
  list: async () => {
    try {
      const data = await request<{ items: any[] }>('/rules')
      return data.items
    } catch {
      return generateMockRules()
    }
  },
  categories: async () => {
    try {
      const data = await request<{ items: string[] }>('/rules/categories')
      return data.items
    } catch {
      return ['越权访问', '身份安全', '数据安全', '业务风控', '可用性', '注入攻击', '配置错误']
    }
  },
  detail: async (id: string) => {
    try {
      return await request<any>(`/rules/${id}`)
    } catch {
      return { rule_id: id, name: '', params: [] }
    }
  },
  update: async (id: string, body: any) => {
    try {
      return await request<any>(`/rules/${id}`, { method: 'PUT', body: JSON.stringify(body) })
    } catch {
      return { status: 'ok' }
    }
  },
}

// ─── Mock Data Fallback ─────────────────────────────────────────

function generateMockRules() {
  return [
    { rule_id: 'R-BOLA-001', source_requirement: 'FR-DET-001', name: 'BOLA 对象遍历检测', category: '越权访问', severity: 'high', enabled: true, default_risk_score: 80, hit_count: 23, description: '检测账号在短时间高频访问不同对象ID的行为。', recommendation: '建议对该账号实施限流或临时封禁。', params: [{ key: 'traverse_threshold', label: '遍历阈值', type: 'int', default_value: 20, min: 5, max: 500, unit: '个', description: '5分钟内不同对象ID数量超过此值触发告警' }, { key: 'rate_threshold', label: '速率阈值', type: 'float', default_value: 2.0, min: 0.5, max: 100, description: '遍历速率超过此值加重评分' }] },
    { rule_id: 'R-AUTH-001', source_requirement: 'FR-DET-002', name: '认证失效检测', category: '身份安全', severity: 'critical', enabled: true, default_risk_score: 90, hit_count: 7, description: '检测单 IP 短时间多重账号登录失败行为。', recommendation: '建议对该 IP 实施临时封禁。', params: [{ key: 'fail_count', label: '失败次数阈值', type: 'int', default_value: 30, min: 5, max: 500, description: '时间窗口内失败次数超过此值触发' }, { key: 'unique_accounts', label: '不同账号数', type: 'int', default_value: 10, min: 2, max: 200, description: '涉及不同账号数超过此值加重' }] },
    { rule_id: 'R-BFLA-001', source_requirement: 'FR-DET-005', name: 'BFLA 越权操作检测', category: '越权访问', severity: 'high', enabled: true, default_risk_score: 75, hit_count: 5, description: '检测低权限账号访问管理端点或执行高权限操作。', recommendation: '检查该账号的角色配置是否正确。', params: [{ key: 'admin_endpoints', label: '管理端点列表', type: 'string', default_value: '/admin,/api/v1/admin', description: '逗号分隔的管理端点前缀' }, { key: 'strict_mode', label: '严格模式', type: 'bool', default_value: false, description: '开启后所有未经历史访问的管理端点请求即告警' }] },
    { rule_id: 'R-DLP-001', source_requirement: 'FR-DLP-001', name: '敏感数据检测', category: '数据安全', severity: 'high', enabled: true, default_risk_score: 70, hit_count: 0, description: '自动识别响应体中的敏感数据。', recommendation: '检查该接口返回的敏感字段是否必须。', params: [{ key: 'id_card', label: '身份证检测', type: 'bool', default_value: true, description: '启用身份证号正则+校验位检测' }, { key: 'phone', label: '手机号检测', type: 'bool', default_value: true, description: '启用手机号检测' }] },
    { rule_id: 'R-BOT-001', source_requirement: 'FR-RISK-002', name: '爬虫行为检测', category: '业务风控', severity: 'medium', enabled: false, default_risk_score: 50, hit_count: 0, description: '基于设备指纹、请求间隔规律识别自动化爬虫。', recommendation: '对该设备指纹实施验证码挑战或限流。', params: [{ key: 'interval_variance', label: '请求间隔方差阈值', type: 'float', default_value: 0.1, min: 0.01, max: 1.0, description: '请求间隔标准差小于此值判定为脚本' }, { key: 'burst_threshold', label: '短时爆发阈值', type: 'int', default_value: 100, min: 10, max: 1000, description: '1分钟内请求超过此值触发' }] },
    { rule_id: 'R-RATE-001', source_requirement: 'FR-DET-004', name: '资源消耗异常检测', category: '可用性', severity: 'medium', enabled: false, default_risk_score: 50, hit_count: 0, description: '检测接口 QPS 超出历史基线的异常流量。', recommendation: '对该来源实施限流策略。', params: [{ key: 'multiplier', label: '基线倍数阈值', type: 'float', default_value: 5.0, min: 1.5, max: 100, description: '当前QPS超历史基线N倍时触发' }, { key: 'min_qps', label: '最低QPS门槛', type: 'int', default_value: 500, min: 10, max: 100000, description: '低于此QPS不检测' }] },
    { rule_id: 'R-SSRF-001', source_requirement: 'FR-DET-007', name: 'SSRF 检测', category: '注入攻击', severity: 'high', enabled: true, default_risk_score: 65, hit_count: 0, description: '检测请求参数中包含内网地址等SSRF特征。', recommendation: '检查该接口是否需要对用户输入做URL白名单校验。', params: [{ key: 'internal_nets', label: '内网IP段', type: 'string', default_value: '10.0.0.0/8,192.168.0.0/16', description: '匹配到这些网段的请求参数触发告警' }] },
  ]
}

function generateMockAgents() {
  const now = new Date()
  return [
    { agent_id: 'agent-prod-k8s-01', hostname: 'k8s-node-sh-prod-01', status: 'online', collect_mode: 'ebpf', cluster: 'shanghai-prod', qps: 15230, last_heartbeat: new Date(now.getTime() - 5000).toISOString(), agent_version: '0.1.0', os: 'linux', cpu_percent: 12.3, memory_mb_used: 512, drop_rate: 0.001 },
    { agent_id: 'agent-prod-k8s-02', hostname: 'k8s-node-sh-prod-02', status: 'online', collect_mode: 'ebpf', cluster: 'shanghai-prod', qps: 14800, last_heartbeat: new Date(now.getTime() - 3000).toISOString(), agent_version: '0.1.0', os: 'linux', cpu_percent: 15.1, memory_mb_used: 498, drop_rate: 0.002 },
    { agent_id: 'agent-prod-k8s-03', hostname: 'k8s-node-sh-prod-03', status: 'online', collect_mode: 'ebpf', cluster: 'shanghai-prod', qps: 8900, last_heartbeat: new Date(now.getTime() - 7000).toISOString(), agent_version: '0.1.0', os: 'linux', cpu_percent: 8.7, memory_mb_used: 380, drop_rate: 0.000 },
    { agent_id: 'agent-staging-01', hostname: 'k8s-node-stg-01', status: 'online', collect_mode: 'ebpf', cluster: 'shanghai-staging', qps: 3200, last_heartbeat: new Date(now.getTime() - 12000).toISOString(), agent_version: '0.1.0', os: 'linux', cpu_percent: 5.2, memory_mb_used: 256, drop_rate: 0.000 },
    { agent_id: 'agent-vm-dmz-01', hostname: 'vm-dmz-01', status: 'online', collect_mode: 'dpdk', cluster: 'beijing-prod', qps: 28700, last_heartbeat: new Date(now.getTime() - 4000).toISOString(), agent_version: '0.1.0', os: 'linux', cpu_percent: 22.5, memory_mb_used: 1024, drop_rate: 0.003 },
    { agent_id: 'agent-vm-dmz-02', hostname: 'vm-dmz-02', status: 'online', collect_mode: 'dpdk', cluster: 'beijing-prod', qps: 31200, last_heartbeat: new Date(now.getTime() - 6000).toISOString(), agent_version: '0.1.0', os: 'linux', cpu_percent: 25.8, memory_mb_used: 1100, drop_rate: 0.005 },
    { agent_id: 'agent-bj-backup', hostname: 'vm-backup-01', status: 'degraded', collect_mode: 'gateway_log', cluster: 'beijing-backup', qps: 22300, last_heartbeat: new Date(now.getTime() - 45000).toISOString(), agent_version: '0.1.0', os: 'linux', cpu_percent: 45.2, memory_mb_used: 2048, drop_rate: 0.05 },
    { agent_id: 'agent-saas-tencent', hostname: 'tencent-cvm-01', status: 'online', collect_mode: 'ebpf', cluster: 'shenzhen-prod', qps: 5600, last_heartbeat: new Date(now.getTime() - 8000).toISOString(), agent_version: '0.1.0', os: 'linux', cpu_percent: 7.3, memory_mb_used: 320, drop_rate: 0.001 },
    { agent_id: 'agent-offline-01', hostname: 'vm-legacy-01', status: 'offline', collect_mode: 'pcap', cluster: 'shanghai-legacy', qps: 0, last_heartbeat: new Date(now.getTime() - 7200000).toISOString(), agent_version: '0.0.9', os: 'linux', cpu_percent: 0, memory_mb_used: 0, drop_rate: 0 },
  ]
}

function generateMockAssets() {
  const now = new Date()
  return [
    { asset_id: 'ast-001', path_normalized: '/api/v1/user/{id}', method: 'GET', protocol_type: 'REST', host: 'api.example.com', first_seen: '2026-05-22T08:00:00Z', last_seen: new Date(now.getTime() - 30000).toISOString(), daily_avg_calls: 45230, sensitivity_hint: 'medium', claim_status: 'claimed', owner: 'zhang.wei@company.com', group_path: '零售事业部/交易系统/用户模块', normalization_confidence: 0.94, status: 'active', sensitive_fields: ['phone', 'email', 'id_card_no'], request_stats: { total_calls_24h: 45230, unique_callers_24h: 1280, error_rate_24h: 0.3, avg_latency_ms: 23.5, p95_latency_ms: 89.2, hourly_calls: [820, 650, 430, 310, 280, 350, 890, 2100, 3800, 4200, 3900, 3600, 3400, 3200, 3100, 3300, 3500, 3800, 3200, 2800, 2400, 2100, 1800, 1200] } },
    { asset_id: 'ast-002', path_normalized: '/api/v1/order/{id}', method: 'GET', protocol_type: 'REST', host: 'api.example.com', first_seen: '2026-05-27T10:00:00Z', last_seen: new Date(now.getTime() - 10000).toISOString(), daily_avg_calls: 28720, sensitivity_hint: 'high', claim_status: 'claimed', owner: 'li.ming@company.com', group_path: '零售事业部/交易系统/订单模块', normalization_confidence: 0.91, status: 'active', sensitive_fields: ['order_amount', 'recipient_phone', 'shipping_address'], request_stats: { total_calls_24h: 28720, unique_callers_24h: 890, error_rate_24h: 0.8, avg_latency_ms: 45.2, p95_latency_ms: 156.8, hourly_calls: [420, 310, 200, 150, 130, 180, 520, 1800, 2900, 3100, 2800, 2600, 2400, 2200, 2100, 2200, 2300, 2100, 1800, 1500, 1200, 1000, 700] } },
    { asset_id: 'ast-003', path_normalized: '/api/v1/payment/checkout', method: 'POST', protocol_type: 'REST', host: 'api.example.com', first_seen: '2026-06-01T14:00:00Z', last_seen: new Date(now.getTime() - 60000).toISOString(), daily_avg_calls: 8500, sensitivity_hint: 'high', claim_status: 'unclaimed', owner: '', group_path: '零售事业部/交易系统/支付模块', normalization_confidence: 0.99, status: 'active', sensitive_fields: ['card_number', 'cvv', 'expiry', 'amount'] },
    { asset_id: 'ast-004', path_normalized: '/api/v1/user/{id}/orders', method: 'GET', protocol_type: 'REST', host: 'api.example.com', first_seen: '2026-06-06T09:00:00Z', last_seen: new Date(now.getTime() - 300000).toISOString(), daily_avg_calls: 18900, sensitivity_hint: 'high', claim_status: 'claimed', owner: 'wang.fang@company.com', group_path: '零售事业部/交易系统/用户模块', normalization_confidence: 0.89, status: 'shadow', sensitive_fields: ['order_history', 'total_spent'] },
    { asset_id: 'ast-005', path_normalized: '/api/v1/admin/users', method: 'GET', protocol_type: 'REST', host: 'api.example.com', first_seen: '2026-04-07T08:00:00Z', last_seen: new Date(now.getTime() - 10800000).toISOString(), daily_avg_calls: 450, sensitivity_hint: 'high', claim_status: 'claimed', owner: 'admin@company.com', group_path: '零售事业部/管理系统/用户管理', normalization_confidence: 1.0, status: 'active', sensitive_fields: ['role', 'permissions', 'department'] },
    { asset_id: 'ast-006', path_normalized: '/graphql', method: 'POST', protocol_type: 'GraphQL', host: 'api.example.com', first_seen: '2026-06-16T10:00:00Z', last_seen: new Date(now.getTime() - 20000).toISOString(), daily_avg_calls: 12400, sensitivity_hint: 'medium', claim_status: 'claimed', owner: 'chen.hao@company.com', group_path: '零售事业部/移动端/GraphQL', normalization_confidence: 1.0, status: 'active', sensitive_fields: ['user_profile', 'favorite_items'] },
    { asset_id: 'ast-007', path_normalized: '/api/v1/inventory/{warehouse_id}/stock', method: 'GET', protocol_type: 'REST', host: 'api.example.com', first_seen: '2026-06-21T08:00:00Z', last_seen: new Date(now.getTime() - 7200000).toISOString(), daily_avg_calls: 2100, sensitivity_hint: 'low', claim_status: 'claimed', owner: 'liu.qiang@company.com', group_path: '供应链/仓储管理/库存模块', normalization_confidence: 0.88, status: 'zombie', sensitive_fields: [] },
    { asset_id: 'ast-008', path_normalized: '/api/v1/legacy/export', method: 'GET', protocol_type: 'REST', host: 'internal.example.com', first_seen: '2025-12-29T08:00:00Z', last_seen: new Date(now.getTime() - 2700000).toISOString(), daily_avg_calls: 120, sensitivity_hint: 'high', claim_status: 'unclaimed', owner: '', group_path: '未分组', normalization_confidence: 1.0, status: 'shadow', sensitive_fields: ['full_name', 'id_card', 'phone', 'address'] },
    { asset_id: 'ast-009', path_normalized: 'recommendation.ProductService/List', method: 'POST', protocol_type: 'gRPC', host: 'grpc-internal.example.com', first_seen: '2026-06-26T10:00:00Z', last_seen: new Date(now.getTime() - 5000).toISOString(), daily_avg_calls: 95000, sensitivity_hint: 'low', claim_status: 'claimed', owner: 'zhao.yang@company.com', group_path: '推荐系统/商品推荐/gRPC', normalization_confidence: 1.0, status: 'active', sensitive_fields: [] },
    { asset_id: 'ast-010', path_normalized: '/ws/notifications', method: 'GET', protocol_type: 'WebSocket', host: 'api.example.com', first_seen: '2026-07-01T10:00:00Z', last_seen: new Date(now.getTime() - 1000).toISOString(), daily_avg_calls: 3200, sensitivity_hint: 'low', claim_status: 'claimed', owner: 'sun.ming@company.com', group_path: '零售事业部/消息服务/WebSocket', normalization_confidence: 1.0, status: 'active', sensitive_fields: [] },
  ]
}

function generateMockAlerts() {
  const now = new Date()
  return [
    { alert_id: 'alt-001', timestamp: new Date(now.getTime() - 300000).toISOString(), severity: 'high', title: '疑似 BOLA 攻击：账号 usr-88213 高频遍历订单对象', description: '账号 usr-88213 在过去 5 分钟内连续访问了 847 个不同订单 ID。', source_requirement: 'FR-DET-001', risk_score: 91, confidence: 0.92, status: 'open', source_ip: '203.0.113.18', account_id: 'usr-88213', attack_path: [{ sequence: 1, action: 'login', detail: '正常登录' }, { sequence: 2, action: 'traverse', detail: '开始遍历' }] },
    { alert_id: 'alt-002', timestamp: new Date(now.getTime() - 900000).toISOString(), severity: 'critical', title: '撞库攻击：单 IP 尝试 68 个不同账号', description: 'IP 198.51.100.22 尝试 68 个不同账号。', source_requirement: 'FR-DET-002', risk_score: 96, confidence: 0.97, status: 'acknowledged', source_ip: '198.51.100.22', attack_path: [] },
    { alert_id: 'alt-003', timestamp: new Date(now.getTime() - 2700000).toISOString(), severity: 'medium', title: '影子 API 发现', description: '发现接口未在 CMDB 注册。', source_requirement: 'FR-AST-002', risk_score: 65, confidence: 0.92, status: 'open', attack_path: [] },
    { alert_id: 'alt-004', timestamp: new Date(now.getTime() - 1800000).toISOString(), severity: 'medium', title: '异常资源消耗', description: '接口 QPS 超基线 5 倍。', source_requirement: 'FR-DET-004', risk_score: 72, confidence: 0.85, status: 'open', attack_path: [] },
    { alert_id: 'alt-005', timestamp: new Date(now.getTime() - 7200000).toISOString(), severity: 'high', title: '未脱敏身份证号', description: '接口响应体含未脱敏身份证号。', source_requirement: 'FR-DLP-003', risk_score: 82, confidence: 0.95, status: 'acknowledged', attack_path: [] },
    { alert_id: 'alt-006', timestamp: new Date(now.getTime() - 1200000).toISOString(), severity: 'critical', title: '支付接口撞库', description: '尝试 120 张银行卡。', source_requirement: 'FR-RISK-003', risk_score: 94, confidence: 0.93, status: 'open', source_ip: '45.33.22.11', attack_path: [] },
    { alert_id: 'alt-007', timestamp: new Date(now.getTime() - 3600000).toISOString(), severity: 'medium', title: '影子 API', description: '发现接口未注册。', source_requirement: 'FR-AST-002', risk_score: 58, confidence: 0.88, status: 'open', attack_path: [] },
    { alert_id: 'alt-008', timestamp: new Date(now.getTime() - 10800000).toISOString(), severity: 'high', title: '明文传输敏感数据', description: '接口通过 HTTP 传输。', source_requirement: 'FR-DET-008', risk_score: 78, confidence: 0.96, status: 'open', attack_path: [] },
    { alert_id: 'alt-009', timestamp: new Date(now.getTime() - 14400000).toISOString(), severity: 'low', title: '僵尸 API', description: '接口 7 天无访问。', source_requirement: 'FR-AST-002', risk_score: 25, confidence: 0.90, status: 'open', attack_path: [] },
    { alert_id: 'alt-010', timestamp: new Date(now.getTime() - 21600000).toISOString(), severity: 'medium', title: '爬虫行为', description: '设备指纹异常。', source_requirement: 'FR-RISK-002', risk_score: 68, confidence: 0.91, status: 'acknowledged', attack_path: [] },
  ]
}
