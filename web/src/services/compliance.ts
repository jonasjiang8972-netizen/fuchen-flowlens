import { message } from 'antd'
import { API_BASE, ApiError, DEMO, errorMessage, request } from './http'

export type CheckStatus = 'pass' | 'partial' | 'fail' | 'manual'
export type CheckBasis = 'live' | 'capability' | 'manual'

export interface Check {
  id: string
  category: string
  title: string
  requirement: string
  ref: string
  status: CheckStatus
  basis: CheckBasis
  evidence: string
  remediation?: string
}

export interface Report {
  template: string
  title: string
  generated_at: string
  disclaimer: string
  demo?: boolean
  summary: { pass: number; partial: number; fail: number; manual: number; total: number }
  sections: { category: string; checks: Check[] }[]
}

export interface TemplateInfo {
  id: string
  title: string
  description: string
}

const TEMPLATES: TemplateInfo[] = [
  { id: 'mlps3', title: '等保 2.0 三级自查', description: '对照 GB/T 22239-2019 第三级的安全通信网络、安全计算环境、安全管理中心要求，逐项给出运行状态和证据' },
  { id: 'finance', title: '金融行业自查', description: '在等保三级自查基础上，突出个人金融信息保护、数据分级与日志留存，条目引用 JR/T 0071、JR/T 0171、JR/T 0197 与相关法律' },
]

export const complianceService = {
  templates: async (): Promise<TemplateInfo[]> => {
    if (DEMO) return TEMPLATES
    try {
      return (await request<{ items: TemplateInfo[] }>('/reports/compliance/templates')).items
    } catch (err) {
      if (!(err instanceof ApiError && err.status === 401)) message.error(errorMessage(err))
      return []
    }
  },
  // Throws on failure so the page can show why (for example: not permitted).
  generate: async (template: string): Promise<Report> => (DEMO ? demoReport(template) : request<Report>(`/reports/compliance?template=${encodeURIComponent(template)}`)),
  exportUrl: (template: string, format: 'html' | 'csv') => `${API_BASE}/reports/compliance/export?template=${encodeURIComponent(template)}&format=${format}`,
}

// ─── Demo build ─────────────────────────────────────────────────
// A short sample in the shape the platform returns. It describes an invented
// deployment and is labelled as such; it says nothing about a real system.

const DISCLAIMER = '本报告是产品对自身运行状态的自查，不是等保测评结论，也不能替代测评机构出具的报告。“实时”项由平台当前的配置和数据判定；“能力”项说明产品是否实现了相应功能，取自代码而非现场验证；“需人工”项涉及机房、制度、人员、演练等软件无法判断的内容。条款编号仅作定位，请以标准原文为准。'

function demoReport(template: string): Report {
  const finance = template === 'finance'
  const c = (id: string, category: string, title: string, requirement: string, ref: string, status: CheckStatus, basis: CheckBasis, evidence: string, remediation?: string): Check =>
    ({ id, category, title, requirement, ref, status, basis, evidence, remediation })
  const std = finance ? 'JR/T 0071-2020；GB/T 22239-2019' : 'GB/T 22239-2019'
  const sections = [
    { category: '身份鉴别', checks: [
      c('ID-1', '身份鉴别', '口令复杂度、有效期与历史', '口令有复杂度要求并定期更换，不能重复使用旧口令', `${std} 8.1.4.1`, 'pass', 'live', '最短 8 位，须含 3 类字符；90 天强制更换；不得与最近 5 次相同'),
      c('ID-4', '身份鉴别', '初始口令已修改', '默认账号和初始口令必须在首次使用时修改', `${std} 8.1.4.2`, 'fail', 'live', '1 个启用账号仍在使用初始口令（系统会在首次登录时强制修改）；账号总数 5', '让这些账号完成首次登录并修改口令，或在系统管理后台停用不用的账号'),
      c('ID-5', '身份鉴别', '双因素认证', '采用口令、密码技术、生物技术中两种或以上组合的鉴别', `${std} 8.1.4.1`, 'fail', 'capability', '目前只支持用户名加口令，尚未实现 TOTP 动态口令或 USB Key / 数字证书登录', '接入 TOTP 或国密 USB Key 登录（路线图中尚未排期）'),
    ] },
    { category: '安全审计', checks: [
      c('AU-1', '安全审计', '日志留存不少于六个月', '网络日志留存不少于六个月', '网络安全法第二十一条', 'pass', 'live', '审计日志保留 180 天（下限 180 天，不能配置得更低）'),
      c('AU-3', '安全审计', '审计日志防篡改', '对审计记录进行保护，避免被未预期地删除、修改或覆盖', `${std} 8.1.4.3`, 'pass', 'live', 'SM3 哈希链校验通过（本次校验 1284 条）'),
    ] },
    { category: '通信传输与密码应用', checks: [
      c('TR-1', '通信传输与密码应用', '控制台与 API 传输加密', '通信过程中对整个报文或会话过程进行加密', `${std} 8.1.2`, 'partial', 'live', '已按 HTTPS 部署，由前置代理终止 TLS；平台无法验证代理侧的证书和协议版本，请人工核查'),
      c('TR-3', '通信传输与密码应用', '商用密码应用（SM2 / SM3 / SM4）', '身份鉴别、传输、存储中使用商用密码', 'GB/T 39786-2021 第三级', 'partial', 'capability', '已使用 SM3：审计哈希链、会话令牌哈希、凭证指纹。未实现：SM2 证书登录、SM4 存储加密、国密 TLS', '国密改造属于路线图 v1.3.0'),
    ] },
    { category: '入侵防范与处置响应', checks: [
      c('IR-2', '入侵防范与处置响应', '告警及时处置', '发现攻击行为后及时报告和处置', std, 'partial', 'live', '没有超时工单，但 1 张临近超时、1 张开放工单没有负责人', '在处置闭环页优先处理超时和无负责人的工单'),
      c('IR-4', '入侵防范与处置响应', '联动处置能力', '具备对攻击源采取阻断措施的能力', std, 'partial', 'live', '已配置 1 个联动系统，但处于演练模式，封禁只记录不执行', '按 docs/SOAR.md 配置网关或 WAF 联动；先用演练模式验证'),
    ] },
    { category: '管理制度与人工核查', checks: [
      c('MG-3', '管理制度与人工核查', '数据备份与恢复演练', '重要数据定期备份，并验证可以恢复', std, 'manual', 'manual', '平台数据全部在 PostgreSQL，备份、异地存放和恢复演练由数据库运维负责；平台本身不做备份，也没有验证过恢复'),
    ] },
  ]
  if (finance) {
    sections.splice(3, 0, { category: '数据安全与个人信息保护', checks: [
      c('DA-4', '数据安全与个人信息保护', '数据分级与全生命周期管理', '按金融数据分级指南对数据分级，并落实全生命周期保护', 'JR/T 0197-2020；JR/T 0223-2021', 'fail', 'capability', '只有低/中/高的敏感度提示，没有对齐 JR/T 0197 的分级，也没有保留期与销毁管理', '需要数据分级模型和保留期策略；路线图尚未排期'),
    ] })
  }
  const all = sections.flatMap(s => s.checks)
  const count = (st: CheckStatus) => all.filter(x => x.status === st).length
  return {
    template, title: `${TEMPLATES.find(t => t.id === template)?.title ?? template}报告`, generated_at: new Date().toISOString(), disclaimer: DISCLAIMER, demo: true,
    summary: { pass: count('pass'), partial: count('partial'), fail: count('fail'), manual: count('manual'), total: all.length }, sections,
  }
}
