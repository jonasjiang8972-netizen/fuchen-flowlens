// Sensitive data types by field name. Mirrors SensitiveType in
// platform/internal/engine/dlp.go; keep the two in sync.
export const sensitiveTypes = [
  { key: 'id_card', label: '身份证号', level: 'high', markers: ['id_card', 'idcard', 'id_no', 'idno', 'identity', 'cert_no', 'certno', 'sfz'] },
  { key: 'bank_card', label: '银行卡号', level: 'high', markers: ['card', 'bank', 'account_no', 'acct_no', 'iban'] },
  { key: 'phone', label: '手机号', level: 'high', markers: ['phone', 'mobile', 'telephone', 'tel_no', 'telno'] },
  { key: 'credential', label: '凭证', level: 'critical', markers: ['password', 'passwd', 'pwd', 'token', 'secret', 'api_key', 'apikey', 'access_key', 'credential'] },
  { key: 'contact', label: '地址与邮箱', level: 'medium', markers: ['address', 'email'] },
]

export function sensitiveType(field: string): string {
  const n = field.toLowerCase()
  for (const t of sensitiveTypes) {
    if (t.markers.some(m => n.includes(m))) return t.key
  }
  return ''
}

export const sensitiveLabel = (key: string) => sensitiveTypes.find(t => t.key === key)?.label || key
