import { Tag } from '@arco-design/web-react'

interface Props { severity: string; style?: React.CSSProperties }

const SEV_MAP: Record<string, { color: string; label: string }> = {
  critical: { color: 'red', label: '严重' },
  high:     { color: 'orangered', label: '高危' },
  medium:   { color: 'orange', label: '中危' },
  low:      { color: 'blue', label: '低危' },
}

export default function RiskBadge({ severity, style }: Props) {
  const m = SEV_MAP[severity] || SEV_MAP.low
  return <Tag color={m.color} style={style}>{m.label}</Tag>
}
