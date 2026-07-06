import { useState } from 'react'
import { Tooltip } from '@arco-design/web-react'
import { IconCopy } from '@arco-design/web-react/icon'

interface Props { children: string; copyable?: boolean }

export default function EvidenceText({ children, copyable = true }: Props) {
  const [copied, setCopied] = useState(false)
  const handleCopy = () => {
    navigator.clipboard.writeText(children)
    setCopied(true); setTimeout(() => setCopied(false), 1500)
  }
  return (
    <span className="mono" style={{ color: 'var(--color-text-primary)', fontSize: 13 }}>
      {children}
      {copyable && (
        <Tooltip content={copied ? '已复制' : '复制'}>
          <IconCopy
            style={{ marginLeft: 6, color: 'var(--color-text-secondary)', cursor: 'pointer', fontSize: 13 }}
            onClick={handleCopy}
          />
        </Tooltip>
      )}
    </span>
  )
}
