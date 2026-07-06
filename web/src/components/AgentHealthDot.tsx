interface Props { status: string }

export default function AgentHealthDot({ status }: Props) {
  const cls = status === 'online' ? 'health-dot--online'
    : status === 'offline' ? 'health-dot--offline'
    : 'health-dot--degraded'
  return <span className={`health-dot ${cls}`} />
}
