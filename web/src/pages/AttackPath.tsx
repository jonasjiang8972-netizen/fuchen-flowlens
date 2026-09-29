import { useEffect, useState } from 'react'
import { Alert, Button, Card, Col, Empty, Row, Space, Spin, Tag } from 'antd'
import { AimOutlined, ArrowRightOutlined, FireOutlined, ReloadOutlined, ThunderboltOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import ForceGraph from '../components/ForceGraph'
import type { GraphNode } from '../components/ForceGraph'
import { graphService } from '../services/graph'
import type { AttackGraph, AttackPathSummary } from '../services/graph'

interface Props {
  // Alert to focus on when opened from an alert; empty shows every source.
  alertId?: string
  onNavigate: (page: string, id?: string) => void
}

const SEV_COLOR: Record<string, string> = { critical: 'red', high: 'orange', medium: 'gold', low: 'blue' }

export default function AttackPath({ alertId, onNavigate }: Props) {
  const [focus, setFocus] = useState<string | undefined>(alertId || undefined)
  const [graph, setGraph] = useState<AttackGraph | null>(null)
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<GraphNode | null>(null)

  useEffect(() => { setFocus(alertId || undefined) }, [alertId])

  const load = () => {
    setLoading(true)
    graphService.attack(focus).then(g => { setGraph(g); setSelected(null) }).finally(() => setLoading(false))
  }
  useEffect(load, [focus])

  const paths = graph?.paths ?? []
  const escalating = paths.filter(p => p.escalating)
  const critical = paths.filter(p => p.severity === 'critical')

  const openAlert = (node: GraphNode | null) => {
    setSelected(node)
  }

  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">攻击路径</div>
          <div className="page-heading__desc">把同一来源触发的告警按时间串成攻击链，并叠加它实际访问过的账号、接口和暴露的敏感字段。</div>
        </div>
        <Space>
          {focus && <Button onClick={() => setFocus(undefined)}>查看全部来源</Button>}
          <Button icon={<ReloadOutlined />} onClick={load} loading={loading}>刷新</Button>
        </Space>
      </div>

      <div className="metric-grid">
        <Card className="metric-card">
          <div className="metric-card__label"><AimOutlined /> 攻击来源</div>
          <div className="metric-card__value">{paths.length}</div>
          <div className="metric-card__meta">触发过未关闭告警的来源地址</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><ThunderboltOutlined /> 攻击升级</div>
          <div className="metric-card__value">{escalating.length}</div>
          <div className="metric-card__meta">后续阶段比前序更深入（如撞库后外泄）</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><FireOutlined /> 严重来源</div>
          <div className="metric-card__value">{critical.length}</div>
          <div className="metric-card__meta">至少触发一条严重告警</div>
        </Card>
      </div>

      {graph?.stats.truncated && (
        <Alert type="info" showIcon style={{ marginBottom: 12 }} message="只显示风险最高的来源。点击某个来源可聚焦查看。" />
      )}

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={16}>
          <Card title={focus ? '攻击链图（已聚焦）' : '攻击链图'}>
            <Spin spinning={loading}>
              <ForceGraph
                nodes={graph?.nodes ?? []} links={graph?.edges ?? []} height={580} layered
                selectedId={selected?.id} onSelect={openAlert}
                emptyText={loading ? '' : '当前没有需要关注的攻击来源'}
              />
            </Spin>
            {selected?.kind === 'alert' && (
              <div style={{ marginTop: 12 }}>
                <span className="muted">已选告警：</span>{selected.label}
                <Button type="link" onClick={() => onNavigate('alert-detail', selected.id.replace(/^alert:/, ''))}>打开告警详情</Button>
              </div>
            )}
          </Card>
        </Col>
        <Col xs={24} xl={8}>
          <Card title="按来源的攻击链">
            {paths.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无攻击链" /> : (
              <Space direction="vertical" size={14} style={{ width: '100%' }}>
                {paths.map(p => <PathCard key={p.actor} path={p} onFocus={() => setFocus(p.steps[0].alert_id)} onOpen={id => onNavigate('alert-detail', id)} />)}
              </Space>
            )}
          </Card>
        </Col>
      </Row>
    </div>
  )
}

function PathCard({ path, onFocus, onOpen }: { path: AttackPathSummary; onFocus: () => void; onOpen: (alertId: string) => void }) {
  return (
    <div style={{ border: '1px solid var(--fl-border-soft, #edf1f6)', borderRadius: 8, padding: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <span className="asset-path" style={{ fontWeight: 600 }}>{path.actor}</span>
        <Tag color={path.zone === 'internal' ? 'default' : 'processing'}>{path.zone === 'internal' ? '内网' : '外网'}</Tag>
        <Tag color={SEV_COLOR[path.severity]}>{path.severity}</Tag>
        {path.escalating && <Tag color="volcano">攻击升级</Tag>}
        <Button type="link" size="small" style={{ marginLeft: 'auto', padding: 0 }} onClick={onFocus}>聚焦</Button>
      </div>
      {path.accounts && path.accounts.length > 0 && (
        <div className="muted" style={{ marginTop: 4, fontSize: 12 }}>涉及账号：{path.accounts.join('、')}</div>
      )}
      <div style={{ marginTop: 8, display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 6 }}>
        {path.steps.map((s, i) => (
          <span key={s.alert_id} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            {i > 0 && <ArrowRightOutlined style={{ color: '#94a3b8', fontSize: 11 }} />}
            <Tag color={SEV_COLOR[s.severity]} style={{ cursor: 'pointer', margin: 0 }} title={`${s.title}\n${dayjs(s.time).format('MM-DD HH:mm:ss')}`} onClick={() => onOpen(s.alert_id)}>
              {s.stage}
            </Tag>
          </span>
        ))}
      </div>
    </div>
  )
}
