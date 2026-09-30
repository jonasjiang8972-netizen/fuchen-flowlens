import { useEffect, useMemo, useRef, useState } from 'react'
import { forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY } from 'd3-force'
import type { SimulationLinkDatum, SimulationNodeDatum } from 'd3-force'
import { select } from 'd3-selection'
import { zoom, zoomIdentity } from 'd3-zoom'
import { drag } from 'd3-drag'

export interface GraphNode {
  id: string
  kind: string
  label: string
  layer: number
  calls?: number
  errors?: number
  risk?: string
  zone?: string
  detail?: string
}

export interface GraphLink {
  source: string
  target: string
  kind?: string
  label?: string
  calls?: number
  errors?: number
}

interface Props {
  nodes: GraphNode[]
  links: GraphLink[]
  height?: number
  selectedId?: string | null
  onSelect?: (node: GraphNode | null) => void
  // Pull nodes into columns by layer (left to right) instead of a free layout.
  layered?: boolean
  emptyText?: string
}

type SimNode = GraphNode & SimulationNodeDatum
type SimLink = SimulationLinkDatum<SimNode> & { raw: GraphLink }

export const KIND_LABEL: Record<string, string> = {
  client: '调用方', service: '服务', endpoint: '接口', field: '敏感字段',
  actor: '攻击来源', account: '账号', alert: '告警',
}

const KIND_FILL: Record<string, string> = {
  client: '#2563a9', service: '#117865', endpoint: '#ffffff', field: '#c9352b',
  actor: '#8b1f18', account: '#d96b20', alert: '#b7791f',
}

const RISK_STROKE: Record<string, string> = {
  critical: '#c9352b', high: '#d96b20', medium: '#b7791f', low: '#2563a9',
}

export const nodeFill = (n: GraphNode) => {
  if (n.kind === 'client' && n.zone === 'internal') return '#64748b'
  if (n.kind === 'alert') return RISK_STROKE[n.risk || ''] || KIND_FILL.alert
  return KIND_FILL[n.kind] || '#94a3b8'
}

const radius = (n: GraphNode, max: number) => {
  const base = n.kind === 'field' ? 9 : n.kind === 'endpoint' ? 10 : 13
  if (!n.calls || max <= 0) return base
  return base + Math.min(10, Math.sqrt(n.calls / max) * 10)
}

const truncate = (s: string, n = 20) => (s.length > n ? `${s.slice(0, n - 1)}…` : s)

export default function ForceGraph({ nodes, links, height = 460, selectedId, onSelect, layered = true, emptyText = '暂无数据' }: Props) {
  const wrapRef = useRef<HTMLDivElement>(null)
  const svgRef = useRef<SVGSVGElement>(null)
  const [width, setWidth] = useState(800)
  const [tip, setTip] = useState<{ x: number; y: number; node: GraphNode } | null>(null)
  const onSelectRef = useRef(onSelect)
  onSelectRef.current = onSelect

  useEffect(() => {
    const el = wrapRef.current
    if (!el) return
    const ro = new ResizeObserver(entries => {
      const w = Math.floor(entries[0].contentRect.width)
      if (w > 0) setWidth(w)
    })
    ro.observe(el)
    setWidth(el.clientWidth || 800)
    return () => ro.disconnect()
  }, [])

  const kinds = useMemo(() => Array.from(new Set(nodes.map(n => n.kind))), [nodes])

  useEffect(() => {
    const svgEl = svgRef.current
    if (!svgEl) return
    const svg = select(svgEl)
    svg.selectAll('*').remove()
    if (nodes.length === 0) return

    const simNodes: SimNode[] = nodes.map(n => ({ ...n }))
    const byId = new Map(simNodes.map(n => [n.id, n]))
    const simLinks: SimLink[] = links
      .filter(l => byId.has(l.source) && byId.has(l.target))
      .map(l => ({ source: l.source, target: l.target, raw: l }))
    const maxCalls = Math.max(1, ...nodes.map(n => n.calls || 0))
    const maxLinkCalls = Math.max(1, ...links.map(l => l.calls || 0))
    const maxLayer = Math.max(1, ...nodes.map(n => n.layer))
    const colX = (layer: number) => 70 + (layer / maxLayer) * Math.max(200, width - 140)

    // Neighbours, for highlight on hover.
    const neighbours = new Map<string, Set<string>>()
    simNodes.forEach(n => neighbours.set(n.id, new Set([n.id])))
    simLinks.forEach(l => {
      neighbours.get(l.raw.source)?.add(l.raw.target)
      neighbours.get(l.raw.target)?.add(l.raw.source)
    })

    const defs = svg.append('defs')
    ;[['flow', '#94a3b8'], ['sequence', '#b7791f']].forEach(([id, color]) => {
      defs.append('marker').attr('id', `arrow-${id}`).attr('viewBox', '0 -5 10 10').attr('refX', 10).attr('refY', 0)
        .attr('markerWidth', 6).attr('markerHeight', 6).attr('orient', 'auto')
        .append('path').attr('d', 'M0,-5L10,0L0,5').attr('fill', color)
    })

    const root = svg.append('g')
    const linkSel = root.append('g').selectAll<SVGPathElement, SimLink>('path').data(simLinks).join('path')
      .attr('fill', 'none')
      .attr('stroke', d => (d.raw.kind === 'sequence' ? '#b7791f' : '#94a3b8'))
      .attr('stroke-dasharray', d => (d.raw.kind === 'sequence' ? '5 4' : null))
      .attr('stroke-width', d => 1 + Math.sqrt((d.raw.calls || 1) / maxLinkCalls) * 3)
      .attr('stroke-opacity', 0.75)
      .attr('marker-end', d => `url(#arrow-${d.raw.kind === 'sequence' ? 'sequence' : 'flow'})`)
    linkSel.append('title').text(d => `${d.raw.label || ''}${d.raw.calls ? ` · ${d.raw.calls} 次` : ''}${d.raw.errors ? ` · ${d.raw.errors} 失败` : ''}`.replace(/^ · /, ''))

    const linkLabel = root.append('g').selectAll<SVGTextElement, SimLink>('text')
      .data(simLinks.filter(l => l.raw.label))
      .join('text').attr('font-size', 10).attr('fill', '#475569').attr('text-anchor', 'middle').attr('pointer-events', 'none')
      .attr('paint-order', 'stroke').attr('stroke', '#f8fafc').attr('stroke-width', 3)
      .attr('opacity', d => (d.raw.kind === 'sequence' ? 1 : 0))
      .text(d => d.raw.label || '')

    const nodeSel = root.append('g').selectAll<SVGGElement, SimNode>('g').data(simNodes, d => d.id).join('g')
      .attr('cursor', 'pointer')
    nodeSel.each(function (d) {
      const g = select(this)
      const r = radius(d, maxCalls)
      const stroke = RISK_STROKE[d.risk || ''] || (d.kind === 'endpoint' ? '#117865' : '#ffffff')
      const sw = d.risk ? 3 : 2
      if (d.kind === 'endpoint') {
        g.append('rect').attr('x', -r).attr('y', -r * 0.7).attr('width', r * 2).attr('height', r * 1.4).attr('rx', 5)
          .attr('fill', nodeFill(d)).attr('stroke', stroke).attr('stroke-width', sw)
      } else if (d.kind === 'field') {
        g.append('path').attr('d', `M0,${-r}L${r},0L0,${r}L${-r},0Z`).attr('fill', nodeFill(d)).attr('stroke', stroke).attr('stroke-width', sw)
      } else {
        g.append('circle').attr('r', r).attr('fill', nodeFill(d)).attr('stroke', stroke).attr('stroke-width', sw)
      }
      g.append('text').attr('class', 'fg-label').attr('y', r + 13).attr('text-anchor', 'middle')
        .attr('font-size', 11).attr('fill', '#142033').attr('pointer-events', 'none')
        .attr('paint-order', 'stroke').attr('stroke', '#ffffff').attr('stroke-width', 3).text(truncate(d.label))
    })

    const highlight = (id: string | null) => {
      nodeSel.attr('opacity', d => (!id || neighbours.get(id)?.has(d.id) ? 1 : 0.15))
      linkSel.attr('stroke-opacity', d => (!id ? 0.75 : d.raw.source === id || d.raw.target === id ? 1 : 0.05))
      // Edge captions stay out of the way until a node is hovered.
      linkLabel.attr('opacity', d => (id ? (d.raw.source === id || d.raw.target === id ? 1 : 0) : d.raw.kind === 'sequence' ? 1 : 0))
    }
    nodeSel
      .on('mouseenter', (ev: MouseEvent, d) => {
        highlight(d.id)
        const box = wrapRef.current?.getBoundingClientRect()
        if (box) setTip({ x: ev.clientX - box.left, y: ev.clientY - box.top, node: d })
      })
      .on('mousemove', (ev: MouseEvent, d) => {
        const box = wrapRef.current?.getBoundingClientRect()
        if (box) setTip({ x: ev.clientX - box.left, y: ev.clientY - box.top, node: d })
      })
      .on('mouseleave', () => { highlight(null); setTip(null) })
      .on('click', (ev: MouseEvent, d) => { ev.stopPropagation(); onSelectRef.current?.(nodes.find(n => n.id === d.id) || null) })
    svg.on('click', () => onSelectRef.current?.(null))

    const sim = forceSimulation<SimNode>(simNodes)
      .force('link', forceLink<SimNode, SimLink>(simLinks).id(d => d.id).distance(layered ? 90 : 110).strength(0.35))
      .force('charge', forceManyBody().strength(layered ? -420 : -320))
      .force('collide', forceCollide<SimNode>().radius(d => radius(d, maxCalls) + 20))
      .force('y', forceY(height / 2).strength(0.045))
    if (layered) sim.force('x', forceX<SimNode>(d => colX(d.layer)).strength(0.9))
    else sim.force('x', forceX(width / 2).strength(0.05))

    const linkPath = (d: SimLink) => {
      const s = d.source as SimNode, t = d.target as SimNode
      const sx = s.x || 0, sy = s.y || 0, tx = t.x || 0, ty = t.y || 0
      const dx = tx - sx, dy = ty - sy
      const len = Math.hypot(dx, dy) || 1
      const rt = radius(t, maxCalls) + 3
      const ex = tx - (dx / len) * rt, ey = ty - (dy / len) * rt
      const bend = d.raw.kind === 'sequence' ? 0.25 : 0
      const mx = (sx + ex) / 2 - dy * bend, my = (sy + ey) / 2 + dx * bend
      return `M${sx},${sy}Q${mx},${my} ${ex},${ey}`
    }
    sim.on('tick', () => {
      simNodes.forEach(n => {
        n.x = Math.max(20, Math.min(width - 20, n.x || 0))
        n.y = Math.max(20, Math.min(height - 24, n.y || 0))
      })
      linkSel.attr('d', linkPath)
      linkLabel
        .attr('x', d => (((d.source as SimNode).x || 0) + ((d.target as SimNode).x || 0)) / 2)
        .attr('y', d => (((d.source as SimNode).y || 0) + ((d.target as SimNode).y || 0)) / 2 - 4)
      nodeSel.attr('transform', d => `translate(${d.x || 0},${d.y || 0})`)
    })

    nodeSel.call(
      drag<SVGGElement, SimNode>()
        .on('start', (ev, d) => { if (!ev.active) sim.alphaTarget(0.25).restart(); d.fx = d.x; d.fy = d.y })
        .on('drag', (ev, d) => { d.fx = ev.x; d.fy = ev.y })
        .on('end', (ev, d) => { if (!ev.active) sim.alphaTarget(0); d.fx = null; d.fy = null }),
    )

    const zoomer = zoom<SVGSVGElement, unknown>().scaleExtent([0.3, 4]).on('zoom', ev => root.attr('transform', ev.transform.toString()))
    svg.call(zoomer).on('dblclick.zoom', null)
    svg.call(zoomer.transform, zoomIdentity)

    return () => { sim.stop() }
  }, [nodes, links, width, height, layered])

  // Selection ring, kept separate so selecting does not restart the layout.
  useEffect(() => {
    const svg = svgRef.current
    if (!svg) return
    select(svg).selectAll<SVGGElement, SimNode>('g > g > g').each(function (d) {
      if (!d) return
      const shape = select(this).select<SVGElement>('circle,rect,path')
      const base = RISK_STROKE[d.risk || ''] || (d.kind === 'endpoint' ? '#117865' : '#ffffff')
      shape.attr('stroke', d.id === selectedId ? '#142033' : base).attr('stroke-width', d.id === selectedId ? 4 : d.risk ? 3 : 2)
    })
  }, [selectedId, nodes, links])

  return (
    <div ref={wrapRef} style={{ position: 'relative', width: '100%' }}>
      {kinds.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 14, marginBottom: 8, fontSize: 12, color: '#64748b' }}>
          {kinds.map(k => (
            <span key={k} style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
              <span style={{ width: 10, height: 10, borderRadius: k === 'endpoint' ? 3 : k === 'field' ? 0 : 5, transform: k === 'field' ? 'rotate(45deg) scale(0.8)' : undefined, background: KIND_FILL[k] || '#94a3b8', border: '1px solid #94a3b8' }} />
              {KIND_LABEL[k] || k}
            </span>
          ))}
          <span style={{ marginLeft: 'auto' }}>滚轮缩放 · 拖动平移 · 点击查看详情</span>
        </div>
      )}
      <svg ref={svgRef} width={width} height={height} style={{ display: 'block', background: '#f8fafc', border: '1px solid #edf1f6', borderRadius: 8 }} role="img" aria-label="关系图" />
      {nodes.length === 0 && (
        <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#94a3b8', pointerEvents: 'none' }}>{emptyText}</div>
      )}
      {tip && (
        <div style={{ position: 'absolute', left: Math.min(tip.x + 14, width - 230), top: tip.y + 14, maxWidth: 220, background: '#142033', color: '#fff', padding: '6px 10px', borderRadius: 6, fontSize: 12, pointerEvents: 'none', zIndex: 5, lineHeight: 1.5 }}>
          <div style={{ fontWeight: 600, wordBreak: 'break-all' }}>{tip.node.label}</div>
          <div style={{ opacity: 0.8 }}>{KIND_LABEL[tip.node.kind] || tip.node.kind}{tip.node.zone ? (tip.node.zone === 'internal' ? ' · 内网' : ' · 外网') : ''}</div>
          {tip.node.calls ? <div style={{ opacity: 0.8 }}>{tip.node.calls} 次调用{tip.node.errors ? ` · ${tip.node.errors} 失败` : ''}</div> : null}
          {tip.node.detail ? <div style={{ opacity: 0.8 }}>{tip.node.detail}</div> : null}
        </div>
      )}
    </div>
  )
}
