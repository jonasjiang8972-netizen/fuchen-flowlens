import { useState } from 'react'
import { Card, Table, Tag, Tabs, Typography } from '@arco-design/web-react'
import ReactECharts from 'echarts-for-react'
import { alertService } from '../../services/api'

export default function DataGovernance({ onNavigate }: { onNavigate: (page: string, id?: string) => void }) {
  const [alerts] = useState<any[]>(alertService.list())
  const dlpAlerts = alerts.filter(a => a.source_requirement?.startsWith('FR-DLP') || a.source_requirement === 'FR-DLP-003')

  const flowNodes = [
    { id: 'user-svc', label: '用户服务', category: 0 },
    { id: 'order-svc', label: '订单服务', category: 0 },
    { id: 'payment-svc', label: '支付服务', category: 0 },
    { id: 'phone', label: '手机号', category: 1 },
    { id: 'id_card', label: '身份证', category: 1 },
    { id: 'address', label: '地址', category: 1 },
  ]
  const flowEdges = [
    { source: 'user-svc', target: 'phone' },
    { source: 'user-svc', target: 'id_card' },
    { source: 'order-svc', target: 'phone' },
    { source: 'order-svc', target: 'address' },
    { source: 'payment-svc', target: 'phone' },
  ]

  const flowOption = {
    backgroundColor: 'transparent',
    tooltip: {},
    series: [{
      type: 'graph', layout: 'force', symbolSize: 60, draggable: true,
      roam: true, label: { show: true, color: '#EDEAE0' },
      edgeSymbol: ['', 'arrow'], edgeLabel: { fontSize: 10 },
      force: { repulsion: 400, edgeLength: 200 },
      categories: [{ name: '服务', itemStyle: { color: '#3FBDAA' } }, { name: '字段', itemStyle: { color: '#D99A3D' } }],
      data: flowNodes,
      links: flowEdges.map(e => ({ source: e.source, target: e.target, lineStyle: { color: '#25344A', width: 2 } })),
    }],
  }

  const defectColumns = [
    { title: '接口', dataIndex: 'path', key: 'path' },
    { title: '字段', dataIndex: 'field', key: 'field' },
    { title: '缺陷类型', dataIndex: 'type', key: 'type', render: (t: string) => <Tag color="red">{t}</Tag> },
    { title: '检测时间', dataIndex: 'time', key: 'time', width: 160 },
  ]
  const defectData = [
    { path: '/api/v1/user/{id}', field: 'id_card_no', type: '未脱敏', time: new Date(Date.now() - 7200000).toLocaleString('zh-CN') },
    { path: '/api/v1/legacy/export', field: 'phone', type: '未脱敏', time: new Date(Date.now() - 10800000).toLocaleString('zh-CN') },
    { path: '/api/v1/user/{id}/orders', field: 'address', type: '部分脱敏', time: new Date(Date.now() - 3600000).toLocaleString('zh-CN') },
  ]

  return (
    <div className="page-enter">
      <Tabs defaultActiveTab="overview">
        <Tabs.TabPane key="overview" title="敏感字段总览">
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
            <Card className="panel-card">
              <div style={{ fontSize: 12, color: '#8A93A3', marginBottom: 8 }}>检测中的敏感字段数</div>
              <div style={{ fontSize: 28, fontWeight: 700, color: '#EDEAE0' }}>12</div>
            </Card>
            <Card className="panel-card">
              <div style={{ fontSize: 12, color: '#8A93A3', marginBottom: 8 }}>脱敏缺陷</div>
              <div style={{ fontSize: 28, fontWeight: 700, color: '#D14D3D' }}>{defectData.length}</div>
            </Card>
          </div>
          <Card className="panel-card" title={<span style={{ color: '#EDEAE0', fontSize: 15 }}>数据流动图谱</span>}>
            <ReactECharts option={flowOption} style={{ height: 400, width: '100%' }} />
          </Card>
        </Tabs.TabPane>
        <Tabs.TabPane key="defects" title="脱敏缺陷看板">
          <Card className="panel-card">
            <Table columns={defectColumns} data={defectData} pagination={false} />
          </Card>
        </Tabs.TabPane>
        <Tabs.TabPane key="reports" title="合规报告中心">
          <Card className="panel-card">
            <div style={{ color: '#8A93A3' }}>合规报告生成功能将在 V1.0 版本提供</div>
          </Card>
        </Tabs.TabPane>
      </Tabs>
    </div>
  )
}
