import { useEffect, useState } from 'react'
import { Card, Table, Tag, Tabs, Typography, Switch, Modal, Descriptions, Button, Form, InputNumber, Select, Message } from '@arco-design/web-react'
import { ruleService } from '../services/api'

export default function Rules({ onNavigate }: { onNavigate: (page: string, id?: string) => void }) {
  const [rules, setRules] = useState<any[]>([])
  const [categories, setCategories] = useState<string[]>([])
  const [selectedRule, setSelectedRule] = useState<any>(null)
  const [detailVisible, setDetailVisible] = useState(false)
  const [tab, setTab] = useState('all')

  useEffect(() => {
    ruleService.list().then(setRules)
    ruleService.categories().then(setCategories)
  }, [])

  const handleToggle = async (ruleId: string, enabled: boolean) => {
    await ruleService.update(ruleId, { enabled })
    setRules(prev => prev.map(r => r.rule_id === ruleId ? { ...r, enabled } : r))
    Message.success(`规则 ${enabled ? '已启用' : '已禁用'}`)
  }

  const handleView = async (ruleId: string) => {
    const detail = await ruleService.detail(ruleId)
    setSelectedRule(detail)
    setDetailVisible(true)
  }

  const handleApplyConfig = async (ruleId: string, key: string, value: any) => {
    await ruleService.update(ruleId, { config: { [key]: value } })
    Message.success('配置已更新')
  }

  const filteredRules = tab === 'all' ? rules : rules.filter(r => r.category === tab)

  const columns = [
    { title: '规则ID', dataIndex: 'rule_id', key: 'id', width: 120, render: (id: string) => <span className="mono">{id}</span> },
    { title: '名称', dataIndex: 'name', key: 'name' },
    { title: '所属需求', dataIndex: 'source_requirement', key: 'fr', width: 120, render: (fr: string) => <Tag>{fr}</Tag> },
    { title: '分类', dataIndex: 'category', key: 'category', width: 100, render: (c: string) => <Tag color="blue">{c}</Tag> },
    { title: '等级', dataIndex: 'severity', key: 'severity', width: 80,
      render: (s: string) => <Tag color={{ critical: 'red', high: 'orangered', medium: 'orange', low: 'blue' }[s]}>{s}</Tag> },
    { title: '状态', dataIndex: 'enabled', key: 'enabled', width: 80,
      render: (enabled: boolean, record: any) => <Switch checked={enabled} onChange={(v) => handleToggle(record.rule_id, v)} /> },
    { title: '命中次数', dataIndex: 'hit_count', key: 'hits', width: 100 },
    { title: '操作', key: 'action', width: 80,
      render: (_: any, record: any) => <Button size="small" type="primary" onClick={() => handleView(record.rule_id)}>查看</Button> },
  ]

  return (
    <div className="page-enter">
      <Card className="panel-card" style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <span style={{ color: '#EDEAE0', fontSize: 15, fontWeight: 600 }}>检测规则管理</span>
            <span style={{ color: '#8A93A3', fontSize: 12, marginLeft: 8 }}>共 {rules.length} 条规则 · 可见 · 可知 · 可控 · 可优化</span>
          </div>
          <div style={{ color: '#8A93A3', fontSize: 12 }}>已启用: {rules.filter(r => r.enabled).length} / {rules.length}</div>
        </div>
      </Card>

      <Card className="panel-card">
        <Tabs activeTab={tab} onChange={setTab}>
          <Tabs.TabPane key="all" title="全部" />
          {categories.map(c => (
            <Tabs.TabPane key={c} title={c} />
          ))}
        </Tabs>
        <Table columns={columns} data={filteredRules} rowKey="rule_id" pagination={false} />
      </Card>

      <Modal
        title={<span style={{ color: '#EDEAE0' }}>规则详情: {selectedRule?.rule_id}</span>}
        visible={detailVisible}
        onCancel={() => setDetailVisible(false)}
        footer={null}
        width={720}
      >
        {selectedRule && (
          <div style={{ color: '#EDEAE0' }}>
            <Descriptions bordered column={2} size="small" labelStyle={{ color: '#8A93A3' }}>
              <Descriptions.Item label="规则ID"><span className="mono">{selectedRule.rule_id}</span></Descriptions.Item>
              <Descriptions.Item label="所属需求">{selectedRule.source_requirement}</Descriptions.Item>
              <Descriptions.Item label="名称">{selectedRule.name}</Descriptions.Item>
              <Descriptions.Item label="分类">
                <Tag color="blue">{selectedRule.category}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="严重等级">
                <Tag color={{ critical: 'red', high: 'orangered', medium: 'orange', low: 'blue' }[selectedRule.severity]}>{selectedRule.severity}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="状态">
                <Switch checked={selectedRule.enabled} onChange={(v) => handleToggle(selectedRule.rule_id, v)} />
              </Descriptions.Item>
              <Descriptions.Item label="描述" span={2}>{selectedRule.description}</Descriptions.Item>
              <Descriptions.Item label="建议" span={2}>{selectedRule.recommendation}</Descriptions.Item>
              <Descriptions.Item label="基础评分">{selectedRule.default_risk_score}</Descriptions.Item>
              <Descriptions.Item label="命中次数">{selectedRule.hit_count}</Descriptions.Item>
            </Descriptions>

            <div style={{ marginTop: 20 }}>
              <div style={{ fontWeight: 600, marginBottom: 12 }}>可调参数</div>
              {selectedRule.params?.map((param: any) => (
                <div key={param.key} style={{ marginBottom: 16, padding: 12, background: '#16233A', borderRadius: 4 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                    <span style={{ fontWeight: 500 }}>{param.label}</span>
                    <span className="mono" style={{ color: '#8A93A3', fontSize: 12 }}>{param.key}</span>
                  </div>
                  <div style={{ color: '#8A93A3', fontSize: 12, marginBottom: 8 }}>{param.description}</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    {param.type === 'bool' ? (
                      <Switch
                        defaultChecked={param.default_value === true}
                        onChange={(v) => handleApplyConfig(selectedRule.rule_id, param.key, v)}
                      />
                    ) : param.type === 'float' || param.type === 'int' ? (
                      <InputNumber
                        defaultValue={param.default_value}
                        min={param.min}
                        max={param.max}
                        step={param.type === 'int' ? 1 : 0.1}
                        onChange={(v) => handleApplyConfig(selectedRule.rule_id, param.key, v)}
                      />
                    ) : (
                      <input
                        defaultValue={param.default_value as string}
                        onChange={(e) => handleApplyConfig(selectedRule.rule_id, param.key, e.target.value)}
                        style={{ background: '#0B1420', border: '1px solid #25344A', color: '#EDEAE0', padding: '4px 8px', borderRadius: 2, width: '100%' }}
                      />
                    )}
                    {param.unit && <span style={{ color: '#8A93A3', fontSize: 12 }}>{param.unit}</span>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </Modal>
    </div>
  )
}
