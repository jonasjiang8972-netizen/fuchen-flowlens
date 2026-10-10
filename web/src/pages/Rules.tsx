import { useEffect, useState } from 'react'
import { Button, Card, Descriptions, Input, InputNumber, Modal, Space, Switch, Table, Tabs, Tag, message } from 'antd'
import { ruleService } from '../services/api'
import { errorMessage } from '../services/http'
import { useSession } from '../context/session'

export default function Rules({ onNavigate }: { onNavigate: (page: string, id?: string) => void }) {
  const [rules, setRules] = useState<any[]>([])
  const [categories, setCategories] = useState<string[]>([])
  const [selectedRule, setSelectedRule] = useState<any>(null)
  const [detailVisible, setDetailVisible] = useState(false)
  const [tab, setTab] = useState('all')
  // Unsaved parameter edits of the open rule, keyed by parameter key.
  const [draft, setDraft] = useState<Record<string, any>>({})
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    ruleService.list().then(setRules)
    ruleService.categories().then(setCategories)
  }, [])

  const { can } = useSession()
  const canManage = can('rule.manage')

  const handleToggle = async (ruleId: string, enabled: boolean) => {
    try {
      await ruleService.update(ruleId, { enabled })
    } catch (err) {
      message.error(errorMessage(err))
      return
    }
    setRules(prev => prev.map(r => r.rule_id === ruleId ? { ...r, enabled } : r))
    setSelectedRule((prev: any) => (prev && prev.rule_id === ruleId ? { ...prev, enabled } : prev))
    message.success(`规则 ${enabled ? '已启用' : '已禁用'}`)
  }

  const handleView = async (ruleId: string) => {
    const detail = await ruleService.detail(ruleId)
    setSelectedRule(detail)
    setDraft({})
    setDetailVisible(true)
  }

  // The value in effect: the saved one, else the default.
  const currentValue = (param: any) => (param.value !== undefined && param.value !== null ? param.value : param.default_value)
  const shownValue = (param: any) => (param.key in draft ? draft[param.key] : currentValue(param))

  const editParam = (param: any, value: any) => {
    setDraft(prev => {
      const next = { ...prev }
      if (value === currentValue(param)) delete next[param.key]
      else next[param.key] = value
      return next
    })
  }

  const handleSaveParams = async () => {
    if (!selectedRule || Object.keys(draft).length === 0) return
    for (const param of selectedRule.params || []) {
      if ((param.type === 'int' || param.type === 'float') && param.key in draft && (draft[param.key] === null || draft[param.key] === undefined)) {
        message.error(`${param.label} 不能为空`)
        return
      }
    }
    setSaving(true)
    let updated: any
    try {
      updated = await ruleService.update(selectedRule.rule_id, { config: draft })
    } catch (err) {
      message.error(errorMessage(err))
      setSaving(false)
      return
    }
    setSaving(false)
    // The platform returns the saved rule; the static demo build does not.
    const next = updated?.rule_id
      ? updated
      : { ...selectedRule, params: selectedRule.params.map((p: any) => (p.key in draft ? { ...p, value: draft[p.key] } : p)) }
    setSelectedRule(next)
    setRules(prev => prev.map(r => (r.rule_id === next.rule_id ? { ...r, ...next } : r)))
    setDraft({})
    message.success('参数已保存，立即生效')
  }

  const formatValue = (param: any, value: any) => {
    if (param.type === 'bool') return value ? '开启' : '关闭'
    return `${value}${param.unit ? ' ' + param.unit : ''}`
  }

  const filteredRules = tab === 'all' ? rules : rules.filter(r => r.category === tab)

  const columns = [
    { title: '规则ID', dataIndex: 'rule_id', key: 'id', width: 120, render: (id: string) => <span className="mono">{id}</span> },
    { title: '名称', dataIndex: 'name', key: 'name' },
    { title: '所属需求', dataIndex: 'source_requirement', key: 'fr', width: 120, render: (fr: string) => <Tag>{fr}</Tag> },
    { title: '分类', dataIndex: 'category', key: 'category', width: 100, render: (c: string) => <Tag color="blue">{c}</Tag> },
    { title: '等级', dataIndex: 'severity', key: 'severity', width: 80,
      render: (s: string) => {
        const colors: Record<string, string> = { critical: 'red', high: 'orangered', medium: 'orange', low: 'blue' }
        return <Tag color={colors[s]}>{s}</Tag>
      } },
    { title: '状态', dataIndex: 'enabled', key: 'enabled', width: 80,
      render: (enabled: boolean, record: any) => <Switch checked={enabled} disabled={!canManage} onChange={(v) => handleToggle(record.rule_id, v)} /> },
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
        <Tabs activeKey={tab} onChange={setTab}>
          <Tabs.TabPane key="all" tab="全部" />
          {categories.map(c => (
            <Tabs.TabPane key={c} tab={c} />
          ))}
        </Tabs>
        <Table columns={columns} dataSource={filteredRules} rowKey="rule_id" pagination={false} />
      </Card>

      <Modal
        title={<span style={{ color: '#EDEAE0' }}>规则详情: {selectedRule?.rule_id}</span>}
        open={detailVisible}
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
                <Tag color={({ critical: 'red', high: 'orangered', medium: 'orange', low: 'blue' } as Record<string, string>)[selectedRule.severity]}>{selectedRule.severity}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="状态">
                <Switch checked={selectedRule.enabled} disabled={!canManage} onChange={(v) => handleToggle(selectedRule.rule_id, v)} />
              </Descriptions.Item>
              <Descriptions.Item label="描述" span={2}>{selectedRule.description}</Descriptions.Item>
              <Descriptions.Item label="建议" span={2}>{selectedRule.recommendation}</Descriptions.Item>
              <Descriptions.Item label="基础评分">{selectedRule.default_risk_score}</Descriptions.Item>
              <Descriptions.Item label="命中次数">{selectedRule.hit_count}</Descriptions.Item>
            </Descriptions>

            <div style={{ marginTop: 20 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <span style={{ fontWeight: 600 }}>可调参数</span>
                {canManage && (
                  <Space>
                    <Button size="small" disabled={Object.keys(draft).length === 0 || saving} onClick={() => setDraft({})}>撤销修改</Button>
                    <Button size="small" type="primary" loading={saving} disabled={Object.keys(draft).length === 0} onClick={handleSaveParams}>
                      保存{Object.keys(draft).length > 0 ? `（${Object.keys(draft).length} 项）` : ''}
                    </Button>
                  </Space>
                )}
              </div>
              {!selectedRule.enabled && (
                <div style={{ color: '#D6A243', fontSize: 12, marginBottom: 12 }}>规则已停用：参数会保存，但启用前不会产生检测和告警。</div>
              )}
              {selectedRule.params?.map((param: any) => {
                const changed = param.key in draft
                return (
                  <div key={param.key} style={{ marginBottom: 16, padding: 12, background: '#16233A', borderRadius: 4, border: changed ? '1px solid #D6A243' : '1px solid transparent' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                      <span style={{ fontWeight: 500 }}>{param.label}{changed && <Tag color="gold" style={{ marginLeft: 8 }}>未保存</Tag>}</span>
                      <span className="mono" style={{ color: '#8A93A3', fontSize: 12 }}>{param.key}</span>
                    </div>
                    <div style={{ color: '#8A93A3', fontSize: 12, marginBottom: 8 }}>
                      {param.description}
                      <span style={{ marginLeft: 8 }}>默认值：{formatValue(param, param.default_value)}</span>
                      {(param.type === 'int' || param.type === 'float') && (param.min || param.max) ? <span style={{ marginLeft: 8 }}>范围：{param.min}～{param.max}</span> : null}
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                      {param.type === 'bool' ? (
                        <Switch checked={shownValue(param) === true} disabled={!canManage} onChange={(v) => editParam(param, v)} />
                      ) : param.type === 'float' || param.type === 'int' ? (
                        <InputNumber
                          value={shownValue(param)}
                          min={param.min}
                          max={param.max}
                          step={param.type === 'int' ? 1 : (param.max && param.max <= 1 ? 0.01 : 0.1)}
                          precision={param.type === 'int' ? 0 : undefined}
                          disabled={!canManage}
                          onChange={(v) => editParam(param, v)}
                        />
                      ) : (
                        <Input
                          value={shownValue(param) ?? ''}
                          disabled={!canManage}
                          onChange={(e) => editParam(param, e.target.value)}
                        />
                      )}
                      {param.unit && <span style={{ color: '#8A93A3', fontSize: 12, whiteSpace: 'nowrap' }}>{param.unit}</span>}
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </Modal>
    </div>
  )
}
