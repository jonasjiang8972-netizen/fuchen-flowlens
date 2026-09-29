import { useEffect, useMemo, useState } from 'react'
import { Alert, Button, Card, Empty, Segmented, Space, Spin, Table, Tag, Tooltip } from 'antd'
import { DownloadOutlined, FileDoneOutlined, ReloadOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import { useSession } from '../context/session'
import { DEMO, errorMessage } from '../services/http'
import { complianceService } from '../services/compliance'
import type { Check, CheckStatus, Report, TemplateInfo } from '../services/compliance'

const STATUS: Record<CheckStatus, { label: string; color: string; tag: string }> = {
  pass: { label: '符合', color: '#168447', tag: 'success' },
  partial: { label: '部分符合', color: '#b7791f', tag: 'warning' },
  fail: { label: '不符合', color: '#c9352b', tag: 'error' },
  manual: { label: '需人工核查', color: '#64748b', tag: 'default' },
}

const BASIS: Record<string, { label: string; hint: string }> = {
  live: { label: '实时', hint: '由平台当前的配置和数据判定' },
  capability: { label: '能力', hint: '说明产品是否实现了该功能，取自代码，未经现场验证' },
  manual: { label: '需人工', hint: '涉及机房、制度、人员等，软件无法判断' },
}

export default function ComplianceReport() {
  const { can } = useSession()
  const allowed = can('report.read')

  const [templates, setTemplates] = useState<TemplateInfo[]>([])
  const [template, setTemplate] = useState('mlps3')
  const [report, setReport] = useState<Report | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState<'all' | CheckStatus>('all')

  const generate = async (t = template) => {
    setLoading(true)
    setError('')
    try {
      setReport(await complianceService.generate(t))
    } catch (err) {
      setError(errorMessage(err))
      setReport(null)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (!allowed) return
    complianceService.templates().then(setTemplates)
    generate()
  }, [allowed])

  const desc = templates.find(t => t.id === template)?.description
  const sections = useMemo(() => {
    if (!report) return []
    return report.sections
      .map(s => ({ ...s, checks: s.checks.filter(c => filter === 'all' || c.status === filter) }))
      .filter(s => s.checks.length > 0)
  }, [report, filter])

  if (!allowed) {
    return (
      <div className="commercial-page">
        <div className="page-heading"><div><div className="page-heading__title">合规报告</div></div></div>
        <Alert type="info" showIcon message="需要安全管理员权限" description="合规报告汇总了整个平台的安全状况（账号策略、审计、加密、处置情况），只有安全管理员可以生成和导出。" />
      </div>
    )
  }

  const s = report?.summary
  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">合规报告</div>
          <div className="page-heading__desc">对照等保三级和金融行业要求，用平台当前的真实状态逐项自查；做不到的、无法判断的都会如实标出，不会凑成“符合”。</div>
        </div>
        <Space>
          <Button icon={<ReloadOutlined />} loading={loading} onClick={() => generate()}>重新生成</Button>
          <Tooltip title={DEMO ? '演示站没有后端，无法导出' : '下载可打印的 HTML 报告（导出会记入审计）'}>
            <Button icon={<DownloadOutlined />} disabled={!report || DEMO} href={complianceService.exportUrl(template, 'html')}>导出 HTML</Button>
          </Tooltip>
          <Tooltip title={DEMO ? '演示站没有后端，无法导出' : '下载 CSV，可用 Excel 打开（导出会记入审计）'}>
            <Button icon={<DownloadOutlined />} disabled={!report || DEMO} href={complianceService.exportUrl(template, 'csv')}>导出 CSV</Button>
          </Tooltip>
        </Space>
      </div>

      <Space direction="vertical" size={12} style={{ width: '100%' }}>
        <Space align="center" wrap>
          <Segmented value={template} options={templates.length ? templates.map(t => ({ value: t.id, label: t.title })) : [{ value: 'mlps3', label: '等保 2.0 三级自查' }]}
            onChange={v => { setTemplate(String(v)); setFilter('all'); generate(String(v)) }} />
          {desc && <span className="muted">{desc}</span>}
        </Space>

        {report?.demo && <Alert type="warning" showIcon message="演示数据" description="这是演示环境的示例报告，描述的是一个虚构的部署，不代表任何真实系统。" />}
        {report && <Alert type="info" showIcon message={report.disclaimer} />}
        {error && <Alert type="error" showIcon message="无法生成报告" description={error} />}
      </Space>

      <Spin spinning={loading}>
        {s && (
          <div className="metric-grid" style={{ marginTop: 16, gridTemplateColumns: 'repeat(5, minmax(0, 1fr))' }}>
            <Card className="metric-card"><div className="metric-card__label"><FileDoneOutlined /> 检查项</div><div className="metric-card__value">{s.total}</div><div className="metric-card__meta">生成于 {dayjs(report!.generated_at).format('MM-DD HH:mm')}</div></Card>
            {(['pass', 'partial', 'fail', 'manual'] as CheckStatus[]).map(k => (
              <Card key={k} className="metric-card" style={{ cursor: 'pointer', outline: filter === k ? `2px solid ${STATUS[k].color}` : undefined }} onClick={() => setFilter(f => (f === k ? 'all' : k))}>
                <div className="metric-card__label">{STATUS[k].label}</div>
                <div className="metric-card__value" style={{ color: STATUS[k].color }}>{s[k]}</div>
                <div className="metric-card__meta">{filter === k ? '点击取消筛选' : '点击只看这一类'}</div>
              </Card>
            ))}
          </div>
        )}

        {!report && !loading && !error && <Empty description="尚未生成" />}
        {sections.map(sec => (
          <Card key={sec.category} title={sec.category} style={{ marginTop: 16 }}>
            <Table<Check>
              rowKey="id" size="middle" pagination={false} dataSource={sec.checks}
              columns={[
                { title: '编号', dataIndex: 'id', width: 70 },
                {
                  title: '检查项', dataIndex: 'title', width: 300,
                  render: (v: string, c) => (
                    <div>
                      <div style={{ fontWeight: 600 }}>{v}</div>
                      <div className="muted" style={{ fontSize: 12 }}>{c.requirement}</div>
                      <div className="muted" style={{ fontSize: 12 }}>{c.ref}</div>
                    </div>
                  ),
                },
                {
                  title: '结论', dataIndex: 'status', width: 120,
                  render: (v: CheckStatus, c) => (
                    <Space direction="vertical" size={2}>
                      <Tag color={STATUS[v].tag}>{STATUS[v].label}</Tag>
                      <Tooltip title={BASIS[c.basis]?.hint}><span className="muted" style={{ fontSize: 12 }}>{BASIS[c.basis]?.label}</span></Tooltip>
                    </Space>
                  ),
                },
                { title: '证据', dataIndex: 'evidence' },
                { title: '整改建议', dataIndex: 'remediation', width: 260, render: (v?: string) => v || <span className="muted">—</span> },
              ]}
            />
          </Card>
        ))}
      </Spin>
    </div>
  )
}
