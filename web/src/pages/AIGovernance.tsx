import { Card, Space, Table, Tag } from 'antd'
import { AppstoreOutlined, AuditOutlined, DatabaseOutlined, LinkOutlined } from '@ant-design/icons'

const capabilityRows = [
  { id: 'ai-api', domain: 'AI API 资产', scope: '模型调用、Embedding、Rerank、Vision、Speech', status: '预留' },
  { id: 'agent-tool', domain: 'Agent 工具调用', scope: 'Tool Calling、MCP Server、Function Call、内部系统动作', status: '预留' },
  { id: 'rag', domain: 'RAG 数据访问', scope: '向量库、知识库、文档检索、权限边界', status: '预留' },
  { id: 'context', domain: 'Prompt / Context 风险', scope: '系统提示词、用户输入、上下文窗口、敏感数据外发', status: '预留' },
]

export default function AIGovernance() {
  return (
    <div className="commercial-page">
      <div className="page-heading">
        <div>
          <div className="page-heading__title">AI 应用治理</div>
          <div className="page-heading__desc">预留 AI 应用中的模型 API、Agent 工具调用、RAG 检索接口和上下文数据流治理能力。</div>
        </div>
        <Tag color="default">Phase 2 / Phase 3</Tag>
      </div>

      <div className="metric-grid">
        <Card className="metric-card">
          <div className="metric-card__label"><AppstoreOutlined /> 模型调用资产</div>
          <div className="metric-card__value">预留</div>
          <div className="metric-card__meta">统一纳管第三方与私有模型网关</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><LinkOutlined /> Agent 工具链路</div>
          <div className="metric-card__value">预留</div>
          <div className="metric-card__meta">审计工具调用与内部 API 动作</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><DatabaseOutlined /> RAG 数据访问</div>
          <div className="metric-card__value">预留</div>
          <div className="metric-card__meta">识别知识库权限与敏感内容流转</div>
        </Card>
        <Card className="metric-card">
          <div className="metric-card__label"><AuditOutlined /> 审计与回放</div>
          <div className="metric-card__value">预留</div>
          <div className="metric-card__meta">追踪 prompt、context、tool call 和输出</div>
        </Card>
      </div>

      <Card title="预留能力域">
        <Table
          columns={[
            { title: '能力域', dataIndex: 'domain', key: 'domain' },
            { title: '覆盖范围', dataIndex: 'scope', key: 'scope' },
            { title: '状态', dataIndex: 'status', key: 'status', width: 100, render: (value: string) => <Tag>{value}</Tag> },
          ]}
          dataSource={capabilityRows}
          rowKey="id"
          pagination={false}
        />
      </Card>

      <Card title="后续讨论问题">
        <Space direction="vertical" size={10}>
          <div className="insight-row"><div className="insight-row__index">1</div><div><div className="section-title">AI 应用调用了哪些模型和工具？</div><div className="muted">需要从模型网关、Agent 框架和工具调用日志中形成统一资产视图。</div></div></div>
          <div className="insight-row"><div className="insight-row__index">2</div><div><div className="section-title">上下文里是否包含敏感数据？</div><div className="muted">Prompt、检索结果、工具参数和模型响应都可能成为新的数据外发路径。</div></div></div>
          <div className="insight-row"><div className="insight-row__index">3</div><div><div className="section-title">Agent 是否越权调用内部 API？</div><div className="muted">需要把 Tool Call 与传统 API 鉴权、业务动作和审计链路关联起来。</div></div></div>
        </Space>
      </Card>
    </div>
  )
}
