# 拂尘 FlowLens — 项目分析总汇与完善方案

> 汇总两份分析：需求完成度校验 + 代码架构稳定性审查
> 文档版本 V1.0 · 2026年7月7日

---

## 目录

- [一、项目现状总览](#一项目现状总览)
- [二、需求完成度矩阵（37条功能需求）](#二需求完成度矩阵37条功能需求)
- [三、代码实现逻辑缺陷清单](#三代码实现逻辑缺陷清单)
- [四、架构稳定性与连续性评估](#四架构稳定性与连续性评估)
- [五、修正方案（按优先级）](#五修正方案按优先级)
- [六、版本规划修订建议](#六版本规划修订建议)
- [七、投入估算](#七投入估算)

---

## 一、项目现状总览

### 正面指标

| 指标 | 数值 |
|------|------|
| 代码文件数 | 59 |
| 后端 Go | 15 文件，~2,500 行 |
| 前端 React | 12 文件，~1,500 行 |
| 接口契约 | 4 文件（Proto+OpenAPI+DDL） |
| 构建通过率 | Platform: ✅，Agent: ❌，Web: ⚠️ |
| API 端点 | 11 个 REST 端点，全部可访问 |
| 前端页面 | 7 个页面，含下钻导航 |

### 风险指标

| 指标 | 数值 |
|------|------|
| 功能需求完成率 | 17/37 = **46%** |
| P0 需求完成率 | 12/18 = **67%**（仅 3/8 真正完整实现） |
| 编译阻断缺陷 | **1 处**（Agent 无法编译） |
| 逻辑错误缺陷 | **1 处**（Normalizer 死码） |
| 架构断裂点 | **3 处**（Agent↔Platform 断连、无持久化、无流管道） |
| 数据竞争缺陷 | **1 处**（Monitor 心跳） |
| 前端 Mock/后端数据分裂 | **全部 7 页面** |

---

## 二、需求完成度矩阵（37条功能需求）

### 模块一：API 资产发现与全生命周期管理

| 编号 | 需求 | P | 完成度 | 当前实现 | 差距 |
|------|------|---|--------|----------|------|
| FR-AST-001 | 全量API自动发现 | P0 | ⚠️ **35%** | Agent 自动探测+路径归一化引擎就绪 | ① 无真实流量采集→资产写入 ② 无 Kafka 消费端 ③ 无 Flink 流处理 |
| FR-AST-002 | 影子/僵尸API识别 | P0 | ⚠️ **20%** | Seed 数据含 shadow/zombie 标记 | ① 无差集比对算法 ② 无官方目录导入 ③ 无 30 天频率趋势分析 |
| FR-AST-003 | 资产分组与责任人认领 | P0 | ✅ **90%** | 后端 Claim API + 前端认领按钮 + 分组展示 | ① 无 30 天超期自动升级 ② 无通知推送 |
| FR-AST-004 | API规范导入导出 | P1 | ❌ **0%** | — | 完全未实现 |
| FR-AST-005 | 资产变更监测 | P1 | ⚠️ **15%** | Seed 数据含变更历史 | ① 无 5 分钟快照比对 ② 无 4 类变更分类 |

### 模块二：威胁检测引擎（OWASP API Security Top 10）

| 编号 | 需求 | P | OWASP | 完成度 | 当前实现 | 差距 |
|------|---|------|-------|--------|----------|------|
| FR-DET-001 | BOLA | P0 | API1 | ⚠️ **25%** | Seed 含 BOLA 告警+攻击路径 | ① 无账号资源基线 ② 无遍历速率检测 ③ 无 0-100 评分模型 |
| FR-DET-002 | 身份认证失效 | P0 | API2 | ⚠️ **15%** | Seed 含撞库告警 | ① 无 Token 熵值分析 ② 无撞库特征提取 ③ 无会话生命周期检测 |
| FR-DET-003 | 对象属性级授权 | P0 | API3 | ❌ **0%** | — | 完全未实现 |
| FR-DET-004 | 资源消耗无限制 | P1 | API4 | ❌ **0%** | — | 完全未实现 |
| FR-DET-005 | BFLA | P0 | API5 | ⚠️ **15%** | Seed 含 admin 端点资产 | ① 无角色-接口矩阵 ② 无 IAM 确认 ③ 无管理端点加权 |
| FR-DET-006 | 敏感业务流 | P1 | API6 | ❌ **0%** | — | 完全未实现 |
| FR-DET-007 | SSRF | P2 | API7 | ❌ **0%** | — | 能力边界项，标记为 P2 |
| FR-DET-008 | 安全配置错误 | P2 | API8 | ❌ **0%** | — | 能力边界项，标记为 P2 |
| FR-DET-009 | 库存管理不当 | P0 | API9 | ✅ | 锚点需求，由 AST-001/002 覆盖 | 0 |
| FR-DET-010 | 第三方API | P1 | API10 | ❌ **0%** | — | 完全未实现 |

### 模块三：敏感数据识别与合规治理

| 编号 | 需求 | P | 完成度 | 当前实现 | 差距 |
|------|---|--------|----------|------|
| FR-DLP-001 | 分类分级 | P0 | ❌ **5%** | 资产模型含 `sensitive_fields` 字段 | ① 无正则引擎 ② 无 NLP 模型 ③ 无自定义规则 |
| FR-DLP-002 | 数据流动图谱 | P1 | ⚠️ **15%** | `/sensitive/flow-map` API 返回硬编码数据 | ① 无字段指纹关联 ② 无有向图构建 ③ 无 3 视角切换 |
| FR-DLP-003 | 脱敏效果核验 | P0 | ⚠️ **10%** | Seed 含脱敏缺陷告警 | ① 无脱敏模板 ② 无实际返回比对 ③ 无缺陷分类 |
| FR-DLP-004 | 合规报告生成 | P1 | ❌ **0%** | — | 完全未实现 |

### 模块四：业务风控与自动化攻击检测

| 编号 | 需求 | P | 完成度 | 差距 |
|------|---|--------|----------|------|
| FR-RISK-001 | 设备指纹 | P1 | ⚠️ **10%** | Alert 模型含 device_fingerprint 字段，无实际指纹生成 |
| FR-RISK-002 | 爬虫识别 | P1 | ❌ **0%** | 完全未实现 |
| FR-RISK-003 | 撞库检测 | P0 | ❌ **0%** | 完全未实现（FR-DET-002 也未实现） |
| FR-RISK-004 | 业务滥用规则库 | P2 | ❌ **0%** | 完全未实现 |

### 模块五：告警管理与响应联动

| 编号 | 需求 | P | 完成度 | 当前实现 | 差距 |
|------|---|--------|----------|------|
| FR-ALT-001 | 风险评分分级 | P0 | ✅ **85%** | Alert 模型完整（risk_score/severity/confidence），前端按等级着色 | ① 无权重重调优接口 |
| FR-ALT-002 | 攻击路径溯源 | P0 | ✅ **80%** | AttackPath + Timeline 模型完整，前端 Steps 展示 | ① 24h 拉取是 mock ① 无关系图谱视图 |
| FR-ALT-003 | SOAR联动 | P0 | ⚠️ **20%** | `POST /alerts/:id/:action` API 存在 | ① 无真实网关/WAF 联动 ② 无人工审核/自动执行双路径 |
| FR-ALT-004 | 工单闭环 | P1 | ❌ **0%** | — | 完全未实现 |

### 模块六：可视化门户与报表中心

| 编号 | 需求 | P | 完成度 | 当前实现 | 差距 |
|------|---|--------|----------|------|
| FR-VIS-001 | 总览大屏 | P0 | ✅ **85%** | 4 统计卡片 + ECharts 趋势/分布 + Top 告警表 + 高风险资产表 | ① 无自定义看板布局 |
| FR-VIS-002 | API详情画像 | P0 | ✅ **80%** | 24h 调用量/错误率/延迟/小时趋势/关联告警/变更历史 | ① 30 天趋势是 mock ② 无敏感字段分布图 |
| FR-VIS-003 | 自定义报表 | P1 | ❌ **0%** | — | 完全未实现 |

### 模块七：系统管理

| 编号 | 需求 | P | 完成度 | 当前实现 | 差距 |
|------|---|--------|----------|------|
| FR-SYS-001 | 多租户RBAC | P0 | ⚠️ **15%** | DDL 含 5 种角色+权限表，前端路由布局就绪 | ① 无认证中间件 ② 无登录页 ③ 无权限判断 |
| FR-SYS-002 | 审计日志 | P0 | ⚠️ **15%** | DDL 含 audit_logs 哈希链表 | ① 无操作拦截 ② 无日志写入 |
| FR-SYS-003 | SSO | P1 | ❌ **0%** | — | 完全未实现 |

---

## 三、代码实现逻辑缺陷清单

### 编译阻断

| ID | 位置 | 严重度 | 描述 |
|----|------|--------|------|
| `C-001` | `agent/internal/config/config.go:123` | 🔴 编译失败 | `DefaultConfig()` 中 `ManagementConfig: ManagementConfig{...}` 应为 `Management: ManagementConfig{...}`（字段名用成了类型名） |
| `C-002` | `agent/internal/config/config.go:129` | 🔴 编译失败 | 同上，`KafkaConfig: KafkaConfig{...}` 应为 `Kafka: KafkaConfig{...}` |

### 逻辑错误

| ID | 位置 | 严重度 | 描述 |
|----|------|--------|------|
| `L-001` | `agent/internal/normalizer/normalizer.go:84-90` | 🔴 逻辑错误 | 第84行创建 `result` 变量，85-88行做无操作替换（`{id}`→`{id}`），第90行直接覆盖 `result`。84-88行是死代码，路径归一化的参数模板替换从未生效 |

### 数据竞争

| ID | 位置 | 严重度 | 描述 |
|----|------|--------|------|
| `R-001` | `agent/internal/health/monitor.go:56` | 🟡 并发安全 | `lastHeartbeat` 在 `Start()` goroutine 中无锁写入，但 `TimeSinceHeartbeat()` 用 `mu.RLock()` 读取 |

### 死代码

| ID | 位置 | 严重度 | 描述 |
|----|------|--------|------|
| `D-001` | `platform/cmd/main.go:105-111` | 🟢 整洁 | `healthHandler` 函数定义了但从未被引用（已被 `server.HealthHandler` 替代） |
| `D-002` | `agent/internal/normalizer/normalizer.go:84-88` | 🔴 逻辑 | 同上 L-001 |

### 数据源分裂（前端）

| ID | 位置 | 严重度 | 描述 |
|----|------|--------|------|
| `S-001` | `web/src/services/api.ts` | 🟡 架构 | `list()`/`detail()` 返回硬编码 mock，`claimAsset()` 调真实 API。认领操作刷新后回滚 |
| `S-002` | `web/src/pages/Assets.tsx:16` | 🟡 质量 | 运行时 `require()` 导入，Vite 生产构建时 tree-shaking 退化 |

---

## 四、架构稳定性与连续性评估

### 架构断裂点（阻断 PRD 连续性）

| ID | 组件对 | 问题 | PRD 要求 | 影响模块 |
|----|--------|------|----------|----------|
| `BR-01` | **Agent → Platform** | 无通信通道。Agent 的 gRPC 心跳代码未连接；Platform 无 gRPC Server | 双向心跳/配置下发/远程管理 | FR-SYS 管控面、FR-AST-001 |
| `BR-02` | **Platform → 数据库** | 所有数据在内存 map 中，无 PG/CH/ES/Kafka 客户端代码 | 元数据≥90天、审计≥180天、持久化 | 全模块 |
| `BR-03` | **Agent → Kafka → Flink** | Agent 无 Kafka Producer；Platform 无 Consumer；Flink 无集成 | 流式重组、TLS 旁路解密 | FR-AST、FR-DET 全系列 |
| `BR-04` | **前端 → 后端** | 前端 7 页面均使用 Mock 数据替代后端 API 调用 | 前后端一体化 | FR-VIS 全系列 |

### 连续性风险（可修复但需投入）

| ID | 风险点 | 当前状态 | 修复路线 |
|----|--------|----------|----------|
| `CR-01` | 检测引擎全为空 | 10 条 DET 需求无实时检测逻辑 | MVP 后集中开发，优先 DET-001/003/005 |
| `CR-02` | 无认证鉴权 | API 全开放 | 引入 JWT 中间件，对接 DDL 的 RBAC 表 |
| `CR-03` | 种子数据耦合 | Service 层用硬编码 map 交叉引用 | 提取为独立 Seed 包，或直接接入数据库 |
| `CR-04` | Agent 采集器实现不足 | 仅 Gateway Log 可用 | 优先级：eBPF > pcap > DPDK > VPC |

---

## 五、修正方案（按优先级）

### P0 — 修复阻断（立即执行）

#### FIX-001: 修复 Agent 编译错误
**文件**: `agent/internal/config/config.go:123,129`
**操作**: 修改 `DefaultConfig()` 中的字段名

```go
// 改前 (line 123)
ManagementConfig: ManagementConfig{...}
// 改后
Management: ManagementConfig{...}

// 改前 (line 129)
KafkaConfig: KafkaConfig{...}
// 改后
Kafka: KafkaConfig{...}
```

**预计**: 5 分钟

---

#### FIX-002: 修复 Normalizer 路径归一化逻辑
**文件**: `agent/internal/normalizer/normalizer.go:70-99`
**操作**: 重构 `NormalizePath()` — 移除死代码，使参数模板替换生效

```go
func (n *Normalizer) NormalizePath(rawPath string) (string, float64) {
	if rawPath == "" || rawPath == "/" {
		return rawPath, 1.0
	}
	n.mu.RLock()
	if normalized, ok := n.staticPaths[rawPath]; ok {
		n.mu.RUnlock()
		return normalized, 1.0
	}
	n.mu.RUnlock()

	for _, pattern := range n.pathPatterns {
		if matches := pattern.regex.FindStringSubmatch(rawPath); matches != nil {
			result := rawPath
			for i, name := range pattern.paramNames {
				if i+1 < len(matches) {
					result = strings.Replace(result, matches[i+1], "{"+name+"}", 1)
				}
			}
			n.mu.Lock()
			n.staticPaths[rawPath] = result
			n.mu.Unlock()
			return result, pattern.minConfidence
		}
	}
	return rawPath, 1.0
}
```

**预计**: 2 小时

---

### P1 — 架构断裂修复（本周内）

#### FIX-003: 打通 Agent ↔ Platform 心跳通道
**方案**:
1. Platform 引入 gRPC Server（port 9000），实现 `AgentService` proto 定义的 rpc
2. Agent 的 `health.Monitor.Start()` 连接 gRPC，发送 `Heartbeat` 消息
3. Platform 存储心跳到 `agent_heartbeats` 表
4. 60 秒无心跳自动标记为 offline

**涉及文件**:
- `agent/internal/health/monitor.go` — 新增 `sendHeartbeat(ctx)` 方法
- `agent/cmd/main.go` — 启动时建立 gRPC 连接
- `platform/cmd/main.go` — 新增 gRPC server
- `contracts/proto/agent_communication.proto` — 已存在，直接复用

**预计**: 3 天

---

#### FIX-004: 集成 PostgreSQL 最小数据库
**方案**:
1. 引入 `pgx` 驱动（已存在于 `go.mod`）
2. 创建 `platform/internal/storage/postgres.go` — 实现 `ListAssets`/`GetAsset`/`ListAlerts`/`GetAlert`/`RegisterAgent`/`UpdateHeartbeat`
3. 逐步替换 service 层的内存 map
4. 保留 seed 数据作为开发模式回退（`--mock` flag）

**DDL 复用**: `contracts/ddl/001_initial_schema.sql` 已就绪

**预计**: 3 天

---

### P2 — 功能修复（2周内）

#### FIX-005: 前端 API 接入真实后端
**方案**:
```typescript
// api.ts 重构为 fetch 调用
export const agentService = {
  list: async (): Promise<Agent[]> => {
    const resp = await fetch('/api/v1/agents')
    const data = await resp.json()
    return data.items
  },
  detail: async (id: string): Promise<AgentDetail> => {
    const resp = await fetch(`/api/v1/agents/${id}`)
    return resp.json()
  },
}
// 同理 assetService, alertService
```

**预计**: 4 小时

---

#### FIX-006: 修复 Monitor 数据竞争
**文件**: `agent/internal/health/monitor.go:56`

```go
case <-ticker.C:
	m.mu.Lock()
	m.lastHeartbeat = time.Now()
	m.mu.Unlock()
```

**预计**: 30 分钟

---

#### FIX-007: 前端 require → import 重构
**文件**: `src/pages/*.tsx` 中的 3 处 `require()`
**操作**: 替换为标准 ESM import

**预计**: 30 分钟

---

### P3 — 功能补齐（3-4周内）

#### FIX-008: MVP 缺失检测引擎

| 需求 | 实现方案 | 依赖 | 工时 |
|------|----------|------|------|
| FR-DET-001 BOLA | 基于路径参数 ID 的模式匹配 + 访问频率统计 → 评分 | FIX-003 (Kafka) | 3天 |
| FR-DET-002 认证失效 | 登录接口 401 统计 + Token 熵值分析 | FIX-003 (Kafka) | 2天 |
| FR-DET-005 BFLA | 角色-接口访问矩阵（内存统计） | 无 | 2天 |

#### FIX-009: 系统管理 MVP
- 登录页面 + JWT 签发
- RBAC 中间件（5 种角色）
- 操作审计日志写入

**预计**: 3 天

---

## 六、版本规划修订建议

### 当前状态

| 版本 | 计划周期 | 状态 |
|------|----------|------|
| MVP | T0 ~ 3个月 | 当前代码处于 "MVP 原型" 阶段 — 架构就绪但核心链路断裂 |

### 修正后的推荐顺序

```
Week 1-2        Week 3-4          Week 5-8           Week 9-12
───────────────────────────────────────────────────────────────────
P0 修复         P1 架构修复       P2 功能修复         P3 功能补齐
                                                                            
FIX-001 ───┐                                                                
FIX-002 ───┤                                                                
           ▼                                                                
FIX-003 ───────┐     FIX-005 ───┐                                           
FIX-004 ───────┤     FIX-006 ───┤                                           
                │    FIX-007 ───┤                                           
                ▼               ▼                                            
                               FIX-008 ──────────┐                          
                               FIX-009 ──────────┤                          
                                                  ▼                         
                                                客户 POC 部署                         
```

### 里程碑修正

| 阶段 | 时间 | 交付物 | 验收标准（修正版） |
|------|------|--------|-------------------|
| **Alpha** | T0 ~ 2周 | 代码可编译 + Agent↔Platform 心跳 + PG 集成 | Agent 编译通过，平台可展示实时心跳（不再依赖 Seed） |
| **Beta** | 3 ~ 4周 | 前后端数据打通 + 登录认证 | 前端调用真实后端 API，管理员可登录 |
| **MVP** | 5 ~ 8周 | AST-001~003 最小闭环 + DET-001/002/005 告警 | Agent 采集→平台检测→前端展示→告警下钻 全链路走通 |
| **V1.0** | 9~12周 + 4周 POC | OWASP Top10 覆盖 + 数据库持久化 + 审计日志 | 3-5 家客户 POC |

---

## 七、投入估算

| 修复编号 | 任务 | 工时 | 角色 |
|----------|------|------|------|
| FIX-001 | 编译错误修复 | 0.5h | Go 开发 |
| FIX-002 | Normalizer 逻辑修复 | 2h | Go 开发 |
| FIX-003 | Agent↔Platform gRPC 通道 | 3天 | Go 开发 × 2 |
| FIX-004 | PostgreSQL 集成 | 3天 | Go 开发 |
| FIX-005 | 前端 API 接入 | 4h | 前端 |
| FIX-006 | Monitor 数据竞争 | 0.5h | Go 开发 |
| FIX-007 | require → import | 0.5h | 前端 |
| FIX-008 | MVP 检测引擎 | 7天 | Go 开发 × 2 |
| FIX-009 | 登录+RBAC+审计 | 3天 | Go 开发 + 前端 |
| **合计** | | **~21人天** | |

---

<p align="center">
  <i>清风拂尘 · 流量为镜 · 修复即提升</i><br>
  FlowLens 项目分析总汇 V1.0 · 2026-07-07
</p>
