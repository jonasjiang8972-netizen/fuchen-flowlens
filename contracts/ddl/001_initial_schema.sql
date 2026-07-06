-- ============================================================
-- FlowLens Platform Database Schema
-- PostgreSQL 14+
-- ============================================================
-- 字符集: UTF8
-- 时区: Asia/Shanghai

-- ============================================================
-- 扩展
-- ============================================================
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- 租户表
-- ============================================================
CREATE TABLE tenants (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(128) NOT NULL,
    code            VARCHAR(64) UNIQUE NOT NULL,
    description     TEXT,
    isolation_mode  VARCHAR(16) NOT NULL DEFAULT 'logical',  -- logical | physical
    status          VARCHAR(16) NOT NULL DEFAULT 'active',   -- active | suspended | deleted
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tenants_code ON tenants(code);
CREATE INDEX idx_tenants_status ON tenants(status);

-- ============================================================
-- 用户表
-- ============================================================
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    username        VARCHAR(64) NOT NULL,
    email           VARCHAR(128) NOT NULL,
    password_hash   VARCHAR(256),
    role            VARCHAR(32) NOT NULL DEFAULT 'readonly',
    -- super_admin | security_admin | operator | auditor | readonly
    status          VARCHAR(16) NOT NULL DEFAULT 'active',
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(tenant_id, username),
    UNIQUE(tenant_id, email)
);

CREATE INDEX idx_users_tenant ON users(tenant_id);
CREATE INDEX idx_users_role ON users(role);

-- ============================================================
-- API 资产表
-- ============================================================
CREATE TABLE assets (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id               UUID NOT NULL REFERENCES tenants(id),
    asset_code              VARCHAR(64) NOT NULL,  -- 业务展示ID: ast-XXXXXX
    
    -- 核心字段
    path_normalized         VARCHAR(512) NOT NULL,
    path_raw_samples        JSONB DEFAULT '[]',    -- 原始路径样本["/user/123", "/user/456"]
    method                  VARCHAR(16) NOT NULL,
    protocol_type           VARCHAR(16) NOT NULL DEFAULT 'REST',
    host                    VARCHAR(256),
    
    -- 元数据
    description             TEXT,
    sensitivity_hint        VARCHAR(16) DEFAULT 'medium',  -- high | medium | low
    normalization_confidence FLOAT DEFAULT 1.0,
    
    -- 管理
    claim_status            VARCHAR(16) DEFAULT 'unclaimed', -- unclaimed | claimed | escalated
    owner_id                UUID REFERENCES users(id),
    group_path              VARCHAR(512),  -- "零售事业部/交易系统/订单模块"
    
    -- 统计
    first_seen_at           TIMESTAMPTZ NOT NULL,
    last_seen_at            TIMESTAMPTZ NOT NULL,
    daily_avg_calls         INTEGER DEFAULT 0,
    source_distribution     JSONB DEFAULT '{}',  -- {"internal":"62%","external":"38%"}
    
    -- 状态
    status                  VARCHAR(16) DEFAULT 'active',  -- active | shadow | zombie | archived
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(tenant_id, path_normalized, method, host)
);

CREATE INDEX idx_assets_tenant ON assets(tenant_id);
CREATE INDEX idx_assets_status ON assets(status);
CREATE INDEX idx_assets_group ON assets(tenant_id, group_path);
CREATE INDEX idx_assets_owner ON assets(owner_id);
CREATE INDEX idx_assets_last_seen ON assets(last_seen_at);
CREATE INDEX idx_assets_host ON assets(host);
CREATE INDEX idx_assets_condition ON assets(tenant_id, status, sensitivity_hint);

-- ============================================================
-- 资产变更记录表
-- ============================================================
CREATE TABLE asset_changes (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    asset_id        UUID NOT NULL REFERENCES assets(id),
    
    change_type     VARCHAR(32) NOT NULL,
    -- auth_method | field_added | field_removed | method_changed | endpoint_removed
    
    before_value    JSONB,
    after_value     JSONB,
    severity        VARCHAR(16) NOT NULL DEFAULT 'medium',  -- high | medium | low
    
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged    BOOLEAN DEFAULT FALSE,
    acknowledged_by UUID REFERENCES users(id),
    
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_asset_changes_tenant ON asset_changes(tenant_id);
CREATE INDEX idx_asset_changes_asset ON asset_changes(asset_id);
CREATE INDEX idx_asset_changes_detected ON asset_changes(detected_at);
CREATE INDEX idx_asset_changes_severity ON asset_changes(severity);

-- ============================================================
-- 告警表
-- ============================================================
CREATE TABLE alerts (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id               UUID NOT NULL REFERENCES tenants(id),
    alert_code              VARCHAR(64) NOT NULL,  -- 业务展示ID: alt-XXXXXX
    
    -- 风险信息
    severity                VARCHAR(16) NOT NULL,  -- critical | high | medium | low
    title                   VARCHAR(256) NOT NULL,
    description             TEXT,
    
    -- 检测来源
    source_requirement      VARCHAR(32) NOT NULL,  -- FR-DET-001, ...
    risk_score              SMALLINT NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    confidence              FLOAT NOT NULL,
    
    -- 关联对象
    source_ip               INET,
    account_id              VARCHAR(128),
    device_fingerprint_id   VARCHAR(64),
    
    -- 攻击路径
    attack_path             JSONB DEFAULT '[]',
    
    -- 处置
    status                  VARCHAR(16) DEFAULT 'open',
    -- open | acknowledged | in_progress | resolved | false_positive
    assigned_to             UUID REFERENCES users(id),
    disposal_action         VARCHAR(32),  -- ip_block | rate_limit | session_invalidate | captcha | none
    disposal_status         VARCHAR(16),  -- pending | success | failed
    disposal_detail         JSONB,
    resolved_at             TIMESTAMPTZ,
    resolved_by             UUID REFERENCES users(id),
    resolution_note         TEXT,
    
    -- 时间
    occurred_at             TIMESTAMPTZ NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alerts_tenant ON alerts(tenant_id);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_source ON alerts(source_requirement);
CREATE INDEX idx_alerts_occurred ON alerts(occurred_at);
CREATE INDEX idx_alerts_assigned ON alerts(assigned_to);
CREATE INDEX idx_alerts_ip ON alerts(source_ip);

-- ============================================================
-- 告警-资产关联表（多对多）
-- ============================================================
CREATE TABLE alert_assets (
    alert_id    UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    asset_id    UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    PRIMARY KEY (alert_id, asset_id)
);

CREATE INDEX idx_alert_assets_asset ON alert_assets(asset_id);

-- ============================================================
-- 敏感字段表
-- ============================================================
CREATE TABLE sensitive_fields (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id),
    
    field_name          VARCHAR(128) NOT NULL,
    data_type           VARCHAR(64) NOT NULL,   -- 身份证号/手机号/银行卡/...
    sensitivity_level   VARCHAR(16) NOT NULL,   -- high | medium | low
    detection_method    VARCHAR(32),            -- regex | nlp | dictionary
    
    -- 关联资产
    asset_id            UUID REFERENCES assets(id),
    
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sensitive_fields_tenant ON sensitive_fields(tenant_id);
CREATE INDEX idx_sensitive_fields_asset ON sensitive_fields(asset_id);
CREATE INDEX idx_sensitive_fields_level ON sensitive_fields(sensitivity_level);
CREATE INDEX idx_sensitive_fields_type ON sensitive_fields(data_type);

-- ============================================================
-- 采集器注册表
-- ============================================================
CREATE TABLE agents (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id),
    
    agent_code          VARCHAR(64) NOT NULL,   -- 业务展示ID: agent-XXXXXX
    
    -- 硬件/环境
    hostname            VARCHAR(256),
    os                  VARCHAR(64),
    arch                VARCHAR(16),
    cpu_cores           SMALLINT,
    memory_mb           INTEGER,
    
    -- 采集配置
    collect_mode        VARCHAR(32) NOT NULL,
    capabilities        JSONB DEFAULT '[]',
    agent_version       VARCHAR(32),
    
    -- 关联环境
    cluster             VARCHAR(128),
    namespace           VARCHAR(128),
    service_names       JSONB DEFAULT '[]',
    cloud_provider      VARCHAR(32),
    region              VARCHAR(64),
    
    -- 状态
    status              VARCHAR(16) DEFAULT 'registering',
    -- registering | online | offline | degraded | upgrading
    
    -- 心跳
    last_heartbeat_at   TIMESTAMPTZ,
    heartbeat_interval  SMALLINT DEFAULT 10,  -- 秒
    
    -- 指标快照（最新）
    current_qps         FLOAT DEFAULT 0,
    drop_rate           FLOAT DEFAULT 0,
    cpu_percent         FLOAT DEFAULT 0,
    memory_mb_used      INTEGER DEFAULT 0,
    config_version      BIGINT DEFAULT 0,
    
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(tenant_id, agent_code)
);

CREATE INDEX idx_agents_tenant ON agents(tenant_id);
CREATE INDEX idx_agents_status ON agents(status);
CREATE INDEX idx_agents_cluster ON agents(tenant_id, cluster);
CREATE INDEX idx_agents_heartbeat ON agents(last_heartbeat_at);

-- ============================================================
-- 采集器心跳日志表
-- ============================================================
CREATE TABLE agent_heartbeats (
    id              BIGSERIAL PRIMARY KEY,
    agent_id        UUID NOT NULL REFERENCES agents(id),
    
    status          VARCHAR(16) NOT NULL,   -- running | degraded | stopping
    qps             FLOAT,
    packets_per_sec FLOAT,
    drop_rate       FLOAT,
    cpu_percent     FLOAT,
    memory_mb       INTEGER,
    kafka_lag       INTEGER,
    
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_heartbeats_agent ON agent_heartbeats(agent_id);
CREATE INDEX idx_heartbeats_time ON agent_heartbeats(recorded_at);

-- 分区建议：按月分区

-- ============================================================
-- 审计日志表
-- ============================================================
CREATE TABLE audit_logs (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    
    operator_id     UUID REFERENCES users(id),
    operator_name   VARCHAR(64),  -- 冗余存储，用户删除后仍可查
    action          VARCHAR(128) NOT NULL,
    resource_type   VARCHAR(64),
    resource_id     VARCHAR(128),
    detail          JSONB,
    
    ip_address      INET,
    user_agent      VARCHAR(512),
    
    -- 哈希链防篡改
    prev_hash       VARCHAR(64),
    current_hash    VARCHAR(64) NOT NULL,
    
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_tenant ON audit_logs(tenant_id);
CREATE INDEX idx_audit_operator ON audit_logs(operator_id);
CREATE INDEX idx_audit_action ON audit_logs(action);
CREATE INDEX idx_audit_time ON audit_logs(created_at);

-- 分区建议：按月分区
-- 留存策略：≥180天

-- ============================================================
-- 报表记录表
-- ============================================================
CREATE TABLE reports (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    
    report_type     VARCHAR(64) NOT NULL,       -- compliance_quarterly | ...
    template        VARCHAR(32) NOT NULL,       -- financial | government | healthcare
    period_start    DATE NOT NULL,
    period_end      DATE NOT NULL,
    format          VARCHAR(16) DEFAULT 'pdf',  -- pdf | word
    
    status          VARCHAR(16) DEFAULT 'pending',
    -- pending | generating | completed | failed
    
    file_path       VARCHAR(512),
    file_size_bytes INTEGER,
    
    generated_by    UUID REFERENCES users(id),
    generated_at    TIMESTAMPTZ,
    error_message   TEXT,
    
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_reports_tenant ON reports(tenant_id);
CREATE INDEX idx_reports_status ON reports(status);
CREATE INDEX idx_reports_type ON reports(report_type);

-- ============================================================
-- API 分组表（树形结构）
-- ============================================================
CREATE TABLE asset_groups (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    
    parent_id       UUID REFERENCES asset_groups(id),
    name            VARCHAR(128) NOT NULL,
    full_path       VARCHAR(512) NOT NULL,  -- "零售事业部/交易系统/订单模块"
    level           SMALLINT NOT NULL DEFAULT 1,
    
    auto_rule       JSONB,  -- 自动分组规则
    description     TEXT,
    sort_order      INTEGER DEFAULT 0,
    
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(tenant_id, full_path)
);

CREATE INDEX idx_groups_tenant ON asset_groups(tenant_id);
CREATE INDEX idx_groups_parent ON asset_groups(parent_id);

-- ============================================================
-- 资产分组自动规则表
-- ============================================================
CREATE TABLE asset_group_rules (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    group_id        UUID NOT NULL REFERENCES asset_groups(id),
    
    rule_type       VARCHAR(16) NOT NULL,   -- domain | path_prefix | label
    rule_value      VARCHAR(512) NOT NULL,
    priority        INTEGER DEFAULT 0,
    enabled         BOOLEAN DEFAULT TRUE,
    
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_group_rules_tenant ON asset_group_rules(tenant_id);
CREATE INDEX idx_group_rules_group ON asset_group_rules(group_id);

-- ============================================================
-- 联结表：资产 ↔ 分组（多对多）
-- ============================================================
CREATE TABLE asset_group_mappings (
    asset_id    UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    group_id    UUID NOT NULL REFERENCES asset_groups(id) ON DELETE CASCADE,
    matched_by  VARCHAR(16) DEFAULT 'rule',  -- rule | manual
    PRIMARY KEY (asset_id, group_id)
);

CREATE INDEX idx_asset_group_mapping_group ON asset_group_mappings(group_id);

-- ============================================================
-- Webhook/订阅配置表
-- ============================================================
CREATE TABLE webhook_configs (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    
    name            VARCHAR(128) NOT NULL,
    url             VARCHAR(512) NOT NULL,
    secret          VARCHAR(256),  -- 用于签名验证
    
    event_types     JSONB NOT NULL,  -- ["alert.created", "asset.new", "agent.offline"]
    
    enabled         BOOLEAN DEFAULT TRUE,
    last_triggered  TIMESTAMPTZ,
    last_status     VARCHAR(16),
    
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhook_tenant ON webhook_configs(tenant_id);
CREATE INDEX idx_webhook_enabled ON webhook_configs(enabled);

-- ============================================================
-- 敏感数据脱敏缺陷表
-- ============================================================
CREATE TABLE masking_defects (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    asset_id        UUID NOT NULL REFERENCES assets(id),
    
    defect_type     VARCHAR(32) NOT NULL,
    -- no_masking | incomplete_masking | inconsistent_masking
    
    field_name      VARCHAR(128) NOT NULL,
    data_type       VARCHAR(64),
    expected_pattern VARCHAR(256),
    actual_pattern  VARCHAR(256),
    
    severity        VARCHAR(16) NOT NULL DEFAULT 'medium',
    status          VARCHAR(16) DEFAULT 'open',
    
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,
    
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_masking_defects_tenant ON masking_defects(tenant_id);
CREATE INDEX idx_masking_defects_asset ON masking_defects(asset_id);
CREATE INDEX idx_masking_defects_status ON masking_defects(status);

-- ============================================================
-- 触发器：自动更新 updated_at
-- ============================================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 应用触发器

DO $$
DECLARE
    t TEXT;
BEGIN
    FOR t IN SELECT table_name FROM information_schema.columns 
             WHERE column_name = 'updated_at' 
             AND table_schema = 'public'
    LOOP
        EXECUTE format('CREATE TRIGGER trigger_update_updated_at
            BEFORE UPDATE ON %I
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()', t);
    END LOOP;
END;
$$;
