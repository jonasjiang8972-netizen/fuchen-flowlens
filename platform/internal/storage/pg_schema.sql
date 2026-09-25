-- FlowLens platform schema (identity, sessions, settings, audit, detections).
-- Applied at startup; every statement is idempotent.

CREATE TABLE IF NOT EXISTS fl_users (
    id                   TEXT PRIMARY KEY,
    username             TEXT NOT NULL,
    display_name         TEXT NOT NULL DEFAULT '',
    email                TEXT NOT NULL DEFAULT '',
    password_hash        TEXT NOT NULL,
    password_history     JSONB NOT NULL DEFAULT '[]',
    password_changed_at  TIMESTAMPTZ NOT NULL,
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    role                 TEXT NOT NULL,
    status               TEXT NOT NULL DEFAULT 'active',
    failed_attempts      INTEGER NOT NULL DEFAULT 0,
    locked_until         TIMESTAMPTZ,
    last_login_at        TIMESTAMPTZ,
    last_login_ip        TEXT NOT NULL DEFAULT '',
    expires_at           TIMESTAMPTZ,
    created_by           TEXT NOT NULL DEFAULT '',
    created_at           TIMESTAMPTZ NOT NULL,
    updated_at           TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS fl_users_username_uq ON fl_users (lower(username));

CREATE TABLE IF NOT EXISTS fl_sessions (
    token_hash   TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES fl_users(id) ON DELETE CASCADE,
    source_ip    TEXT NOT NULL DEFAULT '',
    user_agent   TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS fl_sessions_user_idx ON fl_sessions (user_id);

CREATE TABLE IF NOT EXISTS fl_settings (
    key        TEXT PRIMARY KEY,
    value      JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS fl_audit_logs (
    seq        BIGSERIAL PRIMARY KEY,
    time       TIMESTAMPTZ NOT NULL,
    user_id    TEXT NOT NULL DEFAULT '',
    username   TEXT NOT NULL DEFAULT '',
    role       TEXT NOT NULL DEFAULT '',
    source_ip  TEXT NOT NULL DEFAULT '',
    console    TEXT NOT NULL DEFAULT '',
    event_type TEXT NOT NULL,
    target     TEXT NOT NULL DEFAULT '',
    result     TEXT NOT NULL,
    reason     TEXT NOT NULL DEFAULT '',
    detail     TEXT NOT NULL DEFAULT '',
    method     TEXT NOT NULL DEFAULT '',
    path       TEXT NOT NULL DEFAULT '',
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS fl_audit_time_idx ON fl_audit_logs (time);
CREATE INDEX IF NOT EXISTS fl_audit_user_idx ON fl_audit_logs (lower(username));
CREATE INDEX IF NOT EXISTS fl_audit_event_idx ON fl_audit_logs (event_type);

-- The audit trail is append-only: block UPDATE outright. DELETE is allowed
-- only for retention purges, which the application restricts to records
-- older than the configured retention period (>= 180 days).
CREATE OR REPLACE FUNCTION fl_audit_no_update() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'fl_audit_logs is append-only';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS fl_audit_no_update ON fl_audit_logs;
CREATE TRIGGER fl_audit_no_update BEFORE UPDATE ON fl_audit_logs
    FOR EACH ROW EXECUTE FUNCTION fl_audit_no_update();

CREATE TABLE IF NOT EXISTS fl_detection_events (
    id         TEXT PRIMARY KEY,
    type       TEXT NOT NULL,
    severity   TEXT NOT NULL,
    title      TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    source_ip  TEXT NOT NULL DEFAULT '',
    account_id TEXT NOT NULL DEFAULT '',
    risk_score INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS fl_detection_created_idx ON fl_detection_events (created_at);

-- Business records (assets, alerts, detection rules, collectors) stored as
-- JSON documents; the platform keeps a working copy in memory.
CREATE TABLE IF NOT EXISTS fl_documents (
    kind       TEXT NOT NULL,
    id         TEXT NOT NULL,
    data       JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (kind, id)
);
