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

-- fl_audit_logs and fl_detection_events are partitioned by month and are
-- created and migrated in pg_partition.go.


-- Business records (assets, alerts, detection rules, collectors) stored as
-- JSON documents; the platform keeps a working copy in memory.
CREATE TABLE IF NOT EXISTS fl_documents (
    kind       TEXT NOT NULL,
    id         TEXT NOT NULL,
    data       JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (kind, id)
);
