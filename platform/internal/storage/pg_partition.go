package storage

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The two tables that grow without bound (the audit trail, kept for at
// least 180 days, and detection events) are range-partitioned by month:
//
//   - queries with a time range touch only the matching partitions;
//   - retention drops whole partitions instead of deleting billions of rows;
//   - every index is per partition, so index depth stays bounded.
//
// All list queries order by (time DESC, seq DESC) and each filter has a
// matching (filter, time, seq) index, so fetching a page reads only that
// page from an index regardless of table size.

const auditTableDDL = `
CREATE TABLE fl_audit_logs (
    seq            BIGINT NOT NULL,
    time           TIMESTAMPTZ NOT NULL,
    user_id        TEXT NOT NULL DEFAULT '',
    username       TEXT NOT NULL DEFAULT '',
    -- a plain (stored) column rather than an index on lower(username), so
    -- counting a user's records is an index-only scan
    username_lower TEXT GENERATED ALWAYS AS (lower(username)) STORED,
    role           TEXT NOT NULL DEFAULT '',
    source_ip      TEXT NOT NULL DEFAULT '',
    console        TEXT NOT NULL DEFAULT '',
    event_type     TEXT NOT NULL,
    event_category TEXT GENERATED ALWAYS AS (split_part(event_type, '.', 1)) STORED,
    target         TEXT NOT NULL DEFAULT '',
    result         TEXT NOT NULL,
    reason         TEXT NOT NULL DEFAULT '',
    detail         TEXT NOT NULL DEFAULT '',
    method         TEXT NOT NULL DEFAULT '',
    path           TEXT NOT NULL DEFAULT '',
    prev_hash      TEXT NOT NULL,
    hash           TEXT NOT NULL,
    PRIMARY KEY (time, seq)
) PARTITION BY RANGE (time)`

// auditIndexes are declared on the parent and created on every partition.
//
// Every filter combination the console offers (user, event category,
// "failed only", each with an optional time range) has an index whose
// leading columns are its equality filters and whose tail is (time, seq).
// A page and the capped count are then index range scans of at most
// MaxAuditCount+1 entries, independent of table size. "Succeeded only"
// needs no index: it matches ~95% of rows. Failures are rare, so their
// indexes are small partial indexes.
var auditIndexes = []string{
	// chain walks and verification in sequence order
	`CREATE INDEX IF NOT EXISTS fl_audit_seq_idx ON fl_audit_logs (seq)`,
	// INCLUDE lets the remaining filters (exact type, result) be checked in
	// the index, so counts are index-only scans.
	`CREATE INDEX IF NOT EXISTS fl_audit_user_idx ON fl_audit_logs (username_lower, time, seq) INCLUDE (event_type, result)`,
	`CREATE INDEX IF NOT EXISTS fl_audit_cat_idx ON fl_audit_logs (event_category, time, seq) INCLUDE (event_type, result)`,
	`CREATE INDEX IF NOT EXISTS fl_audit_user_cat_idx ON fl_audit_logs (username_lower, event_category, time, seq) INCLUDE (event_type, result)`,
	`CREATE INDEX IF NOT EXISTS fl_audit_failure_time_idx ON fl_audit_logs (time, seq) WHERE result = 'failure'`,
	`CREATE INDEX IF NOT EXISTS fl_audit_failure_user_idx ON fl_audit_logs (username_lower, time, seq) WHERE result = 'failure'`,
	`CREATE INDEX IF NOT EXISTS fl_audit_fail_cat_idx ON fl_audit_logs (event_category, time, seq) INCLUDE (event_type) WHERE result = 'failure'`,
	`CREATE INDEX IF NOT EXISTS fl_audit_fail_user_cat_idx ON fl_audit_logs (username_lower, event_category, time, seq) INCLUDE (event_type) WHERE result = 'failure'`,
}

const auditTriggerDDL = `
CREATE OR REPLACE FUNCTION fl_audit_no_update() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'fl_audit_logs is append-only';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS fl_audit_no_update ON fl_audit_logs;
CREATE TRIGGER fl_audit_no_update BEFORE UPDATE ON fl_audit_logs
    FOR EACH ROW EXECUTE FUNCTION fl_audit_no_update();`

// fl_audit_head holds the last record's seq, hash and time. Appends lock
// this one row instead of searching the partitioned table for its end.
const auditHeadDDL = `
CREATE TABLE IF NOT EXISTS fl_audit_head (
    id   INTEGER PRIMARY KEY CHECK (id = 1),
    seq  BIGINT NOT NULL,
    hash TEXT NOT NULL,
    time TIMESTAMPTZ NOT NULL
)`

const detectionTableDDL = `
CREATE TABLE fl_detection_events (
    id         TEXT NOT NULL,
    type       TEXT NOT NULL,
    severity   TEXT NOT NULL,
    title      TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    source_ip  TEXT NOT NULL DEFAULT '',
    account_id TEXT NOT NULL DEFAULT '',
    risk_score INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (created_at, id)
) PARTITION BY RANGE (created_at)`

type partitionedTable struct {
	name    string
	ddl     string
	upgrade []string // DDL bringing an older partitioned table up to date
	indexes []string
	after   string // extra DDL (triggers)
	partKey string
	columns string // columns copied when migrating an unpartitioned table
	oldPKey string
}

var partitionedTables = []partitionedTable{
	{
		name: "fl_audit_logs", ddl: auditTableDDL, indexes: auditIndexes, after: auditTriggerDDL, partKey: "time",
		upgrade: []string{
			`ALTER TABLE fl_audit_logs ADD COLUMN IF NOT EXISTS username_lower TEXT GENERATED ALWAYS AS (lower(username)) STORED`,
			`DROP INDEX IF EXISTS fl_audit_user_time_idx`,
			// exact event types are filtered through the category indexes
			`DROP INDEX IF EXISTS fl_audit_type_time_idx`,
			// superseded by the INCLUDE variants
			`DROP INDEX IF EXISTS fl_audit_username_time_idx`,
			`DROP INDEX IF EXISTS fl_audit_category_time_idx`,
			`DROP INDEX IF EXISTS fl_audit_user_cat_time_idx`,
			`DROP INDEX IF EXISTS fl_audit_failure_cat_idx`,
			`DROP INDEX IF EXISTS fl_audit_failure_user_cat_idx`,
		},
		columns: "seq, time, user_id, username, role, source_ip, console, event_type, target, result, reason, detail, method, path, prev_hash, hash",
		oldPKey: "fl_audit_logs_pkey",
	},
	{
		name: "fl_detection_events", ddl: detectionTableDDL, partKey: "created_at",
		columns: "id, type, severity, title, detail, source_ip, account_id, risk_score, created_at",
		oldPKey: "fl_detection_events_pkey",
	},
}

// partitionParams make autovacuum process append-only partitions early, so
// the visibility map stays current and counts remain index-only scans.
const partitionParams = ` WITH (autovacuum_vacuum_insert_scale_factor = 0.01, autovacuum_analyze_scale_factor = 0.02)`

// partitionManager creates monthly partitions on demand and remembers the
// ones that exist.
type partitionManager struct {
	pool *pgxpool.Pool
	mu   sync.Mutex
	have map[string]bool
}

func monthStart(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
}

func partitionName(table string, month time.Time) string {
	return fmt.Sprintf("%s_y%04dm%02d", table, month.Year(), int(month.Month()))
}

var partitionNameRe = regexp.MustCompile(`_y(\d{4})m(\d{2})$`)

// ensure creates the partition of table covering t if it does not exist.
func (m *partitionManager) ensure(ctx context.Context, table string, t time.Time) error {
	month := monthStart(t)
	name := partitionName(table, month)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.have[name] {
		return nil
	}
	sql := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')`,
		pgx.Identifier{name}.Sanitize(), table, month.Format(time.RFC3339), month.AddDate(0, 1, 0).Format(time.RFC3339)) + partitionParams
	if _, err := m.pool.Exec(ctx, sql); err != nil && !isDuplicate(err) {
		return fmt.Errorf("create partition %s: %w", name, err)
	}
	m.have[name] = true
	return nil
}

// ensureAhead creates partitions from the previous month to three months
// ahead, so inserts never wait on DDL.
func (m *partitionManager) ensureAhead(ctx context.Context, now time.Time) error {
	for _, t := range partitionedTables {
		for i := -1; i <= 3; i++ {
			if err := m.ensure(ctx, t.name, monthStart(now).AddDate(0, i, 0)); err != nil {
				return err
			}
		}
	}
	return nil
}

func isDuplicate(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && (pg.Code == "42P07" || pg.Code == "23505")
}

// migratePartitioned creates the partitioned tables, converting tables
// created by earlier versions (unpartitioned) in place.
func migratePartitioned(ctx context.Context, pool *pgxpool.Pool, pm *partitionManager) error {
	for _, t := range partitionedTables {
		var kind string
		err := pool.QueryRow(ctx, `SELECT c.relkind::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE c.relname = $1 AND n.nspname = current_schema()`, t.name).Scan(&kind)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if kind == "p" {
			for _, stmt := range t.upgrade {
				if _, err := pool.Exec(ctx, stmt); err != nil {
					return fmt.Errorf("%s upgrade: %w", t.name, err)
				}
			}
			for _, idx := range t.indexes {
				if _, err := pool.Exec(ctx, idx); err != nil {
					return fmt.Errorf("%s index: %w", t.name, err)
				}
			}
			continue
		}
		if err := convertTable(ctx, pool, pm, t, kind == "r"); err != nil {
			return fmt.Errorf("migrate %s: %w", t.name, err)
		}
	}
	if _, err := pool.Exec(ctx, auditHeadDDL); err != nil {
		return err
	}
	// Initialise the chain head from existing records (fresh or migrated).
	_, err := pool.Exec(ctx, `INSERT INTO fl_audit_head (id, seq, hash, time)
		SELECT 1, seq, hash, time FROM fl_audit_logs ORDER BY seq DESC LIMIT 1
		ON CONFLICT (id) DO NOTHING`)
	return err
}

func convertTable(ctx context.Context, pool *pgxpool.Pool, pm *partitionManager, t partitionedTable, hasOld bool) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	old := t.name + "_v1"
	if hasOld {
		stmts := []string{
			fmt.Sprintf(`ALTER TABLE %s RENAME TO %s`, t.name, old),
			fmt.Sprintf(`ALTER TABLE %s RENAME CONSTRAINT %s TO %s_pkey`, old, t.oldPKey, old),
		}
		for _, s := range stmts {
			if _, err := tx.Exec(ctx, s); err != nil {
				return err
			}
		}
	}
	if _, err := tx.Exec(ctx, t.ddl); err != nil {
		return err
	}
	for _, idx := range t.indexes {
		if _, err := tx.Exec(ctx, idx); err != nil {
			return err
		}
	}
	if t.after != "" {
		if _, err := tx.Exec(ctx, t.after); err != nil {
			return err
		}
	}
	if hasOld {
		var lo, hi *time.Time
		if err := tx.QueryRow(ctx, fmt.Sprintf(`SELECT min(%[1]s), max(%[1]s) FROM %[2]s`, t.partKey, old)).Scan(&lo, &hi); err != nil {
			return err
		}
		if lo != nil {
			for m := monthStart(*lo); !m.After(*hi); m = m.AddDate(0, 1, 0) {
				name := partitionName(t.name, m)
				if _, err := tx.Exec(ctx, fmt.Sprintf(`CREATE TABLE %s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')`,
					name, t.name, m.Format(time.RFC3339), m.AddDate(0, 1, 0).Format(time.RFC3339))+partitionParams); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(ctx, fmt.Sprintf(`INSERT INTO %s (%s) SELECT %s FROM %s`, t.name, t.columns, t.columns, old)); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, fmt.Sprintf(`DROP TABLE %s`, old)); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	pm.mu.Lock()
	pm.have = make(map[string]bool) // re-learn after DDL
	pm.mu.Unlock()
	return nil
}

// dropPartitionsBefore drops the partitions of table that lie entirely
// before t and returns the (estimated) number of rows they held. Rows in
// the partition containing t are kept: retention is a minimum, so keeping
// up to one extra month is compliant and avoids row-by-row deletes.
func (m *partitionManager) dropPartitionsBefore(ctx context.Context, table string, t time.Time) (int64, error) {
	rows, err := m.pool.Query(ctx, `SELECT c.relname, greatest(c.reltuples, 0)::bigint FROM pg_inherits i
		JOIN pg_class c ON c.oid = i.inhrelid JOIN pg_class p ON p.oid = i.inhparent
		WHERE p.relname = $1`, table)
	if err != nil {
		return 0, err
	}
	type part struct {
		name string
		rows int64
	}
	var drop []part
	for rows.Next() {
		var p part
		if err := rows.Scan(&p.name, &p.rows); err != nil {
			rows.Close()
			return 0, err
		}
		mm := partitionNameRe.FindStringSubmatch(p.name)
		if mm == nil {
			continue
		}
		start, err := time.Parse("2006-01", mm[1]+"-"+mm[2])
		if err != nil {
			continue
		}
		if !start.AddDate(0, 1, 0).After(t) {
			drop = append(drop, p)
		}
	}
	rows.Close()
	var total int64
	for _, p := range drop {
		if p.rows == 0 {
			// Never analysed (small or new): count exactly.
			_ = m.pool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s`, pgx.Identifier{p.name}.Sanitize())).Scan(&p.rows)
		}
		if _, err := m.pool.Exec(ctx, fmt.Sprintf(`DROP TABLE %s`, pgx.Identifier{p.name}.Sanitize())); err != nil {
			return total, err
		}
		total += p.rows
		m.mu.Lock()
		delete(m.have, p.name)
		m.mu.Unlock()
	}
	return total, nil
}

// categoryOf returns the category filter for an event type query: "auth."
// means the whole auth category.
func categoryOf(eventType string) (string, bool) {
	if strings.HasSuffix(eventType, ".") && !strings.Contains(strings.TrimSuffix(eventType, "."), ".") {
		return strings.TrimSuffix(eventType, "."), true
	}
	return "", false
}
