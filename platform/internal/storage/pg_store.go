package storage

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed pg_schema.sql
var pgSchema string

// PGStore persists data in PostgreSQL.
type PGStore struct {
	pool *pgxpool.Pool
	pm   *partitionManager
}

// NewPGStore connects to dsn and applies the schema.
func NewPGStore(ctx context.Context, dsn string) (*PGStore, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	if _, err := pool.Exec(ctx, pgSchema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	pm := &partitionManager{pool: pool, have: make(map[string]bool)}
	if err := migratePartitioned(ctx, pool, pm); err != nil {
		pool.Close()
		return nil, fmt.Errorf("partitioned tables: %w", err)
	}
	if err := pm.ensureAhead(ctx, time.Now()); err != nil {
		pool.Close()
		return nil, err
	}
	return &PGStore{pool: pool, pm: pm}, nil
}

// EnsurePartitionRange creates the monthly partitions of both partitioned
// tables covering [from, to], e.g. before importing historical records.
func (s *PGStore) EnsurePartitionRange(ctx context.Context, from, to time.Time) error {
	for _, t := range partitionedTables {
		for m := monthStart(from); !m.After(to); m = m.AddDate(0, 1, 0) {
			if err := s.pm.ensure(ctx, t.name, m); err != nil {
				return err
			}
		}
	}
	return nil
}

// EnsurePartitions creates upcoming monthly partitions; the platform calls
// it daily.
func (s *PGStore) EnsurePartitions(ctx context.Context) error {
	return s.pm.ensureAhead(ctx, time.Now())
}

func (s *PGStore) Close() error {
	s.pool.Close()
	return nil
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// ─── Users ─────────────────────────────────────────────────────

const userColumns = `id, username, display_name, email, password_hash, password_history,
	password_changed_at, must_change_password, role, status, failed_attempts, locked_until,
	last_login_at, last_login_ip, expires_at, created_by, created_at, updated_at`

func scanUser(row pgx.Row) (*User, error) {
	var u User
	var history []byte
	err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.PasswordHash, &history,
		&u.PasswordChangedAt, &u.MustChangePassword, &u.Role, &u.Status, &u.FailedAttempts, &u.LockedUntil,
		&u.LastLoginAt, &u.LastLoginIP, &u.ExpiresAt, &u.CreatedBy, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	if err := json.Unmarshal(history, &u.PasswordHistory); err != nil {
		return nil, fmt.Errorf("decode password history: %w", err)
	}
	return &u, nil
}

func historyJSON(u *User) []byte {
	h := u.PasswordHistory
	if h == nil {
		h = []string{}
	}
	b, _ := json.Marshal(h)
	return b
}

func (s *PGStore) CreateUser(ctx context.Context, u *User) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO fl_users (`+userColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
		u.ID, u.Username, u.DisplayName, u.Email, u.PasswordHash, historyJSON(u),
		u.PasswordChangedAt, u.MustChangePassword, u.Role, u.Status, u.FailedAttempts, u.LockedUntil,
		u.LastLoginAt, u.LastLoginIP, u.ExpiresAt, u.CreatedBy, u.CreatedAt, u.UpdatedAt)
	if err != nil && strings.Contains(err.Error(), "fl_users_username_uq") {
		return fmt.Errorf("username %s already exists", u.Username)
	}
	return err
}

func (s *PGStore) UpdateUser(ctx context.Context, u *User) error {
	tag, err := s.pool.Exec(ctx, `UPDATE fl_users SET username=$2, display_name=$3, email=$4,
		password_hash=$5, password_history=$6, password_changed_at=$7, must_change_password=$8,
		role=$9, status=$10, failed_attempts=$11, locked_until=$12, last_login_at=$13,
		last_login_ip=$14, expires_at=$15, updated_at=$16 WHERE id=$1`,
		u.ID, u.Username, u.DisplayName, u.Email, u.PasswordHash, historyJSON(u),
		u.PasswordChangedAt, u.MustChangePassword, u.Role, u.Status, u.FailedAttempts, u.LockedUntil,
		u.LastLoginAt, u.LastLoginIP, u.ExpiresAt, u.UpdatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PGStore) DeleteUser(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM fl_users WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PGStore) GetUserByID(ctx context.Context, id string) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM fl_users WHERE id=$1`, id))
}

func (s *PGStore) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM fl_users WHERE lower(username)=lower($1)`, username))
}

func (s *PGStore) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userColumns+` FROM fl_users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

func (s *PGStore) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM fl_users`).Scan(&n)
	return n, err
}

// ─── Sessions ──────────────────────────────────────────────────

func (s *PGStore) CreateSession(ctx context.Context, sess *Session) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO fl_sessions
		(token_hash, user_id, source_ip, user_agent, created_at, last_seen_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		sess.TokenHash, sess.UserID, sess.SourceIP, sess.UserAgent, sess.CreatedAt, sess.LastSeenAt, sess.ExpiresAt)
	return err
}

func (s *PGStore) GetSession(ctx context.Context, tokenHash string) (*Session, error) {
	var sess Session
	err := s.pool.QueryRow(ctx, `SELECT token_hash, user_id, source_ip, user_agent, created_at, last_seen_at, expires_at
		FROM fl_sessions WHERE token_hash=$1`, tokenHash).
		Scan(&sess.TokenHash, &sess.UserID, &sess.SourceIP, &sess.UserAgent, &sess.CreatedAt, &sess.LastSeenAt, &sess.ExpiresAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &sess, nil
}

func (s *PGStore) TouchSession(ctx context.Context, tokenHash string, at time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE fl_sessions SET last_seen_at=$2 WHERE token_hash=$1`, tokenHash, at)
	return err
}

func (s *PGStore) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM fl_sessions WHERE token_hash=$1`, tokenHash)
	return err
}

func (s *PGStore) DeleteUserSessions(ctx context.Context, userID, keepHash string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM fl_sessions WHERE user_id=$1 AND token_hash<>$2`, userID, keepHash)
	return err
}

func (s *PGStore) DeleteExpiredSessions(ctx context.Context, idleBefore, now time.Time) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM fl_sessions WHERE last_seen_at < $1 OR expires_at <= $2`, idleBefore, now)
	return err
}

// ─── Settings ──────────────────────────────────────────────────

func (s *PGStore) GetSetting(ctx context.Context, key string) ([]byte, error) {
	var v []byte
	if err := s.pool.QueryRow(ctx, `SELECT value FROM fl_settings WHERE key=$1`, key).Scan(&v); err != nil {
		return nil, notFound(err)
	}
	return v, nil
}

func (s *PGStore) PutSetting(ctx context.Context, key string, value []byte) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO fl_settings (key, value, updated_at) VALUES ($1, $2, NOW())
		ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=NOW()`, key, value)
	return err
}

// ─── Audit ─────────────────────────────────────────────────────

const auditColumns = `seq, time, user_id, username, role, source_ip, console, event_type,
	target, result, reason, detail, method, path, prev_hash, hash`

func scanAudit(row pgx.Row) (AuditRecord, error) {
	var r AuditRecord
	err := row.Scan(&r.Seq, &r.Time, &r.UserID, &r.Username, &r.Role, &r.SourceIP, &r.Console, &r.EventType,
		&r.Target, &r.Result, &r.Reason, &r.Detail, &r.Method, &r.Path, &r.PrevHash, &r.Hash)
	return r, err
}

// AppendAudit locks the chain head row, so appends from any number of
// platform instances form one linear chain. Record time is kept monotonic
// (never earlier than the previous record) so time order equals sequence
// order, which the time-ordered indexes and partitions rely on.
func (s *PGStore) AppendAudit(ctx context.Context, rec *AuditRecord, chain func(prevHash string) string) error {
	if err := s.pm.ensure(ctx, "fl_audit_logs", rec.Time); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Take the head lock; the first append creates the row.
	if _, err := tx.Exec(ctx, `INSERT INTO fl_audit_head (id, seq, hash, time) VALUES (1, 0, '', '-infinity')
		ON CONFLICT (id) DO NOTHING`); err != nil {
		return err
	}
	var headSeq int64
	var headHash string
	var headTime time.Time
	var headInf pgtype.InfinityModifier
	var ht pgtype.Timestamptz
	if err := tx.QueryRow(ctx, `SELECT seq, hash, time FROM fl_audit_head WHERE id = 1 FOR UPDATE`).Scan(&headSeq, &headHash, &ht); err != nil {
		return err
	}
	headTime, headInf = ht.Time, ht.InfinityModifier
	if headInf == pgtype.Finite && rec.Time.Before(headTime) {
		rec.Time = headTime
	}
	rec.Seq = headSeq + 1
	rec.PrevHash = headHash
	rec.Hash = chain(headHash)
	_, err = tx.Exec(ctx, `INSERT INTO fl_audit_logs (`+auditColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		rec.Seq, rec.Time, rec.UserID, rec.Username, rec.Role, rec.SourceIP, rec.Console, rec.EventType,
		rec.Target, rec.Result, rec.Reason, rec.Detail, rec.Method, rec.Path, rec.PrevHash, rec.Hash)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE fl_audit_head SET seq = $1, hash = $2, time = $3 WHERE id = 1`, rec.Seq, rec.Hash, rec.Time); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func auditWhere(q AuditQuery) (string, []any) {
	var conds []string
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		conds = append(conds, fmt.Sprintf(cond, len(args)))
	}
	if q.Username != "" {
		add("username_lower = lower($%d)", q.Username)
	}
	if q.EventType != "" {
		// "auth." selects a category, anything else an exact event type;
		// both are equality lookups on an indexed column.
		if cat, ok := categoryOf(q.EventType); ok {
			add("event_category = $%d", cat)
		} else {
			// Constrain the category too, so the category indexes apply.
			add("event_category = $%d", strings.SplitN(q.EventType, ".", 2)[0])
			add("event_type = $%d", q.EventType)
		}
	}
	if q.Result != "" {
		add("result = $%d", q.Result)
	}
	if q.Console != "" {
		add("console = $%d", q.Console)
	}
	if !q.From.IsZero() {
		add("time >= $%d", q.From)
	}
	if !q.To.IsZero() {
		add("time < $%d", q.To)
	}
	if len(conds) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// ListAudit returns one page, newest first. The total is exact up to
// MaxAuditCount and reported as MaxAuditCount+1 beyond it: counting every
// match of a broad filter over billions of rows cannot be done in seconds.
func (s *PGStore) ListAudit(ctx context.Context, q AuditQuery) ([]AuditRecord, int, error) {
	where, args := auditWhere(q)
	var total int
	if err := s.pool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM (SELECT 1 FROM fl_audit_logs%s LIMIT %d) m`,
		where, MaxAuditCount+1), args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}
	args = append(args, limit, q.Offset)
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`SELECT `+auditColumns+` FROM fl_audit_logs%s
		ORDER BY time DESC, seq DESC LIMIT $%d OFFSET $%d`, where, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []AuditRecord
	for rows.Next() {
		r, err := scanAudit(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

func (s *PGStore) WalkAudit(ctx context.Context, fn func(AuditRecord) error) error {
	return s.WalkAuditFrom(ctx, 0, fn)
}

// WalkAuditFrom visits records with seq >= from in sequence order. It reads
// in batches so a walk over billions of rows never holds one huge query.
func (s *PGStore) WalkAuditFrom(ctx context.Context, from int64, fn func(AuditRecord) error) error {
	const batch = 10000
	next := from
	for {
		rows, err := s.pool.Query(ctx, `SELECT `+auditColumns+` FROM fl_audit_logs WHERE seq >= $1 ORDER BY seq LIMIT $2`, next, batch)
		if err != nil {
			return err
		}
		n := 0
		for rows.Next() {
			r, err := scanAudit(rows)
			if err != nil {
				rows.Close()
				return err
			}
			n++
			next = r.Seq + 1
			if err := fn(r); err != nil {
				rows.Close()
				return err
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if n < batch {
			return nil
		}
	}
}

// DeleteAuditBefore drops monthly partitions lying entirely before t.
func (s *PGStore) DeleteAuditBefore(ctx context.Context, t time.Time) (int64, error) {
	return s.pm.dropPartitionsBefore(ctx, "fl_audit_logs", t)
}

// ─── Documents ─────────────────────────────────────────────────

func (s *PGStore) LoadDocuments(ctx context.Context, kind string) (map[string][]byte, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, data FROM fl_documents WHERE kind=$1`, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string][]byte)
	for rows.Next() {
		var id string
		var data []byte
		if err := rows.Scan(&id, &data); err != nil {
			return nil, err
		}
		out[id] = data
	}
	return out, rows.Err()
}

// SaveDocuments upserts docs in one transaction.
func (s *PGStore) SaveDocuments(ctx context.Context, kind string, docs map[string][]byte) error {
	if len(docs) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for id, data := range docs {
		batch.Queue(`INSERT INTO fl_documents (kind, id, data, updated_at) VALUES ($1, $2, $3, NOW())
			ON CONFLICT (kind, id) DO UPDATE SET data=EXCLUDED.data, updated_at=NOW()`, kind, id, data)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := tx.SendBatch(ctx, batch).Close(); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ─── Detection events ──────────────────────────────────────────

func (s *PGStore) SaveDetectionEvent(ctx context.Context, e *AlertEvent) error {
	if err := s.pm.ensure(ctx, "fl_detection_events", e.CreatedAt); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO fl_detection_events
		(id, type, severity, title, detail, source_ip, account_id, risk_score, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (created_at, id) DO NOTHING`,
		e.ID, e.Type, e.Severity, e.Title, e.Detail, e.SourceIP, e.AccountID, e.RiskScore, e.CreatedAt)
	return err
}

// ListRecentAlerts returns up to limit events after since, newest first.
func (s *PGStore) ListRecentAlerts(ctx context.Context, since time.Time, limit int) ([]AlertEvent, error) {
	if limit <= 0 {
		limit = 1000
	}
	rows, err := s.pool.Query(ctx, `SELECT id, type, severity, title, detail, source_ip, account_id, risk_score, created_at
		FROM fl_detection_events WHERE created_at > $1 ORDER BY created_at DESC LIMIT $2`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertEvent
	for rows.Next() {
		var e AlertEvent
		if err := rows.Scan(&e.ID, &e.Type, &e.Severity, &e.Title, &e.Detail, &e.SourceIP, &e.AccountID, &e.RiskScore, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// DeleteDetectionEventsBefore drops monthly partitions lying entirely before t.
func (s *PGStore) DeleteDetectionEventsBefore(ctx context.Context, t time.Time) (int64, error) {
	return s.pm.dropPartitionsBefore(ctx, "fl_detection_events", t)
}
