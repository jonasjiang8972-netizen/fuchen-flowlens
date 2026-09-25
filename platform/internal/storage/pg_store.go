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
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed pg_schema.sql
var pgSchema string

// auditLockKey serialises audit appends across platform instances so the
// hash chain stays linear.
const auditLockKey = 0x464c4155 // "FLAU"

// PGStore persists data in PostgreSQL.
type PGStore struct {
	pool *pgxpool.Pool
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
	return &PGStore{pool: pool}, nil
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

func (s *PGStore) AppendAudit(ctx context.Context, rec *AuditRecord, chain func(prevHash string) string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, auditLockKey); err != nil {
		return err
	}
	var prev string
	err = tx.QueryRow(ctx, `SELECT hash FROM fl_audit_logs ORDER BY seq DESC LIMIT 1`).Scan(&prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	// Reserve the sequence number first: it is part of the hashed content.
	if err := tx.QueryRow(ctx, `SELECT nextval(pg_get_serial_sequence('fl_audit_logs', 'seq'))`).Scan(&rec.Seq); err != nil {
		return err
	}
	rec.PrevHash = prev
	rec.Hash = chain(prev)
	_, err = tx.Exec(ctx, `INSERT INTO fl_audit_logs (`+auditColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		rec.Seq, rec.Time, rec.UserID, rec.Username, rec.Role, rec.SourceIP, rec.Console, rec.EventType,
		rec.Target, rec.Result, rec.Reason, rec.Detail, rec.Method, rec.Path, rec.PrevHash, rec.Hash)
	if err != nil {
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
		add("lower(username) = lower($%d)", q.Username)
	}
	if q.EventType != "" {
		add("event_type LIKE $%d", strings.NewReplacer("%", `\%`, "_", `\_`).Replace(q.EventType)+"%")
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

func (s *PGStore) ListAudit(ctx context.Context, q AuditQuery) ([]AuditRecord, int, error) {
	where, args := auditWhere(q)
	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM fl_audit_logs`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}
	args = append(args, limit, q.Offset)
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`SELECT `+auditColumns+` FROM fl_audit_logs%s ORDER BY seq DESC LIMIT $%d OFFSET $%d`,
		where, len(args)-1, len(args)), args...)
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
	rows, err := s.pool.Query(ctx, `SELECT `+auditColumns+` FROM fl_audit_logs ORDER BY seq`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		r, err := scanAudit(rows)
		if err != nil {
			return err
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (s *PGStore) DeleteAuditBefore(ctx context.Context, t time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM fl_audit_logs WHERE time < $1`, t)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
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
	_, err := s.pool.Exec(ctx, `INSERT INTO fl_detection_events
		(id, type, severity, title, detail, source_ip, account_id, risk_score, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (id) DO NOTHING`,
		e.ID, e.Type, e.Severity, e.Title, e.Detail, e.SourceIP, e.AccountID, e.RiskScore, e.CreatedAt)
	return err
}

func (s *PGStore) ListRecentAlerts(ctx context.Context, since time.Time) ([]AlertEvent, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, type, severity, title, detail, source_ip, account_id, risk_score, created_at
		FROM fl_detection_events WHERE created_at > $1 ORDER BY created_at`, since)
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
