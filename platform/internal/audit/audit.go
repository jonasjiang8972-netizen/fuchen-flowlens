// Package audit records the platform's own audit trail: an append-only log
// whose records are chained with SM3 so tampering can be detected.
package audit

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/emmansun/gmsm/sm3"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

const (
	ResultSuccess = "success"
	ResultFailure = "failure"
)

// MinRetention is the shortest audit retention allowed (网络安全法第二十一条:
// network logs are kept for no less than six months).
const MinRetention = 180 * 24 * time.Hour

type Service struct {
	store storage.AuditStore
	now   func() time.Time
}

func New(store storage.AuditStore) *Service {
	return &Service{store: store, now: time.Now}
}

// Record appends one audit entry. Seq, PrevHash and Hash are filled in; the
// time defaults to now. Callers should treat an error as serious: it means
// an auditable action was not recorded.
func (s *Service) Record(ctx context.Context, rec storage.AuditRecord) error {
	if rec.Time.IsZero() {
		rec.Time = s.now()
	}
	// PostgreSQL keeps microseconds; hash exactly what will be stored.
	rec.Time = rec.Time.UTC().Truncate(time.Microsecond)
	if rec.Result == "" {
		rec.Result = ResultSuccess
	}
	err := s.store.AppendAudit(ctx, &rec, func(prev string) string {
		rec.PrevHash = prev
		return Hash(rec)
	})
	if err != nil {
		logger.L().Errorf("AUDIT WRITE FAILED (%s by %s): %v", rec.EventType, rec.Username, err)
	}
	return err
}

// Hash computes the SM3 chain hash of a record from its content and
// PrevHash. Seq is included so records cannot be reordered.
func Hash(r storage.AuditRecord) string {
	fields := []string{
		strconv.FormatInt(r.Seq, 10),
		r.Time.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano),
		r.UserID, r.Username, r.Role, r.SourceIP, r.Console, r.EventType,
		r.Target, r.Result, r.Reason, r.Detail, r.Method, r.Path,
		r.PrevHash,
	}
	sum := sm3.Sum([]byte(strings.Join(fields, "\x1f")))
	return hex.EncodeToString(sum[:])
}

func (s *Service) List(ctx context.Context, q storage.AuditQuery) ([]storage.AuditRecord, int, error) {
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 100
	}
	return s.store.ListAudit(ctx, q)
}

// VerifyResult reports the outcome of a hash chain check.
type VerifyResult struct {
	OK       bool   `json:"ok"`
	Checked  int    `json:"checked"`
	FirstSeq int64  `json:"first_seq"`
	LastSeq  int64  `json:"last_seq"`
	BrokenAt int64  `json:"broken_at,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// Verify walks the whole trail and checks every record's hash and link.
// The oldest remaining record's PrevHash is trusted as the anchor, since
// retention purges remove the head of the chain.
func (s *Service) Verify(ctx context.Context) (VerifyResult, error) {
	res := VerifyResult{OK: true}
	var prev *storage.AuditRecord
	err := s.store.WalkAudit(ctx, func(r storage.AuditRecord) error {
		if res.Checked == 0 {
			res.FirstSeq = r.Seq
		}
		res.Checked++
		res.LastSeq = r.Seq
		if !res.OK {
			return nil
		}
		switch {
		case prev != nil && r.PrevHash != prev.Hash:
			res.OK, res.BrokenAt = false, r.Seq
			res.Reason = fmt.Sprintf("记录 %d 与上一条记录 %d 的哈希链接不一致（中间记录可能被删除或修改）", r.Seq, prev.Seq)
		case prev != nil && r.Seq <= prev.Seq:
			res.OK, res.BrokenAt = false, r.Seq
			res.Reason = fmt.Sprintf("记录 %d 的序号不递增", r.Seq)
		case Hash(r) != r.Hash:
			res.OK, res.BrokenAt = false, r.Seq
			res.Reason = fmt.Sprintf("记录 %d 的内容与哈希不符（记录可能被修改）", r.Seq)
		}
		rc := r
		prev = &rc
		return nil
	})
	return res, err
}

// Purge deletes records older than retention, which may not be shorter than
// MinRetention.
func (s *Service) Purge(ctx context.Context, retention time.Duration) (int64, error) {
	if retention < MinRetention {
		retention = MinRetention
	}
	return s.store.DeleteAuditBefore(ctx, s.now().Add(-retention))
}
