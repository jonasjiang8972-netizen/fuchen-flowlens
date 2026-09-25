// Package audit records the platform's own audit trail: an append-only log
// whose records are chained with SM3 so tampering can be detected.
package audit

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
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
	store    storage.AuditStore
	settings SettingsStore
	now      func() time.Time

	fullMu sync.Mutex
	full   FullVerifyStatus
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
	OK         bool      `json:"ok"`
	Mode       string    `json:"mode"` // incremental | full
	Checked    int64     `json:"checked"`
	FirstSeq   int64     `json:"first_seq"`
	LastSeq    int64     `json:"last_seq"`
	BrokenAt   int64     `json:"broken_at,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	FinishedAt time.Time `json:"finished_at"`
}

// Checkpoint is the last record a verification found intact. Incremental
// checks start from it, so their cost depends on the records added since,
// not on the size of the trail.
type Checkpoint struct {
	Seq        int64     `json:"seq"`
	Hash       string    `json:"hash"`
	VerifiedAt time.Time `json:"verified_at"`
}

// SettingsStore keeps checkpoints and full-verification results.
type SettingsStore interface {
	GetSetting(ctx context.Context, key string) ([]byte, error)
	PutSetting(ctx context.Context, key string, value []byte) error
}

const (
	checkpointKey = "audit_verify_checkpoint"
	lastFullKey   = "audit_verify_last_full"
)

var errStop = errors.New("stop")

// SetSettings enables checkpoints and persisted full-verification results.
func (s *Service) SetSettings(st SettingsStore) { s.settings = st }

// verifyFrom checks records with seq >= from. When anchor is set, the first
// record must be exactly the anchored one (same seq and hash); otherwise the
// first record's PrevHash is trusted, as after a retention purge.
func (s *Service) verifyFrom(ctx context.Context, from int64, anchor *Checkpoint, progress func(int64)) (VerifyResult, error) {
	res := VerifyResult{OK: true}
	var prev *storage.AuditRecord
	broken := func(seq int64, reason string) error {
		res.OK, res.BrokenAt, res.Reason = false, seq, reason
		return errStop
	}
	err := s.store.WalkAuditFrom(ctx, from, func(r storage.AuditRecord) error {
		if res.Checked == 0 {
			res.FirstSeq = r.Seq
			if anchor != nil && (r.Seq != anchor.Seq || r.Hash != anchor.Hash) {
				return broken(r.Seq, fmt.Sprintf("检查点记录 %d 已被删除或修改", anchor.Seq))
			}
		}
		res.Checked++
		res.LastSeq = r.Seq
		if progress != nil && res.Checked%100000 == 0 {
			progress(res.Checked)
		}
		switch {
		case prev != nil && r.PrevHash != prev.Hash:
			return broken(r.Seq, fmt.Sprintf("记录 %d 与上一条记录 %d 的哈希链接不一致（中间记录可能被删除或修改）", r.Seq, prev.Seq))
		case prev != nil && r.Seq <= prev.Seq:
			return broken(r.Seq, fmt.Sprintf("记录 %d 的序号不递增", r.Seq))
		case Hash(r) != r.Hash:
			return broken(r.Seq, fmt.Sprintf("记录 %d 的内容与哈希不符（记录可能被修改）", r.Seq))
		}
		rc := r
		prev = &rc
		return nil
	})
	if errors.Is(err, errStop) {
		err = nil
	}
	if err == nil && anchor != nil && res.Checked == 0 {
		res.OK, res.BrokenAt, res.Reason = false, anchor.Seq, fmt.Sprintf("检查点记录 %d 已被删除", anchor.Seq)
	}
	res.FinishedAt = s.now()
	return res, err
}

// Verify walks the whole trail. The oldest remaining record's PrevHash is
// trusted as the anchor, since retention purges remove the head of the
// chain. Its cost grows with the trail; use VerifyIncremental interactively.
func (s *Service) Verify(ctx context.Context) (VerifyResult, error) {
	res, err := s.verifyFrom(ctx, 0, nil, nil)
	res.Mode = "full"
	if err == nil && res.OK {
		s.saveCheckpoint(ctx, res)
	}
	return res, err
}

// VerifyIncremental checks the records appended since the last checkpoint,
// re-validating the checkpoint record itself. Without a checkpoint, or if
// the checkpoint was purged by retention, it verifies the whole trail.
func (s *Service) VerifyIncremental(ctx context.Context) (VerifyResult, error) {
	cp := s.loadCheckpoint(ctx)
	if cp == nil {
		return s.Verify(ctx)
	}
	res, err := s.verifyFrom(ctx, cp.Seq, cp, nil)
	if err != nil {
		return res, err
	}
	if !res.OK && res.FirstSeq > cp.Seq && s.purgedBefore(ctx, res.FirstSeq) {
		// The checkpoint itself fell to retention: start over from the
		// oldest remaining record.
		return s.Verify(ctx)
	}
	res.Mode = "incremental"
	if res.OK {
		s.saveCheckpoint(ctx, res)
	}
	return res, nil
}

// purgedBefore reports whether no record older than seq remains, i.e. the
// gap before seq is explained by a retention purge.
func (s *Service) purgedBefore(ctx context.Context, seq int64) bool {
	older := false
	_ = s.store.WalkAuditFrom(ctx, 0, func(r storage.AuditRecord) error {
		older = r.Seq < seq
		return errStop
	})
	return !older
}

func (s *Service) loadCheckpoint(ctx context.Context) *Checkpoint {
	if s.settings == nil {
		return nil
	}
	raw, err := s.settings.GetSetting(ctx, checkpointKey)
	if err != nil {
		return nil
	}
	var cp Checkpoint
	if json.Unmarshal(raw, &cp) != nil || cp.Seq == 0 {
		return nil
	}
	return &cp
}

func (s *Service) saveCheckpoint(ctx context.Context, res VerifyResult) {
	if s.settings == nil || res.Checked == 0 {
		return
	}
	var last storage.AuditRecord
	_ = s.store.WalkAuditFrom(ctx, res.LastSeq, func(r storage.AuditRecord) error {
		last = r
		return errStop
	})
	if last.Seq != res.LastSeq {
		return
	}
	raw, _ := json.Marshal(Checkpoint{Seq: last.Seq, Hash: last.Hash, VerifiedAt: s.now()})
	_ = s.settings.PutSetting(ctx, checkpointKey, raw)
}

// FullVerifyStatus describes the background full verification.
type FullVerifyStatus struct {
	Running   bool          `json:"running"`
	StartedAt *time.Time    `json:"started_at,omitempty"`
	Checked   int64         `json:"checked"`
	Last      *VerifyResult `json:"last,omitempty"`
}

// StartFullVerify runs a full verification in the background unless one is
// already running; it reports whether a new run started.
func (s *Service) StartFullVerify() bool {
	s.fullMu.Lock()
	if s.full.Running {
		s.fullMu.Unlock()
		return false
	}
	now := s.now()
	s.full.Running, s.full.StartedAt, s.full.Checked = true, &now, 0
	s.fullMu.Unlock()

	go func() {
		ctx := context.Background()
		res, err := s.verifyFrom(ctx, 0, nil, func(n int64) {
			s.fullMu.Lock()
			s.full.Checked = n
			s.fullMu.Unlock()
		})
		res.Mode = "full"
		if err != nil {
			res.OK, res.Reason = false, "校验中断："+err.Error()
			logger.L().Errorf("full audit verification failed: %v", err)
		} else if res.OK {
			s.saveCheckpoint(ctx, res)
		}
		if s.settings != nil {
			raw, _ := json.Marshal(res)
			_ = s.settings.PutSetting(ctx, lastFullKey, raw)
		}
		_ = s.Record(ctx, storage.AuditRecord{Username: "system", Console: "system", EventType: "audit.verify_full",
			Result: map[bool]string{true: ResultSuccess, false: ResultFailure}[res.OK], Reason: res.Reason,
			Detail: fmt.Sprintf("全量校验 %d 条记录（序号 %d–%d）", res.Checked, res.FirstSeq, res.LastSeq)})
		s.fullMu.Lock()
		s.full.Running, s.full.Checked, s.full.Last = false, res.Checked, &res
		s.fullMu.Unlock()
	}()
	return true
}

func (s *Service) FullVerifyStatus(ctx context.Context) FullVerifyStatus {
	s.fullMu.Lock()
	st := s.full
	s.fullMu.Unlock()
	if st.Last == nil && s.settings != nil {
		if raw, err := s.settings.GetSetting(ctx, lastFullKey); err == nil {
			var last VerifyResult
			if json.Unmarshal(raw, &last) == nil {
				st.Last = &last
			}
		}
	}
	return st
}

// Purge deletes records older than retention, which may not be shorter than
// MinRetention.
func (s *Service) Purge(ctx context.Context, retention time.Duration) (int64, error) {
	if retention < MinRetention {
		retention = MinRetention
	}
	return s.store.DeleteAuditBefore(ctx, s.now().Add(-retention))
}
