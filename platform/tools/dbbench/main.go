// Command dbbench generates realistic audit and detection data in a scratch
// PostgreSQL database and times the queries the management console issues,
// through the platform's own storage code.
//
//	go run ./platform/tools/dbbench -dsn postgres://... -generate 10000000
//	go run ./platform/tools/dbbench -dsn postgres://... -bench
//
// Never point it at a production database: -generate appends synthetic rows.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/audit"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

func main() {
	dsn := flag.String("dsn", os.Getenv("FLOWLENS_BENCH_DSN"), "scratch PostgreSQL DSN")
	gen := flag.Int("generate", 0, "audit rows to generate (detection events: same count / 4)")
	days := flag.Int("days", 180, "time span of generated data, ending now")
	bench := flag.Bool("bench", false, "run the query benchmark")
	runs := flag.Int("runs", 5, "timed runs per query (after one warm-up)")
	verify := flag.Bool("verify", false, "also time a full audit chain walk")
	purge := flag.Bool("purge", false, "also time purging the oldest month (destructive)")
	flag.Parse()
	if *dsn == "" {
		fmt.Fprintln(os.Stderr, "missing -dsn")
		os.Exit(2)
	}
	ctx := context.Background()
	st, err := storage.NewPGStore(ctx, *dsn)
	if err != nil {
		fail(err)
	}
	pool, err := pgxpool.New(ctx, *dsn)
	if err != nil {
		fail(err)
	}
	defer pool.Close()

	if *gen > 0 {
		if err := st.EnsurePartitionRange(ctx, time.Now().AddDate(0, 0, -*days-1), time.Now()); err != nil {
			fail(err)
		}
		generate(ctx, pool, *gen, *days)
	}
	if *bench {
		runBench(ctx, st, pool, *runs, *days, *verify, *purge)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

// generate inserts synthetic rows in 1M-row batches: skewed users (a few
// heavy, a long tail, one rare user), realistic event mix, ~5% failures.
func generate(ctx context.Context, pool *pgxpool.Pool, n, days int) {
	var start int64
	_ = pool.QueryRow(ctx, `SELECT coalesce(max(seq), 0) FROM fl_audit_logs`).Scan(&start)
	span := float64(days) * 86400
	const batch = 1_000_000
	t0 := time.Now()
	for done := 0; done < n; done += batch {
		m := batch
		if n-done < m {
			m = n - done
		}
		lo, hi := start+int64(done)+1, start+int64(done+m)
		_, err := pool.Exec(ctx, fmt.Sprintf(`
INSERT INTO fl_audit_logs (seq, time, user_id, username, role, source_ip, console, event_type, target, result, reason, detail, method, path, prev_hash, hash)
SELECT i,
  now() - make_interval(secs => %[3]f) + make_interval(secs => %[3]f * (i - %[5]d) / %[4]d),
  'usr-' || u, CASE WHEN i %% 20000 = 7 THEN 'rare.user' ELSE 'user' || u END,
  (ARRAY['sec_admin','analyst','viewer','sys_admin'])[1 + u %% 4],
  '10.' || (u %% 250) || '.' || (i %% 250) || '.' || (i %% 7),
  (ARRAY['auth','security','security','admin','agent'])[1 + i %% 5],
  CASE WHEN r < 0.50 THEN 'auth.login' WHEN r < 0.65 THEN 'alert.action' WHEN r < 0.75 THEN 'asset.claim'
       WHEN r < 0.80 THEN 'rule.update' WHEN r < 0.88 THEN 'audit.query' WHEN r < 0.95 THEN 'auth.logout'
       WHEN r < 0.96 THEN 'access.denied' WHEN r < 0.965 THEN 'user.create' WHEN r < 0.968 THEN 'user.lock'
       WHEN r < 0.969 THEN 'policy.update' ELSE 'agent.register' END,
  'id=obj-' || (i %% 100000),
  CASE WHEN r < 0.50 AND (i %% 10) = 0 THEN 'failure' WHEN r >= 0.95 AND r < 0.96 THEN 'failure' ELSE 'success' END,
  '', 'detail ' || (i %% 1000), 'POST', '/api/v1/alerts/alt-' || (i %% 5000) || '/block',
  md5((i-1)::text) || md5((i+7)::text), md5(i::text) || md5((i+13)::text)
FROM (SELECT i, (floor(power(random(), 3) * 2000))::int AS u, random() AS r
      FROM generate_series(%[1]d::bigint, %[2]d::bigint) AS i) g`, lo, hi, span, n, start))
		if err != nil {
			fail(err)
		}
		fmt.Printf("audit rows: %d / %d (%.0fs)\n", done+m, n, time.Since(t0).Seconds())
	}
	// Point the chain head at the newest generated record.
	_, _ = pool.Exec(ctx, `INSERT INTO fl_audit_head (id, seq, hash, time)
		SELECT 1, seq, hash, time FROM fl_audit_logs ORDER BY seq DESC LIMIT 1
		ON CONFLICT (id) DO UPDATE SET seq = EXCLUDED.seq, hash = EXCLUDED.hash, time = greatest(fl_audit_head.time, EXCLUDED.time)`)

	d := n / 4
	_, err := pool.Exec(ctx, fmt.Sprintf(`
INSERT INTO fl_detection_events (id, type, severity, title, detail, source_ip, account_id, risk_score, created_at)
SELECT 'det-' || i || '-' || md5(random()::text), (ARRAY['BOLA','BFLA','CREDENTIAL_STUFFING'])[1 + i %% 3], 'high',
  'detection ' || i, 'reason', '203.0.' || (i %% 250) || '.' || (i %% 7), 'acct-' || (i %% 50000), 70 + i %% 30,
  now() - make_interval(secs => %[2]f) + make_interval(secs => %[2]f * i / %[1]d)
FROM generate_series(1, %[1]d) AS i`, d, span))
	if err != nil {
		fail(err)
	}
	fmt.Printf("detection events: %d\n", d)
	_, _ = pool.Exec(ctx, `ANALYZE fl_audit_logs; ANALYZE fl_detection_events`)
	fmt.Printf("generated in %.0fs\n", time.Since(t0).Seconds())
}

type result struct {
	name       string
	cold, p50  time.Duration
	max        time.Duration
	rows, info string
}

func timeIt(runs int, fn func() (string, string, error)) result {
	var r result
	var ds []time.Duration
	for i := 0; i <= runs; i++ {
		t := time.Now()
		rows, info, err := fn()
		d := time.Since(t)
		if err != nil {
			r.info = "ERROR " + err.Error()
			return r
		}
		r.rows, r.info = rows, info
		if i == 0 {
			r.cold = d
			continue
		}
		ds = append(ds, d)
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	r.p50, r.max = ds[len(ds)/2], ds[len(ds)-1]
	return r
}

func runBench(ctx context.Context, st *storage.PGStore, pool *pgxpool.Pool, runs, days int, verify, purge bool) {
	var rows, bytes int64
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM fl_audit_logs`).Scan(&rows)
	_ = pool.QueryRow(ctx, `SELECT coalesce(sum(pg_total_relation_size(c.oid)), 0) FROM pg_class c
		WHERE c.relname LIKE 'fl_audit_logs%' AND c.relkind IN ('r','p')`).Scan(&bytes)
	fmt.Printf("\naudit rows: %d, audit table + indexes: %.1f GB\n\n", rows, float64(bytes)/1e9)

	now := time.Now()
	mid := now.Add(-time.Duration(days/2) * 24 * time.Hour)
	list := func(q storage.AuditQuery) func() (string, string, error) {
		return func() (string, string, error) {
			recs, total, err := st.ListAudit(ctx, q)
			return fmt.Sprintf("%d", len(recs)), fmt.Sprintf("total=%d", total), err
		}
	}
	cases := []struct {
		name string
		fn   func() (string, string, error)
	}{
		{"首页（无筛选，最新 50 条）", list(storage.AuditQuery{Limit: 50})},
		{"按用户：高频用户 user0", list(storage.AuditQuery{Username: "user0", Limit: 50})},
		{"按用户：普通用户 user900", list(storage.AuditQuery{Username: "user900", Limit: 50})},
		{"按用户：低频用户 rare.user", list(storage.AuditQuery{Username: "rare.user", Limit: 50})},
		{"事件类别：登录与口令 + 失败", list(storage.AuditQuery{EventType: "auth.", Result: "failure", Limit: 50})},
		{"事件类别：账号管理（稀有）", list(storage.AuditQuery{EventType: "user.", Limit: 50})},
		{"事件类型：越权访问", list(storage.AuditQuery{EventType: "access.denied", Limit: 50})},
		{"组合：高频用户 + 稀有类别", list(storage.AuditQuery{Username: "user0", EventType: "policy.", Limit: 50})},
		{"组合：高频用户 + 失败", list(storage.AuditQuery{Username: "user0", Result: "failure", Limit: 50})},
		{"组合：高频用户+稀有类别+失败", list(storage.AuditQuery{Username: "user0", EventType: "policy.", Result: "failure", Limit: 50})},
		{"组合：稀有类别 + 失败(无匹配)", list(storage.AuditQuery{EventType: "user.", Result: "failure", Limit: 50})},
		{"组合：类别 + 成功", list(storage.AuditQuery{EventType: "alert.", Result: "success", Limit: 50})},
		{"时间范围：某一天", list(storage.AuditQuery{From: mid, To: mid.Add(24 * time.Hour), Limit: 50})},
		{"用户 + 7 天范围", list(storage.AuditQuery{Username: "user900", From: mid, To: mid.Add(7 * 24 * time.Hour), Limit: 50})},
		{"翻页：第 100 页", list(storage.AuditQuery{Limit: 50, Offset: 4950})},
		{"检测事件：最近 24 小时", func() (string, string, error) {
			evts, err := st.ListRecentAlerts(ctx, now.Add(-24*time.Hour), 1000)
			return fmt.Sprintf("%d", len(evts)), "", err
		}},
		{"写入一条审计记录", func() (string, string, error) {
			rec := &storage.AuditRecord{Time: time.Now(), Username: "bench", EventType: "bench.append", Result: "success"}
			err := st.AppendAudit(ctx, rec, func(prev string) string { rec.PrevHash = prev; return audit.Hash(*rec) })
			return "1", "", err
		}},
	}
	fmt.Printf("%-30s %10s %10s %10s %8s  %s\n", "查询", "首次", "中位数", "最大", "返回行", "说明")
	for _, c := range cases {
		r := timeIt(runs, c.fn)
		fmt.Printf("%-30s %10s %10s %10s %8s  %s\n", pad(c.name, 30), ms(r.cold), ms(r.p50), ms(r.max), r.rows, r.info)
	}
	if verify {
		svc := audit.New(st)
		svc.SetSettings(st)
		t := time.Now()
		res, err := svc.Verify(ctx)
		fmt.Printf("%-30s %10s  checked=%d ok=%v err=%v（合成数据的哈希不成链，发现断点即停止）\n", pad("全量校验", 30), ms(time.Since(t)), res.Checked, res.OK, err)

		// Incremental: append real chained records, checkpoint, append more.
		for i := 0; i < 1000; i++ {
			_ = svc.Record(ctx, storage.AuditRecord{Username: "bench", EventType: "bench.chain"})
		}
		var cp storage.AuditRecord
		_ = st.WalkAuditFrom(ctx, 0, func(storage.AuditRecord) error { return nil }) // warm
		recs, _, _ := st.ListAudit(ctx, storage.AuditQuery{EventType: "bench.chain", Limit: 1})
		if len(recs) == 1 {
			cp = recs[0]
			raw := fmt.Sprintf(`{"seq":%d,"hash":%q,"verified_at":%q}`, cp.Seq, cp.Hash, time.Now().Format(time.RFC3339))
			_ = st.PutSetting(ctx, "audit_verify_checkpoint", []byte(raw))
		}
		for i := 0; i < 100; i++ {
			_ = svc.Record(ctx, storage.AuditRecord{Username: "bench", EventType: "bench.chain"})
		}
		t = time.Now()
		inc, err := svc.VerifyIncremental(ctx)
		fmt.Printf("%-30s %10s  mode=%s checked=%d ok=%v err=%v\n", pad("增量校验（检查点后 101 条）", 30), ms(time.Since(t)), inc.Mode, inc.Checked, inc.OK, err)

		t = time.Now()
		n := 0
		err = st.WalkAudit(ctx, func(storage.AuditRecord) error { n++; return nil })
		fmt.Printf("%-30s %10s  walked=%d err=%v\n", pad("遍历全部记录（全量校验的读取成本）", 30), ms(time.Since(t)), n, err)
	}
	if purge {
		t := time.Now()
		deleted, err := st.DeleteAuditBefore(ctx, now.Add(-time.Duration(days-45)*24*time.Hour))
		fmt.Printf("%-30s %10s  deleted=%d err=%v\n", pad("清理最早一个月", 30), ms(time.Since(t)), deleted, err)
	}
}

func ms(d time.Duration) string {
	if d == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000)
}

// pad right-pads to a display width, counting CJK characters as two columns.
func pad(s string, width int) string {
	w := 0
	for _, r := range s {
		if r > 0x2e80 {
			w += 2
		} else {
			w++
		}
	}
	if w >= width {
		return s
	}
	return s + strings.Repeat(" ", width-w)
}
