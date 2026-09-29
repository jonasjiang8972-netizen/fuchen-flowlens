package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/version"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/auth"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/compliance"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/engine"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/iam"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/middleware"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/server"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/soar"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

type config struct {
	port           int
	debug          bool
	demo           bool
	agentToken     string
	dbDSN          string
	tlsCert        string
	tlsKey         string
	tlsClientCA    string
	secureCookies  bool
	trustedProxies []string
	corsOrigins    []string
}

func main() {
	var cfg config
	var trustedProxies, corsOrigins string
	flag.IntVar(&cfg.port, "port", 8080, "http server port")
	flag.BoolVar(&cfg.debug, "debug", false, "enable debug mode")
	flag.BoolVar(&cfg.demo, "demo", false, "demo mode: disable login, use seed data only")
	flag.StringVar(&cfg.agentToken, "agent-token", os.Getenv("FLOWLENS_AGENT_TOKEN"), "shared token agents use for register/heartbeat/ingest (env FLOWLENS_AGENT_TOKEN)")
	flag.StringVar(&cfg.dbDSN, "db", os.Getenv("FLOWLENS_DB_DSN"), "PostgreSQL DSN (env FLOWLENS_DB_DSN); empty uses in-memory storage")
	flag.StringVar(&cfg.tlsCert, "tls-cert", os.Getenv("FLOWLENS_TLS_CERT"), "TLS certificate file (env FLOWLENS_TLS_CERT)")
	flag.StringVar(&cfg.tlsKey, "tls-key", os.Getenv("FLOWLENS_TLS_KEY"), "TLS private key file (env FLOWLENS_TLS_KEY)")
	flag.StringVar(&cfg.tlsClientCA, "tls-client-ca", os.Getenv("FLOWLENS_TLS_CLIENT_CA"), "CA bundle for agent client certificates; when set agents must present one (env FLOWLENS_TLS_CLIENT_CA)")
	flag.StringVar(&trustedProxies, "trusted-proxies", os.Getenv("FLOWLENS_TRUSTED_PROXIES"), "comma-separated proxy IPs/CIDRs whose X-Forwarded-For is trusted (env FLOWLENS_TRUSTED_PROXIES)")
	flag.StringVar(&corsOrigins, "cors-origins", os.Getenv("FLOWLENS_CORS_ORIGINS"), "comma-separated origins allowed cross-origin (env FLOWLENS_CORS_ORIGINS)")
	flag.Parse()
	cfg.trustedProxies = splitList(trustedProxies)
	cfg.corsOrigins = parseOrigins(corsOrigins)
	cfg.secureCookies = cfg.tlsCert != "" || os.Getenv("FLOWLENS_COOKIE_SECURE") == "true"

	if err := logger.Init(cfg.debug); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()
	log := logger.L()
	if cfg.debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var store storage.Store
	if cfg.dbDSN != "" {
		pg, err := storage.NewPGStore(ctx, cfg.dbDSN)
		if err != nil {
			log.Fatalf("Failed to open database: %v", err)
		}
		store = pg
		log.Info("Storage: PostgreSQL")
	} else {
		store = storage.NewMemStore()
		log.Warn("FLOWLENS_DB_DSN not set — using in-memory storage; accounts and the audit trail are lost on restart. Do not use in production.")
	}
	defer store.Close()

	var srv *server.PlatformServer
	if cfg.dbDSN != "" {
		seed := os.Getenv("FLOWLENS_SEED_DEMO") == "true"
		var err error
		if srv, err = server.NewPlatformServerFrom(ctx, store, seed); err != nil {
			log.Fatalf("Failed to load business data: %v", err)
		}
		if seed {
			log.Warn("FLOWLENS_SEED_DEMO=true — sample assets, alerts and collectors were added to an empty database")
		}
	} else {
		srv = server.NewPlatformServer(store)
	}
	srv.DemoMode = cfg.demo
	if cfg.demo || os.Getenv("FLOWLENS_SEED_DEMO") == "true" {
		srv.SeedDemoGraph()
		srv.SeedDemoTickets()
	}
	srv.SecureCookies = cfg.secureCookies
	srv.SetRedactionKey(cfg.agentToken)

	if !cfg.demo {
		res, err := srv.IAM().Bootstrap(ctx, os.Getenv("FLOWLENS_ADMIN_PASSWORD"))
		if err != nil {
			log.Fatalf("Failed to create initial accounts: %v", err)
		}
		if res != nil {
			log.Warnf("Created initial accounts %v; each must change its password at first login", res.Usernames)
			if res.GeneratedPassword != "" {
				// Printed once so the operator can sign in; it is never stored in plain text.
				log.Warnf("Initial password (FLOWLENS_ADMIN_PASSWORD not set): %s", res.GeneratedPassword)
			}
		}
	}

	policy, adapters, err := soar.FromEnv(os.Getenv)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if cfg.demo {
		// Demo mode has no login: anyone could reach the gateways, even just
		// to probe them with "test connection". Use only the simulator.
		policy.DryRun = true
		adapters = []soar.Adapter{soar.Simulator{}}
	}
	if err := configureBOLAML(srv, os.Getenv); err != nil {
		log.Fatalf("%v", err)
	}
	soarMgr := soar.NewManager(policy, adapters, store, srv.Audit())
	if err := soarMgr.Load(ctx); err != nil {
		log.Fatalf("Failed to load blocks: %v", err)
	}
	srv.SetSOAR(soarMgr)
	go soarMgr.Run(ctx)
	switch {
	case cfg.demo:
		log.Warn("SOAR: demo mode — blocks are simulated, nothing is enforced")
	case len(adapters) == 0:
		log.Info("SOAR: no connectors configured — alert blocking is unavailable (see docs/SOAR.md)")
	default:
		names := make([]string, 0, len(adapters))
		for _, a := range adapters {
			names = append(names, a.Name())
		}
		log.Infof("SOAR: connectors %v, dry_run=%v", names, policy.DryRun)
	}

	srv.SetDeployment(compliance.Deployment{
		DBPersistent: cfg.dbDSN != "", DBSSLMode: dsnSSLMode(cfg.dbDSN),
		TLS: cfg.tlsCert != "", SecureCookies: cfg.secureCookies, ClientCertRequired: cfg.tlsClientCA != "",
		AgentTokenSet: cfg.agentToken != "",
	})

	srv.StartEngines(ctx)
	srv.StartMaintenance(ctx)

	log.Infof("Starting %s Platform v%s on port %d", version.Name, version.Version, cfg.port)
	if cfg.demo {
		log.Warn("Running in DEMO mode — login disabled")
	} else if cfg.agentToken == "" {
		log.Warn("FLOWLENS_AGENT_TOKEN not set — agent register/heartbeat/ingest requests will be rejected")
	}
	if cfg.tlsCert == "" {
		log.Warn("TLS not configured — serve the platform behind an HTTPS proxy, or set FLOWLENS_TLS_CERT/FLOWLENS_TLS_KEY")
	}

	router := setupRouter(srv, cfg)
	httpSrv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.port),
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if cfg.tlsCert != "" {
		tlsCfg, err := serverTLSConfig(cfg.tlsClientCA)
		if err != nil {
			log.Fatalf("TLS config: %v", err)
		}
		httpSrv.TLSConfig = tlsCfg
	}

	go func() {
		var err error
		if cfg.tlsCert != "" {
			err = httpSrv.ListenAndServeTLS(cfg.tlsCert, cfg.tlsKey)
		} else {
			err = httpSrv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Infof("Received signal %v, shutting down...", sig)

	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Errorf("Server forced shutdown: %v", err)
	}
	// Save traffic-driven updates made since the last periodic flush.
	if err := srv.FlushAll(shutdownCtx); err != nil {
		log.Errorf("Final flush of business data failed: %v", err)
	}
	if err := srv.Close(); err != nil {
		log.Errorf("Closing streaming sinks: %v", err)
	}
	log.Info("Server stopped gracefully")
}

// serverTLSConfig requires TLS 1.2+. With a client CA, clients may present a
// certificate; agent routes then require a verified one (see agent group).
func serverTLSConfig(clientCA string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if clientCA != "" {
		pem, err := os.ReadFile(clientCA)
		if err != nil {
			return nil, fmt.Errorf("read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates in %s", clientCA)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return cfg, nil
}

func setupRouter(srv *server.PlatformServer, cfg config) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	// Trust X-Forwarded-For only from configured proxies, so audit records
	// and login rate limits see the real client address.
	_ = r.SetTrustedProxies(cfg.trustedProxies)
	r.Use(corsMiddleware(cfg.corsOrigins))
	r.Use(middleware.MaxBody(8 << 20))

	auditSvc := srv.Audit()
	session := auth.RequireSession(srv.IAM(), cfg.demo)
	perm := func(console string, p iam.Permission) gin.HandlerFunc {
		return auth.RequirePermission(auditSvc, console, p)
	}

	public := r.Group("/api/v1")
	public.GET("/health", srv.HealthHandler)
	public.POST("/auth/login", srv.LoginHandler)

	// Own account: available to every signed-in operator, including one
	// that still has to change its password.
	account := r.Group("/api/v1/auth", session, middleware.Audit(auditSvc, "auth"))
	account.GET("/me", srv.MeHandler)
	account.POST("/logout", srv.LogoutHandler)
	account.POST("/password", srv.ChangePasswordHandler)

	// Collector endpoints authenticate with the agent token (and a verified
	// client certificate when a client CA is configured).
	agentRG := r.Group("/api/v1")
	if !cfg.demo {
		agentRG.Use(auth.AgentTokenMiddleware(cfg.agentToken))
		if cfg.tlsClientCA != "" {
			agentRG.Use(auth.RequireClientCert())
		}
	}
	agentRG.POST("/agents/register", srv.RegisterAgentHandler)
	agentRG.POST("/agents/:id/heartbeat", srv.HeartbeatHandler)
	agentRG.POST("/ingest/event", srv.IngestEventHandler)
	agentRG.POST("/ingest/batch", srv.IngestBatchHandler)

	// ── API security platform: API security operations and policy only ──
	sec := r.Group("/api/v1", session, middleware.Audit(auditSvc, "security"))
	read := perm("security", iam.PermSecurityRead)
	sec.GET("/assets", read, srv.ListAssetsHandler)
	sec.GET("/assets/:id", read, srv.GetAssetHandler)
	sec.POST("/assets/:id/claim", perm("security", iam.PermAssetManage), srv.ClaimAssetHandler)
	sec.GET("/alerts", read, srv.ListAlertsHandler)
	sec.GET("/alerts/:id", read, srv.GetAlertHandler)
	sec.POST("/alerts/:id/:action", perm("security", iam.PermAlertHandle), srv.AlertActionHandler)
	sec.POST("/detect/access", perm("security", iam.PermRuleManage), srv.RecordAccessHandler)
	sec.GET("/detect/events", read, srv.ListDetectionEventsHandler)
	sec.GET("/detect/ml", read, srv.DetectionMLHandler)
	sec.GET("/rules", read, srv.ListRulesHandler)
	sec.GET("/rules/categories", read, srv.ListRuleCategoriesHandler)
	sec.GET("/rules/:id", read, srv.GetRuleHandler)
	sec.PUT("/rules/:id", perm("security", iam.PermRuleManage), srv.UpdateRuleHandler)
	sec.POST("/rules/:id/hit", perm("security", iam.PermRuleManage), srv.HitRuleHandler)
	sec.GET("/tickets", read, srv.ListTicketsHandler)
	sec.GET("/tickets/summary", read, srv.TicketSummaryHandler)
	sec.GET("/tickets/:id", read, srv.GetTicketHandler)
	sec.POST("/tickets", perm("security", iam.PermAlertHandle), srv.CreateTicketHandler)
	sec.POST("/tickets/:id/transition", perm("security", iam.PermAlertHandle), srv.TransitionTicketHandler)
	sec.POST("/tickets/:id/assign", perm("security", iam.PermAlertHandle), srv.AssignTicketHandler)
	sec.POST("/tickets/:id/comment", perm("security", iam.PermAlertHandle), srv.CommentTicketHandler)
	report := perm("security", iam.PermReportRead)
	sec.GET("/reports/compliance/templates", report, srv.ComplianceTemplatesHandler)
	sec.GET("/reports/compliance", report, srv.ComplianceReportHandler)
	sec.GET("/reports/compliance/export", report, srv.ComplianceExportHandler)
	sec.GET("/graph/flow", read, srv.FlowGraphHandler)
	sec.GET("/graph/attack", read, srv.AttackGraphHandler)
	// Enforcement (SOAR): blocks are guarded by policy and always audited.
	sec.GET("/soar/connectors", read, srv.SOARConnectorsHandler)
	sec.POST("/soar/connectors/:name/test", perm("security", iam.PermRuleManage), srv.SOARTestHandler)
	sec.GET("/soar/blocks", read, srv.SOARBlocksHandler)
	sec.POST("/soar/block", perm("security", iam.PermAlertHandle), srv.SOARBlockHandler)
	sec.POST("/soar/unblock", perm("security", iam.PermAlertHandle), srv.SOARUnblockHandler)
	// Collection coverage as seen by security teams (aggregate only).
	sec.GET("/coverage/agents", read, srv.AgentHealthSummaryHandler)

	// ── Management console (系统管理后台): platform administration ──
	adm := r.Group("/api/v1/admin", session, middleware.Audit(auditSvc, "admin"))
	users := perm("admin", iam.PermUserManage)
	adm.GET("/users", users, srv.ListUsersHandler)
	adm.POST("/users", users, srv.CreateUserHandler)
	adm.PUT("/users/:id", users, srv.UpdateUserHandler)
	adm.POST("/users/:id/:action", users, srv.UserActionHandler)
	adm.DELETE("/users/:id", users, srv.DeleteUserHandler)
	adm.GET("/roles", users, srv.ListRolesHandler)

	policy := perm("admin", iam.PermPolicyManage)
	adm.GET("/security-policy", policy, srv.GetPolicyHandler)
	adm.PUT("/security-policy", policy, srv.UpdatePolicyHandler)

	agents := perm("admin", iam.PermAgentManage)
	adm.GET("/agents", agents, srv.ListAgentsHandler)
	adm.GET("/agents/health/summary", agents, srv.AgentHealthSummaryHandler)
	adm.GET("/agents/:id", agents, srv.GetAgentHandler)
	adm.GET("/ingest/metrics", agents, srv.IngestMetricsHandler)

	adm.GET("/system/info", perm("admin", iam.PermSystemManage), srv.SystemInfoHandler)

	auditRead := perm("admin", iam.PermAuditRead)
	adm.GET("/audit-logs", auditRead, srv.ListAuditHandler)
	adm.GET("/audit-logs/verify", auditRead, srv.VerifyAuditHandler)
	adm.POST("/audit-logs/verify-full", auditRead, srv.StartFullVerifyHandler)
	adm.GET("/audit-logs/verify-full", auditRead, srv.FullVerifyStatusHandler)
	adm.GET("/audit-logs/export", auditRead, srv.ExportAuditHandler)

	return r
}

// corsMiddleware allows cross-origin requests only from the configured
// origins. The web console is served same-origin (nginx / vite proxy), so the
// default empty list allows no cross-origin access.
func corsMiddleware(allowedOrigins []string) gin.HandlerFunc {
	allowed := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[o] = true
	}
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" && allowed[origin] {
			h := c.Writer.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Add("Vary", "Origin")
			h.Set("Access-Control-Allow-Credentials", "true")
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, "+auth.CSRFHeader)
			if c.Request.Method == http.MethodOptions {
				c.AbortWithStatus(http.StatusNoContent)
				return
			}
		}
		c.Next()
	}
}

// parseOrigins splits a comma-separated origin list, dropping blanks.
func parseOrigins(v string) []string {
	var out []string
	for _, o := range splitList(v) {
		out = append(out, strings.TrimRight(o, "/"))
	}
	return out
}

func splitList(v string) []string {
	var out []string
	for _, o := range strings.Split(v, ",") {
		if o = strings.TrimSpace(o); o != "" {
			out = append(out, o)
		}
	}
	return out
}

// configureBOLAML applies FLOWLENS_BOLA_ML ("off" or "false" disables the
// anomaly model) and FLOWLENS_BOLA_ML_THRESHOLD (score in (0.5, 1)).
func configureBOLAML(srv *server.PlatformServer, getenv func(string) string) error {
	enabled := true
	switch strings.ToLower(strings.TrimSpace(getenv("FLOWLENS_BOLA_ML"))) {
	case "off", "false", "0", "no":
		enabled = false
	}
	threshold := engine.DefaultMLThreshold
	if v := strings.TrimSpace(getenv("FLOWLENS_BOLA_ML_THRESHOLD")); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return fmt.Errorf("FLOWLENS_BOLA_ML_THRESHOLD: %q 不是有效数字", v)
		}
		threshold = f
	}
	if err := srv.ConfigureBOLAML(enabled, threshold); err != nil {
		return fmt.Errorf("FLOWLENS_BOLA_ML_THRESHOLD: %w", err)
	}
	return nil
}

// dsnSSLMode returns the sslmode of a PostgreSQL connection string, or "" when
// it cannot be told (a keyword/value DSN without one, or none configured).
// Both URL and "key=value" forms are understood.
func dsnSSLMode(dsn string) string {
	if dsn == "" {
		return ""
	}
	if u, err := url.Parse(dsn); err == nil && (u.Scheme == "postgres" || u.Scheme == "postgresql") {
		return u.Query().Get("sslmode")
	}
	for _, f := range strings.Fields(dsn) {
		if v, ok := strings.CutPrefix(f, "sslmode="); ok {
			return strings.Trim(v, "'")
		}
	}
	return ""
}
