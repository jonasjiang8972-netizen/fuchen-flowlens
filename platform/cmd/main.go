package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/version"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/auth"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/middleware"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/server"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

func main() {
	var (
		port       int
		debug      bool
		demo       bool
		agentToken string
	)
	flag.IntVar(&port, "port", 8080, "http server port")
	flag.BoolVar(&debug, "debug", false, "enable debug mode")
	flag.BoolVar(&demo, "demo", false, "demo mode: disable auth, use seed data only")
	flag.StringVar(&agentToken, "agent-token", os.Getenv("FLOWLENS_AGENT_TOKEN"), "shared token agents use for register/heartbeat/ingest (env FLOWLENS_AGENT_TOKEN)")
	flag.Parse()

	if err := logger.Init(debug); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	log := logger.L()
	if debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	if secret := os.Getenv("FLOWLENS_JWT_SECRET"); secret != "" {
		if err := auth.SetJWTSecret(secret); err != nil {
			log.Fatalf("Invalid FLOWLENS_JWT_SECRET: %v", err)
		}
	} else {
		log.Warn("FLOWLENS_JWT_SECRET not set — using a random key; login sessions will not survive a restart")
	}

	store := storage.NewStore("mem")
	srv := server.NewPlatformServer(store)
	srv.DemoMode = demo

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.StartEngines(ctx)

	log.Infof("Starting %s Platform v%s on port %d", version.Name, version.Version, port)
	if demo {
		log.Warn("Running in DEMO mode — authentication disabled")
	} else {
		if os.Getenv("FLOWLENS_ADMIN_PASSWORD") == "" {
			log.Warnf("FLOWLENS_ADMIN_PASSWORD not set — seeded users use the default password %q; set it before exposing the platform", storage.DefaultAdminPassword)
		}
		if agentToken == "" {
			log.Warn("FLOWLENS_AGENT_TOKEN not set — agent register/heartbeat/ingest requests will be rejected")
		}
	}

	router := setupRouter(srv, store, demo, agentToken)

	httpSrv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: router,
	}

	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
	log.Info("Server stopped gracefully")
}

func setupRouter(srv *server.PlatformServer, store storage.Store, demo bool, agentToken string) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(corsMiddleware(parseOrigins(os.Getenv("FLOWLENS_CORS_ORIGINS"))))

	public := r.Group("/api/v1")
	{
		public.GET("/health", srv.HealthHandler)
		public.POST("/auth/login", srv.LoginHandler)
	}

	var rg *gin.RouterGroup
	if demo {
		rg = r.Group("/api/v1")
	} else {
		rg = r.Group("/api/v1")
		rg.Use(auth.AuthMiddleware())
		rg.Use(middleware.AuditMiddleware(store))
	}

	// Agent-facing endpoints authenticate with the shared agent token, not user JWTs
	agentRG := r.Group("/api/v1")
	if !demo {
		agentRG.Use(auth.AgentTokenMiddleware(agentToken))
	}
	agentRG.POST("/agents/register", srv.RegisterAgentHandler)
	agentRG.POST("/agents/:id/heartbeat", srv.HeartbeatHandler)
	agentRG.POST("/ingest/event", srv.IngestEventHandler)
	agentRG.POST("/ingest/batch", srv.IngestBatchHandler)

	// Agent management
	rg.GET("/agents", srv.ListAgentsHandler)
	rg.GET("/agents/:id", srv.GetAgentHandler)
	rg.GET("/agents/health/summary", srv.AgentHealthSummaryHandler)

	// Assets
	rg.GET("/assets", srv.ListAssetsHandler)
	rg.GET("/assets/:id", srv.GetAssetHandler)
	rg.POST("/assets/:id/claim", srv.ClaimAssetHandler)

	// Alerts
	rg.GET("/alerts", srv.ListAlertsHandler)
	rg.GET("/alerts/:id", srv.GetAlertHandler)
	rg.POST("/alerts/:id/:action", srv.AlertActionHandler)

	// Detection
	rg.GET("/ingest/metrics", srv.IngestMetricsHandler)
	rg.POST("/detect/access", srv.RecordAccessHandler)
	rg.GET("/detect/events", srv.ListDetectionEventsHandler)

	// Rules (可见/可知/可控/可优化)
	rg.GET("/rules", srv.ListRulesHandler)
	rg.GET("/rules/categories", srv.ListRuleCategoriesHandler)
	rg.GET("/rules/:id", srv.GetRuleHandler)
	rg.PUT("/rules/:id", srv.UpdateRuleHandler)
	rg.POST("/rules/:id/hit", srv.HitRuleHandler)

	// Sensitive data
	rg.GET("/sensitive/flow-map", srv.FlowMapHandler)

	// Audit & Admin
	admin := rg.Group("")
	if !demo {
		admin.Use(auth.RoleMiddleware("super_admin", "security_admin", "auditor"))
	}
	admin.GET("/audit-logs", srv.ListAuditLogsHandler)

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
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
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
	for _, o := range strings.Split(v, ",") {
		if o = strings.TrimSpace(o); o != "" {
			out = append(out, strings.TrimRight(o, "/"))
		}
	}
	return out
}
