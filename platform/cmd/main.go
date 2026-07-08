package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/auth"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/middleware"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/server"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/version"
)

func main() {
	var (
		port  int
		debug bool
		demo  bool
	)
	flag.IntVar(&port, "port", 8080, "http server port")
	flag.BoolVar(&debug, "debug", false, "enable debug mode")
	flag.BoolVar(&demo, "demo", false, "demo mode: disable auth, use seed data only")
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

	store := storage.NewStore("mem")
	srv := server.NewPlatformServer(store)
	srv.DemoMode = demo

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.StartEngines(ctx)

	log.Infof("Starting %s Platform v%s on port %d", version.Name, version.Version, port)
	if demo {
		log.Warn("Running in DEMO mode — authentication disabled")
	}

	router := setupRouter(srv, store, demo)

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

func setupRouter(srv *server.PlatformServer, store storage.Store, demo bool) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(corsMiddleware())

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

	// Agent management
	rg.GET("/agents", srv.ListAgentsHandler)
	rg.GET("/agents/:id", srv.GetAgentHandler)
	rg.GET("/agents/health/summary", srv.AgentHealthSummaryHandler)
	rg.POST("/agents/register", srv.RegisterAgentHandler)
	rg.POST("/agents/:id/heartbeat", srv.HeartbeatHandler)

	// Assets
	rg.GET("/assets", srv.ListAssetsHandler)
	rg.GET("/assets/:id", srv.GetAssetHandler)
	rg.POST("/assets/:id/claim", srv.ClaimAssetHandler)

	// Alerts
	rg.GET("/alerts", srv.ListAlertsHandler)
	rg.GET("/alerts/:id", srv.GetAlertHandler)
	rg.POST("/alerts/:id/:action", srv.AlertActionHandler)

	// Detection
	rg.POST("/ingest/event", srv.IngestEventHandler)
	rg.POST("/ingest/batch", srv.IngestBatchHandler)
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

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}
