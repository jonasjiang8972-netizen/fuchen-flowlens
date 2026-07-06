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
	)
	flag.IntVar(&port, "port", 8080, "http server port")
	flag.BoolVar(&debug, "debug", false, "enable debug mode")
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.StartEngines(ctx)

	log.Infof("Starting %s Platform v%s on port %d", version.Name, version.Version, port)

	router := setupRouter(srv, store)

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

func setupRouter(srv *server.PlatformServer, store storage.Store) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(corsMiddleware())

	public := r.Group("/api/v1")
	{
		public.GET("/health", srv.HealthHandler)
		public.POST("/auth/login", srv.LoginHandler)
	}

	authGroup := r.Group("/api/v1")
	authGroup.Use(auth.AuthMiddleware())
	authGroup.Use(middleware.AuditMiddleware(store))
	{
		authGroup.GET("/agents", srv.ListAgentsHandler)
		authGroup.GET("/agents/:id", srv.GetAgentHandler)
		authGroup.GET("/agents/health/summary", srv.AgentHealthSummaryHandler)
		authGroup.POST("/agents/register", srv.RegisterAgentHandler)
		authGroup.POST("/agents/:id/heartbeat", srv.HeartbeatHandler)

		authGroup.GET("/assets", srv.ListAssetsHandler)
		authGroup.GET("/assets/:id", srv.GetAssetHandler)
		authGroup.POST("/assets/:id/claim", srv.ClaimAssetHandler)

		authGroup.GET("/alerts", srv.ListAlertsHandler)
		authGroup.GET("/alerts/:id", srv.GetAlertHandler)
		authGroup.POST("/alerts/:id/:action", srv.AlertActionHandler)

		authGroup.GET("/sensitive/flow-map", srv.FlowMapHandler)

		authGroup.POST("/detect/access", srv.RecordAccessHandler)
		authGroup.GET("/detect/events", srv.ListDetectionEventsHandler)

		admin := authGroup.Group("")
		admin.Use(auth.RoleMiddleware("super_admin", "security_admin", "auditor"))
		{
			admin.GET("/audit-logs", srv.ListAuditLogsHandler)
		}
	}

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
