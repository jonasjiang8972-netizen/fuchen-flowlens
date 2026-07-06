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
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/version"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/server"
)

func main() {
	var (
		port    int
		debug   bool
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

	log.Infof("Starting %s Platform v%s on port %d", version.Name, version.Version, port)

	router := setupRouter()

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: router,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Infof("Received signal %v, shutting down...", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Errorf("Server forced shutdown: %v", err)
	}
	log.Info("Server stopped gracefully")
}

func setupRouter() *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(corsMiddleware())

	api := r.Group("/api/v1")
	{
		api.GET("/health", server.HealthHandler)
		api.GET("/agents", server.ListAgentsHandler)
		api.GET("/agents/:id", server.GetAgentHandler)
		api.GET("/agents/health/summary", server.AgentHealthSummaryHandler)
		api.GET("/assets", server.ListAssetsHandler)
		api.GET("/assets/:id", server.GetAssetHandler)
		api.POST("/assets/:id/claim", server.ClaimAssetHandler)
		api.GET("/alerts", server.ListAlertsHandler)
		api.GET("/alerts/:id", server.GetAlertHandler)
		api.POST("/alerts/:id/:action", server.AlertActionHandler)
		api.GET("/sensitive/flow-map", server.FlowMapHandler)
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
