package server

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/VDT2025_PhucNguyen204/cmd/edr-v2/internal/config"
	"github.com/VDT2025_PhucNguyen204/cmd/edr-v2/internal/server/handlers"
	"github.com/VDT2025_PhucNguyen204/cmd/edr-v2/internal/server/middleware"
	"github.com/VDT2025_PhucNguyen204/internal/engine"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// Server wraps HTTP server and EDR engine
type Server struct {
	engine *engine.Engine
	server *http.Server
	config *config.AppConfig
}

// NewServer creates a new server instance
func NewServer(cfg *config.AppConfig, engine *engine.Engine) *Server {
	return &Server{
		engine: engine,
		config: cfg,
	}
}

// setupRouter configures HTTP routes and middleware
func (s *Server) setupRouter() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	// Add middleware
	router.Use(gin.Recovery())
	router.Use(middleware.Logger())
	router.Use(middleware.CORS())

	// Health check routes
	router.GET("/health", handlers.Health)
	router.GET("/", handlers.Health)

	// Serve dashboard
	router.Static("/static", "./web")
	router.GET("/dashboard", func(c *gin.Context) {
		c.File("./web/dashboard.html")
	})

	// API routes
	api := router.Group("/api/v2")
	{
		api.POST("/events", handlers.Events(s.engine))
		api.GET("/stats", handlers.Stats(s.engine))
		api.GET("/alerts", handlers.Alerts(s.engine))
		api.GET("/rules", handlers.Rules(s.engine))
	}

	return router
}

// Start starts the HTTP server
func (s *Server) Start() error {
	router := s.setupRouter()

	s.server = &http.Server{
		Addr:    ":" + s.config.Port,
		Handler: router,

		// Production timeouts
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in goroutine
	go func() {
		logrus.Infof("EDR Engine v2 starting on port %s", s.config.Port)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logrus.Fatalf("Failed to start server: %v", err)
		}
	}()

	return nil
}

// Stop gracefully stops the HTTP server
func (s *Server) Stop() error {
	logrus.Info("Shutting down HTTP server...")

	// Graceful shutdown with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.server.Shutdown(shutdownCtx); err != nil {
		logrus.Errorf("Server forced to shutdown: %v", err)
		return err
	}

	logrus.Info("HTTP server stopped")
	return nil
}

// Run starts the server and waits for shutdown signal
func (s *Server) Run() error {
	// Start server
	if err := s.Start(); err != nil {
		return err
	}

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logrus.Info("Received shutdown signal...")

	// Stop HTTP server
	if err := s.Stop(); err != nil {
		return err
	}

	// Stop EDR engine
	if err := s.engine.Stop(); err != nil {
		logrus.Errorf("Error stopping engine: %v", err)
		return err
	}

	logrus.Info("Server exited gracefully")
	return nil
}
