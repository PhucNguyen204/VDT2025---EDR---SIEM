package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/VDT2025_PhucNguyen204/internal/engine"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

var (
	port      = flag.String("port", "8090", "HTTP server port")
	rulesDir  = flag.String("rules", "./sigma/rules", "Sigma rules directory")
	logLevel  = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	siemURL   = flag.String("siem-url", "", "SIEM endpoint URL for forwarding alerts")
	batchSize = flag.Int("batch-size", 100, "Alert batch size for SIEM forwarding")
)

func main() {
	flag.Parse()

	// Configure logging
	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		log.Fatalf("Invalid log level: %v", err)
	}
	logrus.SetLevel(level)
	logrus.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
	})

	// Create EDR engine
	engineConfig := engine.Config{
		RulesDirectory: []string{*rulesDir},
		SIEMEndpoint:   *siemURL,
		BatchSize:      *batchSize,
	}

	edrEngine, err := engine.NewEngine(engineConfig)
	if err != nil {
		logrus.Fatalf("Failed to create EDR engine: %v", err)
	}

	// Start engine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := edrEngine.Start(ctx); err != nil {
		logrus.Fatalf("Failed to start EDR engine: %v", err)
	}

	// Setup HTTP server
	router := setupRouter(edrEngine)

	srv := &http.Server{
		Addr:    ":" + *port,
		Handler: router,
	}

	// Start server in goroutine
	go func() {
		logrus.Infof("EDR Engine v2 starting on port %s", *port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logrus.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logrus.Info("Shutting down server...")

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logrus.Errorf("Server forced to shutdown: %v", err)
	}

	// Stop engine
	if err := edrEngine.Stop(); err != nil {
		logrus.Errorf("Error stopping engine: %v", err)
	}

	logrus.Info("Server exited")
}

func setupRouter(engine *engine.Engine) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(loggerMiddleware())

	// Health check
	router.GET("/health", handleHealth)
	router.GET("/", handleHealth)

	// API routes
	api := router.Group("/api/v2")
	{
		api.POST("/events", handleEvents(engine))
		api.GET("/stats", handleStats(engine))
		api.GET("/alerts", handleAlerts(engine))
		api.GET("/rules", handleRules(engine))
	}

	return router
}

func loggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)
		clientIP := c.ClientIP()
		method := c.Request.Method
		statusCode := c.Writer.Status()

		if raw != "" {
			path = path + "?" + raw
		}

		logrus.WithFields(logrus.Fields{
			"status":     statusCode,
			"latency_ms": latency.Milliseconds(),
			"client_ip":  clientIP,
			"method":     method,
			"path":       path,
		}).Info("HTTP request")
	}
}

func handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"version":   "2.0.0",
	})
}

func handleEvents(engine *engine.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Read raw body first
		body, err := c.GetRawData()
		if err != nil {
			logrus.Errorf("Failed to read request body: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
			return
		}

		logrus.Debugf("Received raw body: %s", string(body))

		var events []json.RawMessage

		// Try to parse as single event first
		var singleEvent json.RawMessage
		if err := json.Unmarshal(body, &singleEvent); err == nil {
			events = []json.RawMessage{singleEvent}
		} else {
			// Try to parse as array
			if err := json.Unmarshal(body, &events); err != nil {
				logrus.Errorf("JSON parse error: %v, body: %s", err, string(body))
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid JSON format: %v", err)})
				return
			}
		}

		// Get initial stats
		initialStats := engine.GetStats()
		initialAlerts := initialStats.AlertsGenerated

		processed := 0
		errors := 0

		for _, rawEvent := range events {
			if err := engine.ProcessEvent(rawEvent); err != nil {
				logrus.Errorf("Failed to process event: %v", err)
				errors++
			} else {
				processed++
			}
		}

		// Get final stats to calculate alerts generated
		finalStats := engine.GetStats()
		alertsGenerated := finalStats.AlertsGenerated - initialAlerts

		c.JSON(http.StatusOK, gin.H{
			"processed":        processed,
			"errors":           errors,
			"alerts_generated": alertsGenerated,
			"timestamp":        time.Now().UTC(),
		})
	}
}

func handleStats(engine *engine.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		stats := engine.GetStats()
		c.JSON(http.StatusOK, stats)
	}
}

func handleAlerts(engine *engine.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		limit := 100
		if l := c.Query("limit"); l != "" {
			fmt.Sscanf(l, "%d", &limit)
		}

		alerts := engine.GetRecentAlerts(limit)
		c.JSON(http.StatusOK, gin.H{
			"alerts": alerts,
			"count":  len(alerts),
		})
	}
}

func handleRules(engine *engine.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		rules := engine.GetLoadedRules()
		c.JSON(http.StatusOK, gin.H{
			"rules": rules,
			"count": len(rules),
		})
	}
}
