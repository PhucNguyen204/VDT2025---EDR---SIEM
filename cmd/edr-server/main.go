// ====================================================================
// EDR DETECTION ENGINE - MAIN APPLICATION
// ====================================================================
// Tác giả: Senior Software Engineer - EDR Platform Team
// Mô tả: Main application để chạy EDR detection engine
// ====================================================================

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/VDT2025_PhucNguyen204/internal/detector"
	"github.com/VDT2025_PhucNguyen204/internal/models"
	"github.com/VDT2025_PhucNguyen204/internal/rules"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

// EDRServer chứa toàn bộ server components
type EDRServer struct {
	engine     *detector.DetectionEngine
	ruleParser *rules.RuleParser
	logger     *logrus.Logger
	router     *gin.Engine
	upgrader   websocket.Upgrader

	// Alert storage (simple in-memory for demo)
	alerts     []*models.Alert
	alertsChan chan *models.Alert
}

// Config chứa cấu hình server
type Config struct {
	Port           string `json:"port"`
	RulesDirectory string `json:"rules_directory"`
	LogLevel       string `json:"log_level"`
	VectorEndpoint string `json:"vector_endpoint"`
}

func main() {
	// Setup logging
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	logger.Info("🚀 Starting EDR Detection Engine...")

	// Load configuration
	config := loadConfig(logger)

	// Create server
	server := &EDRServer{
		engine:     detector.NewDetectionEngine(),
		ruleParser: rules.NewRuleParser(),
		logger:     logger,
		alerts:     make([]*models.Alert, 0),
		alertsChan: make(chan *models.Alert, 1000),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for demo
			},
		},
	}

	// Load Sigma rules
	if err := server.loadRules(config.RulesDirectory); err != nil {
		logger.Fatalf("Failed to load rules: %v", err)
	}

	// Setup HTTP routes
	server.setupRoutes()

	// Start alert processor
	go server.processAlerts()

	// Start HTTP server
	go func() {
		logger.Infof("🌐 EDR Detection Engine listening on port %s", config.Port)
		logger.Infof("📊 Dashboard: http://localhost:%s/dashboard", config.Port)
		logger.Infof("🔍 API: http://localhost:%s/api/v1/", config.Port)

		if err := server.router.Run(":" + config.Port); err != nil {
			logger.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	logger.Info("🛑 Shutting down EDR Detection Engine...")
}

// loadConfig load configuration từ env hoặc default values
func loadConfig(logger *logrus.Logger) *Config {
	config := &Config{
		Port:           getEnv("EDR_PORT", "8080"),
		RulesDirectory: getEnv("EDR_RULES_DIR", "../../sigma/rules/windows/process_creation"),
		LogLevel:       getEnv("EDR_LOG_LEVEL", "info"),
		VectorEndpoint: getEnv("VECTOR_ENDPOINT", "http://localhost:8686"),
	}

	logger.Infof("📋 Configuration loaded:")
	logger.Infof("  Port: %s", config.Port)
	logger.Infof("  Rules Directory: %s", config.RulesDirectory)
	logger.Infof("  Log Level: %s", config.LogLevel)
	logger.Infof("  Vector Endpoint: %s", config.VectorEndpoint)

	return config
}

// loadRules load Sigma rules từ directory
func (s *EDRServer) loadRules(rulesDir string) error {
	s.logger.Infof("📚 Loading Sigma rules from: %s", rulesDir)

	// Check if directory exists
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) {
		return fmt.Errorf("rules directory does not exist: %s", rulesDir)
	}

	// Load rules using improved Sigma engine
	err := s.engine.LoadSigmaRulesFromDirectory(rulesDir)
	if err != nil {
		return fmt.Errorf("failed to load Sigma rules: %w", err)
	}

	// Fallback: Parse rules với original parser (for compatibility)
	allRules, err := s.ruleParser.ParseRulesDirectory(rulesDir)
	if err != nil {
		s.logger.Warnf("Failed to parse rules with original parser: %v", err)
		return nil // Continue với Sigma engine rules
	}

	// Filter rules (chỉ lấy stable và test rules)
	var validRules []*models.DetectionRule
	for _, rule := range allRules {
		if rule.Status == "stable" || rule.Status == "test" {
			validRules = append(validRules, rule)
		}
	}

	s.logger.Infof("📊 Original parser loaded %d rules (%d total, %d filtered)", len(validRules), len(allRules), len(validRules))

	// Load additional rules vào engine
	s.engine.LoadRules(validRules)

	// Print stats
	stats := s.ruleParser.GetRuleStats(validRules)
	s.logger.Infof("📈 Rule Statistics: %+v", stats)

	return nil
}

// setupRoutes setup HTTP routes
func (s *EDRServer) setupRoutes() {
	// Disable Gin debug mode
	gin.SetMode(gin.ReleaseMode)
	s.router = gin.New()
	s.router.Use(gin.Logger(), gin.Recovery())

	// Serve static files (dashboard)
	s.router.StaticFS("/static", http.Dir("./web/static"))
	// HTML templates disabled for now
	// s.router.LoadHTMLGlob("./web/templates/*")

	// Dashboard routes (disabled for now)
	// s.router.GET("/", s.handleDashboard)
	// s.router.GET("/dashboard", s.handleDashboard)

	// API routes
	api := s.router.Group("/api/v1")
	{
		api.POST("/events", s.handleEvent)             // Receive events từ Vector
		api.GET("/alerts", s.handleGetAlerts)          // Get all alerts
		api.GET("/alerts/:id", s.handleGetAlert)       // Get specific alert
		api.GET("/stats", s.handleGetStats)            // Get detection stats
		api.GET("/rules", s.handleGetRules)            // Get loaded rules
		api.POST("/rules/reload", s.handleReloadRules) // Reload rules
	}

	// WebSocket endpoint cho real-time alerts
	s.router.GET("/ws/alerts", s.handleWebSocket)

	// Health check
	s.router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "healthy",
			"timestamp": time.Now(),
			"version":   "1.0.0",
		})
	})
}

// handleEvent xử lý event từ Vector
func (s *EDRServer) handleEvent(c *gin.Context) {
	var eventData json.RawMessage
	if err := c.ShouldBindJSON(&eventData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
		return
	}

	// Try to parse as array first, then as single event
	var events []*models.Event
	var totalAlerts int
	var eventIDs []string

	// Try parsing as array
	var eventArray []json.RawMessage
	if err := json.Unmarshal(eventData, &eventArray); err == nil {
		// It's an array
		for _, rawEvent := range eventArray {
			event, err := models.ParseEvent(rawEvent)
			if err != nil {
				s.logger.Warnf("Failed to parse event in array: %v", err)
				continue
			}
			events = append(events, event)
		}
	} else {
		// Try parsing as single event
		event, err := models.ParseEvent(eventData)
		if err != nil {
			s.logger.Errorf("Failed to parse event: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid event format"})
			return
		}
		events = append(events, event)
	}

	// Process each event
	for _, event := range events {
		s.logger.Debugf("📨 Received event: %s from host %s", event.ID, event.Host.Name)

		// Process event through detection engine
		alerts, err := s.engine.ProcessEvent(event)
		if err != nil {
			s.logger.Errorf("Failed to process event: %v", err)
			continue
		}

		totalAlerts += len(alerts)
		eventIDs = append(eventIDs, event.ID)

		// Send alerts to channel
		for _, alert := range alerts {
			select {
			case s.alertsChan <- alert:
			default:
				s.logger.Warn("Alert channel full, dropping alert")
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"processed":        true,
		"events_count":     len(events),
		"alerts_generated": totalAlerts,
		"event_ids":        eventIDs,
	})
}

// handleGetAlerts trả về danh sách alerts
func (s *EDRServer) handleGetAlerts(c *gin.Context) {
	// Simple pagination
	limit := 100
	if len(s.alerts) > limit {
		c.JSON(http.StatusOK, gin.H{
			"alerts":  s.alerts[len(s.alerts)-limit:],
			"total":   len(s.alerts),
			"showing": limit,
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"alerts":  s.alerts,
			"total":   len(s.alerts),
			"showing": len(s.alerts),
		})
	}
}

// handleGetAlert trả về alert cụ thể
func (s *EDRServer) handleGetAlert(c *gin.Context) {
	alertID := c.Param("id")

	for _, alert := range s.alerts {
		if alert.ID == alertID {
			c.JSON(http.StatusOK, alert)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Alert not found"})
}

// handleGetStats trả về detection statistics
func (s *EDRServer) handleGetStats(c *gin.Context) {
	stats := s.engine.GetStats()

	c.JSON(http.StatusOK, gin.H{
		"events_processed": stats.GetEventsProcessed(),
		"alerts_generated": stats.GetAlertsGenerated(),
		"rules_matched":    stats.GetRulesMatched(),
		"last_reset":       stats.LastReset,
		"uptime":           time.Since(stats.LastReset),
	})
}

// handleGetRules trả về danh sách rules
func (s *EDRServer) handleGetRules(c *gin.Context) {
	rules := s.engine.GetRules()

	// Return simplified rule info
	var ruleInfo []map[string]interface{}
	for _, rule := range rules {
		ruleInfo = append(ruleInfo, map[string]interface{}{
			"id":       rule.ID,
			"title":    rule.Title,
			"level":    rule.Level,
			"status":   rule.Status,
			"category": rule.LogSource.Category,
			"product":  rule.LogSource.Product,
			"tags":     rule.Tags,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"rules": ruleInfo,
		"count": len(rules),
	})
}

// handleReloadRules reload rules
func (s *EDRServer) handleReloadRules(c *gin.Context) {
	rulesDir := getEnv("EDR_RULES_DIR", "../../sigma/rules")

	if err := s.loadRules(rulesDir); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Rules reloaded successfully"})
}

// handleDashboard serve dashboard HTML
func (s *EDRServer) handleDashboard(c *gin.Context) {
	stats := s.engine.GetStats()

	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"Title":           "EDR Detection Engine Dashboard",
		"EventsProcessed": stats.GetEventsProcessed(),
		"AlertsGenerated": stats.GetAlertsGenerated(),
		"AlertsCount":     len(s.alerts),
		"RulesCount":      s.engine.GetRulesCount(),
	})
}

// handleWebSocket xử lý WebSocket connection cho real-time alerts
func (s *EDRServer) handleWebSocket(c *gin.Context) {
	conn, err := s.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		s.logger.Errorf("Failed to upgrade WebSocket: %v", err)
		return
	}
	defer conn.Close()

	s.logger.Info("📡 New WebSocket connection for real-time alerts")

	// Send existing alerts
	for _, alert := range s.alerts {
		if err := conn.WriteJSON(alert); err != nil {
			s.logger.Errorf("Failed to send alert via WebSocket: %v", err)
			return
		}
	}

	// Keep connection alive and send new alerts
	for {
		select {
		case alert := <-s.alertsChan:
			if err := conn.WriteJSON(alert); err != nil {
				s.logger.Errorf("Failed to send alert via WebSocket: %v", err)
				return
			}
		case <-time.After(30 * time.Second):
			// Send ping to keep connection alive
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// processAlerts xử lý alerts từ channel
func (s *EDRServer) processAlerts() {
	for alert := range s.alertsChan {
		s.logger.Infof("🚨 ALERT: %s - %s (Severity: %s)", alert.RuleName, alert.Description, alert.Severity)

		// Store alert
		s.alerts = append(s.alerts, alert)

		// Keep only last 1000 alerts in memory
		if len(s.alerts) > 1000 {
			s.alerts = s.alerts[len(s.alerts)-1000:]
		}

		// In production, bạn sẽ gửi alert tới:
		// - SIEM system
		// - Slack/Teams notification
		// - Email notification
		// - Ticketing system
		// - Database storage
	}
}

// getEnv get environment variable hoặc default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
