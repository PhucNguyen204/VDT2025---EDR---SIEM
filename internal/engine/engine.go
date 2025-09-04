package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Engine is the main detection engine that now uses only Rust sigma-engine
type Engine struct {
	rustEngine   *RustSigmaEngine
	config       Config
	ctx          context.Context
	cancel       context.CancelFunc
	alertQueue   chan *Alert
	recentAlerts []*Alert
	alertsMutex  sync.RWMutex
	wg           sync.WaitGroup
	startTime    time.Time
}

// Config holds engine configuration
type Config struct {
	RulesDirectory []string
	SIEMEndpoint   string
	BatchSize      int
}

// Alert represents a security alert
type Alert struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Rule        RuleInfo               `json:"rule"`
	Event       map[string]interface{} `json:"event"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Tags        []string               `json:"tags"`
}

// RuleInfo contains information about the matched rule
type RuleInfo struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Level       string   `json:"level"`
	Tags        []string `json:"tags"`
}

// Stats represents engine statistics
type Stats struct {
	EventsProcessed uint64 `json:"events_processed"`
	AlertsGenerated uint64 `json:"alerts_generated"`
	RulesLoaded     uint64 `json:"rules_loaded"`
	Uptime          string `json:"uptime"`
}

// NewEngine creates a new detection engine instance using Rust sigma-engine
func NewEngine(config Config, ruleYamls []string) (*Engine, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Create Rust engine
	rustEngine, err := NewRustSigmaEngine(ruleYamls)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create Rust sigma engine: %w", err)
	}

	engine := &Engine{
		rustEngine: rustEngine,
		config:     config,
		ctx:        ctx,
		cancel:     cancel,
		alertQueue: make(chan *Alert, 1000),
		startTime:  time.Now(),
	}

	logrus.Info("Created Detection Engine with Rust sigma-engine")
	return engine, nil
}

// ProcessEvent processes a single event through the Rust engine
func (e *Engine) ProcessEvent(rawEvent json.RawMessage) error {
	result, err := e.rustEngine.ProcessEvent(rawEvent)
	if err != nil {
		return fmt.Errorf("Rust engine error: %w", err)
	}

	// Generate alerts if matches found
	if len(result.MatchedRules) > 0 {
		e.generateAlertsFromResult(result, rawEvent)
	}

	return nil
}

// generateAlertsFromResult creates alerts from Rust engine results
func (e *Engine) generateAlertsFromResult(result *RustEngineResult, rawEvent json.RawMessage) {
	// Parse the raw event
	var eventData map[string]interface{}
	if err := json.Unmarshal(rawEvent, &eventData); err != nil {
		logrus.Errorf("Failed to parse event data: %v", err)
		return
	}

	// Create alerts for each matched rule
	for _, ruleIndex := range result.MatchedRules {
		alert := &Alert{
			ID:        fmt.Sprintf("rust-%d-%d", ruleIndex, time.Now().UnixNano()),
			Timestamp: time.Now(),
			Rule: RuleInfo{
				ID:          fmt.Sprintf("rule-%d", ruleIndex),
				Title:       fmt.Sprintf("Sigma Rule %d", ruleIndex),
				Description: fmt.Sprintf("Rule %d matched by Rust sigma-engine", ruleIndex),
				Level:       "medium",
				Tags:        []string{"sigma-rule"},
			},
			Event:       eventData,
			Severity:    "medium",
			Description: fmt.Sprintf("Event matched rule %d (Rust sigma-engine)", ruleIndex),
			Tags:        []string{"rust-engine", "sigma-rule"},
		}

		e.addAlertToQueue(alert)
	}
}

// addAlertToQueue adds an alert to the processing queue
func (e *Engine) addAlertToQueue(alert *Alert) {
	select {
	case e.alertQueue <- alert:
		// Successfully queued
	default:
		logrus.Warn("Alert queue is full, dropping alert")
	}

	// Update recent alerts
	e.alertsMutex.Lock()
	e.recentAlerts = append(e.recentAlerts, alert)
	if len(e.recentAlerts) > 100 { // Keep only last 100 alerts
		e.recentAlerts = e.recentAlerts[1:]
	}
	e.alertsMutex.Unlock()
}

// GetStats returns engine statistics
func (e *Engine) GetStats() (*Stats, error) {
	rustStats, err := e.rustEngine.GetStats()
	if err != nil {
		return nil, fmt.Errorf("failed to get Rust engine stats: %w", err)
	}

	return rustStats, nil
}

// Start starts the detection engine
func (e *Engine) Start(ctx context.Context) error {
	logrus.Info("Starting Rust-based Detection Engine...")

	// Start background workers
	e.wg.Add(2)
	go e.alertProcessor()
	go e.siemForwarder()

	logrus.Info("Rust-based Detection Engine started successfully")
	return nil
}

// Stop gracefully stops the detection engine
func (e *Engine) Stop() error {
	logrus.Info("Stopping Rust-based Engine...")

	// Close Rust engine
	if err := e.rustEngine.Close(); err != nil {
		logrus.Errorf("Error closing Rust engine: %v", err)
	}

	// Cancel context to signal shutdown
	e.cancel()

	// Close alert queue
	close(e.alertQueue)

	// Wait for workers to finish
	e.wg.Wait()

	logrus.Info("Rust-based Engine stopped")
	return nil
}

// alertProcessor processes alerts from the queue
func (e *Engine) alertProcessor() {
	defer e.wg.Done()

	for {
		select {
		case alert, ok := <-e.alertQueue:
			if !ok {
				return // Channel closed
			}

			logrus.Infof("Processing alert: %s - %s", alert.ID, alert.Description)

		case <-e.ctx.Done():
			return
		}
	}
}

// siemForwarder forwards alerts to SIEM
func (e *Engine) siemForwarder() {
	defer e.wg.Done()

	// Implementation for SIEM forwarding
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-time.After(time.Second * 10):
			// Batch forward alerts to SIEM
			// Implementation can be added here
		}
	}
}

// GetRuleCount returns the number of loaded rules
func (e *Engine) GetRuleCount() int {
	return e.rustEngine.GetRuleCount()
}

// GetRecentAlerts returns recent alerts
func (e *Engine) GetRecentAlerts(limit int) []*Alert {
	e.alertsMutex.RLock()
	defer e.alertsMutex.RUnlock()

	alerts := make([]*Alert, 0, limit)
	start := len(e.recentAlerts) - limit
	if start < 0 {
		start = 0
	}

	for i := start; i < len(e.recentAlerts); i++ {
		alerts = append(alerts, e.recentAlerts[i])
	}

	return alerts
}

// RuleInfo represents loaded rule information
type RuleMetadata struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Level       string   `json:"level"`
	Tags        []string `json:"tags"`
}

// GetLoadedRules returns information about loaded rules
func (e *Engine) GetLoadedRules() []RuleMetadata {
	ruleCount := e.rustEngine.GetRuleCount()
	rules := make([]RuleMetadata, ruleCount)

	for i := 0; i < ruleCount; i++ {
		rules[i] = RuleMetadata{
			ID:          fmt.Sprintf("rule-%d", i),
			Title:       fmt.Sprintf("Sigma Rule %d", i),
			Description: fmt.Sprintf("Loaded Sigma rule %d", i),
			Level:       "medium",
			Tags:        []string{"sigma-rule"},
		}
	}

	return rules
}

// ProcessEventsBatch processes multiple events efficiently
func (e *Engine) ProcessEventsBatch(events []json.RawMessage) error {
	results, err := e.rustEngine.ProcessEventsBatch(events)
	if err != nil {
		return fmt.Errorf("failed to process events batch: %w", err)
	}

	// Generate alerts for each result
	for i, result := range results {
		if len(result.MatchedRules) > 0 {
			e.generateAlertsFromResult(result, events[i])
		}
	}

	return nil
}
