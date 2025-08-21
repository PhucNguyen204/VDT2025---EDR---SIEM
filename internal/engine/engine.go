package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/VDT2025_PhucNguyen204/internal/event"
	"github.com/markuskont/go-sigma-rule-engine"
	"github.com/sirupsen/logrus"
)

// Config holds engine configuration
type Config struct {
	RulesDirectory []string
	SIEMEndpoint   string
	BatchSize      int
}

// Engine is the main EDR detection engine
type Engine struct {
	config  Config
	ruleset *sigma.Ruleset
	mu      sync.RWMutex

	// Statistics
	eventsProcessed uint64
	alertsGenerated uint64
	rulesLoaded     uint64

	// Alert management
	alertQueue   chan *Alert
	recentAlerts []*Alert
	alertsMutex  sync.RWMutex

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
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
	MITRE       []string               `json:"mitre,omitempty"`
}

// RuleInfo contains basic rule information
type RuleInfo struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Author      string   `json:"author,omitempty"`
	Level       string   `json:"level"`
	Tags        []string `json:"tags,omitempty"`
}

// Stats represents engine statistics
type Stats struct {
	EventsProcessed uint64    `json:"events_processed"`
	AlertsGenerated uint64    `json:"alerts_generated"`
	RulesLoaded     uint64    `json:"rules_loaded"`
	Uptime          string    `json:"uptime"`
	LastEvent       time.Time `json:"last_event"`
}

var startTime = time.Now()

// NewEngine creates a new EDR engine instance
func NewEngine(config Config) (*Engine, error) {
	// Load Sigma rules
	ruleset, err := sigma.NewRuleset(sigma.Config{
		Directory: config.RulesDirectory,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load rules: %w", err)
	}

	logrus.Infof("Loaded %d rules successfully (total: %d, failed: %d, unsupported: %d)",
		ruleset.Ok, ruleset.Total, ruleset.Failed, ruleset.Unsupported)

	engine := &Engine{
		config:       config,
		ruleset:      ruleset,
		alertQueue:   make(chan *Alert, 1000),
		recentAlerts: make([]*Alert, 0, 1000),
		rulesLoaded:  uint64(ruleset.Ok),
	}

	return engine, nil
}

// Start starts the engine background workers
func (e *Engine) Start(ctx context.Context) error {
	e.ctx, e.cancel = context.WithCancel(ctx)

	// Start alert processor
	e.wg.Add(1)
	go e.alertProcessor()

	// Start SIEM forwarder if configured
	if e.config.SIEMEndpoint != "" {
		e.wg.Add(1)
		go e.siemForwarder()
	}

	logrus.Info("EDR Engine started successfully")
	return nil
}

// Stop gracefully stops the engine
func (e *Engine) Stop() error {
	logrus.Info("Stopping EDR Engine...")

	// Cancel context
	e.cancel()

	// Close alert queue
	close(e.alertQueue)

	// Wait for workers to finish
	e.wg.Wait()

	logrus.Info("EDR Engine stopped")
	return nil
}

// ProcessEvent processes a single event
func (e *Engine) ProcessEvent(rawEvent json.RawMessage) error {
	// Parse event
	evt, err := event.ParseEvent(rawEvent)
	if err != nil {
		return fmt.Errorf("failed to parse event: %w", err)
	}

	// Update statistics
	atomic.AddUint64(&e.eventsProcessed, 1)

	// Evaluate against all rules
	matchedRules := make([]*sigma.Tree, 0)

	// Check each rule individually
	for _, rule := range e.ruleset.Rules {
		if match, ok := rule.Match(evt); ok && match {
			matchedRules = append(matchedRules, rule)
		}
	}

	if len(matchedRules) == 0 {
		return nil // No match, but not an error
	}

	// Generate alerts for matches
	for i, rule := range matchedRules {
		alert := e.createAlert(rule, evt, i)

		// Update statistics
		atomic.AddUint64(&e.alertsGenerated, 1)

		// Send to alert queue
		select {
		case e.alertQueue <- alert:
			logrus.WithFields(logrus.Fields{
				"rule_id":    alert.Rule.ID,
				"rule_title": alert.Rule.Title,
				"severity":   alert.Severity,
			}).Info("Alert generated")
		default:
			logrus.Warn("Alert queue full, dropping alert")
		}
	}

	return nil
}

// createAlert creates an alert from a rule match
func (e *Engine) createAlert(rule *sigma.Tree, evt event.Event, index int) *Alert {
	// Generate unique ID based on index
	ruleID := fmt.Sprintf("sigma-rule-%d", index)

	alert := &Alert{
		ID:          fmt.Sprintf("%s-%d", ruleID, time.Now().UnixNano()),
		Timestamp:   time.Now().UTC(),
		Event:       evt.GetData(),
		Severity:    "medium", // Default severity
		Description: "Sigma rule match detected",
		Tags:        []string{"sigma", "detection"},
	}

	// Set rule info with available fields
	alert.Rule = RuleInfo{
		ID:          ruleID,
		Title:       fmt.Sprintf("Sigma Rule %d", index),
		Description: "A Sigma rule has matched this event",
		Level:       "medium",
		Tags:        []string{"sigma"},
	}

	// The v0.3.0 version has limited metadata access
	// Rule details are not exposed in the Tree structure

	return alert
}

// alertProcessor processes alerts from the queue
func (e *Engine) alertProcessor() {
	defer e.wg.Done()

	for {
		select {
		case alert, ok := <-e.alertQueue:
			if !ok {
				return
			}

			// Store alert in recent alerts
			e.alertsMutex.Lock()
			e.recentAlerts = append(e.recentAlerts, alert)

			// Keep only last 1000 alerts
			if len(e.recentAlerts) > 1000 {
				e.recentAlerts = e.recentAlerts[len(e.recentAlerts)-1000:]
			}
			e.alertsMutex.Unlock()

		case <-e.ctx.Done():
			return
		}
	}
}

// siemForwarder forwards alerts to SIEM
func (e *Engine) siemForwarder() {
	defer e.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	batch := make([]*Alert, 0, e.config.BatchSize)

	for {
		select {
		case <-ticker.C:
			if len(batch) > 0 {
				e.forwardToSIEM(batch)
				batch = batch[:0]
			}

		case alert := <-e.alertQueue:
			batch = append(batch, alert)
			if len(batch) >= e.config.BatchSize {
				e.forwardToSIEM(batch)
				batch = batch[:0]
			}

		case <-e.ctx.Done():
			// Forward remaining alerts
			if len(batch) > 0 {
				e.forwardToSIEM(batch)
			}
			return
		}
	}
}

// forwardToSIEM sends alerts to SIEM endpoint
func (e *Engine) forwardToSIEM(alerts []*Alert) {
	// TODO: Implement actual SIEM forwarding
	logrus.Infof("Would forward %d alerts to SIEM: %s", len(alerts), e.config.SIEMEndpoint)
}

// GetStats returns engine statistics
func (e *Engine) GetStats() Stats {
	return Stats{
		EventsProcessed: atomic.LoadUint64(&e.eventsProcessed),
		AlertsGenerated: atomic.LoadUint64(&e.alertsGenerated),
		RulesLoaded:     atomic.LoadUint64(&e.rulesLoaded),
		Uptime:          time.Since(startTime).String(),
		LastEvent:       time.Now(),
	}
}

// GetRecentAlerts returns recent alerts
func (e *Engine) GetRecentAlerts(limit int) []*Alert {
	e.alertsMutex.RLock()
	defer e.alertsMutex.RUnlock()

	if limit > len(e.recentAlerts) {
		limit = len(e.recentAlerts)
	}

	// Return most recent alerts first
	result := make([]*Alert, limit)
	for i := 0; i < limit; i++ {
		result[i] = e.recentAlerts[len(e.recentAlerts)-1-i]
	}

	return result
}

// GetLoadedRules returns information about loaded rules
func (e *Engine) GetLoadedRules() []RuleInfo {
	rules := make([]RuleInfo, 0, len(e.ruleset.Rules))

	for i := range e.ruleset.Rules {
		info := RuleInfo{
			ID:          fmt.Sprintf("sigma-rule-%d", i),
			Title:       fmt.Sprintf("Sigma Rule %d", i),
			Description: "Loaded Sigma rule",
			Level:       "medium",
			Tags:        []string{"sigma"},
		}

		rules = append(rules, info)
	}

	return rules
}
