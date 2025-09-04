package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// HybridEngine combines both Go and Rust engines for comparison and migration
type HybridEngine struct {
	config      Config
	goEngine    *Engine
	rustEngine  *RustSigmaEngine
	mu          sync.RWMutex
	startTime   time.Time
	useRustOnly bool

	// Statistics for comparison
	goStats   EngineStats
	rustStats EngineStats

	// Alert management
	alertQueue   chan *Alert
	recentAlerts []*Alert
	alertsMutex  sync.RWMutex

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// EngineStats tracks performance statistics for each engine
type EngineStats struct {
	EventsProcessed       uint64
	AlertsGenerated       uint64
	TotalProcessingTime   time.Duration
	AverageProcessingTime time.Duration
}

// NewHybridEngine creates a new hybrid engine with both Go and Rust implementations
func NewHybridEngine(config Config, ruleYamls []string) (*HybridEngine, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Create Go engine
	goEngine, err := NewEngine(config)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create Go engine: %w", err)
	}

	// Create Rust engine
	rustEngine, err := NewRustSigmaEngine(ruleYamls)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create Rust engine: %w", err)
	}

	hybrid := &HybridEngine{
		config:      config,
		goEngine:    goEngine,
		rustEngine:  rustEngine,
		ctx:         ctx,
		cancel:      cancel,
		alertQueue:  make(chan *Alert, 1000),
		startTime:   time.Now(),
		useRustOnly: false, // Start with comparison mode
	}

	logrus.Info("Created Hybrid Engine with both Go and Rust implementations")
	return hybrid, nil
}

// SetRustOnly switches to using only the Rust engine
func (e *HybridEngine) SetRustOnly(rustOnly bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.useRustOnly = rustOnly

	if rustOnly {
		logrus.Info("Switched to Rust-only mode")
	} else {
		logrus.Info("Switched to comparison mode (both engines)")
	}
}

// ProcessEvent processes events through both engines for comparison
func (e *HybridEngine) ProcessEvent(rawEvent json.RawMessage) error {
	e.mu.RLock()
	useRustOnly := e.useRustOnly
	e.mu.RUnlock()

	if useRustOnly {
		return e.processEventRustOnly(rawEvent)
	}

	return e.processEventComparison(rawEvent)
}

// processEventRustOnly processes event using only Rust engine
func (e *HybridEngine) processEventRustOnly(rawEvent json.RawMessage) error {
	start := time.Now()

	result, err := e.rustEngine.ProcessEvent(rawEvent)
	if err != nil {
		return fmt.Errorf("Rust engine error: %w", err)
	}

	processingTime := time.Since(start)

	// Update Rust statistics
	atomic.AddUint64(&e.rustStats.EventsProcessed, 1)
	e.updateAverageProcessingTime(&e.rustStats, processingTime)

	// Generate alerts if matches found
	if len(result.MatchedRules) > 0 {
		atomic.AddUint64(&e.rustStats.AlertsGenerated, uint64(len(result.MatchedRules)))
		e.generateAlertsFromRustResult(result, rawEvent)
	}

	return nil
}

// processEventComparison processes event through both engines for comparison
func (e *HybridEngine) processEventComparison(rawEvent json.RawMessage) error {
	var wg sync.WaitGroup
	var goErr, rustErr error
	var rustResult *RustEngineResult

	// Process with Go engine
	wg.Add(1)
	go func() {
		defer wg.Done()
		start := time.Now()
		goErr = e.goEngine.ProcessEvent(rawEvent)
		processingTime := time.Since(start)

		atomic.AddUint64(&e.goStats.EventsProcessed, 1)
		e.updateAverageProcessingTime(&e.goStats, processingTime)
	}()

	// Process with Rust engine
	wg.Add(1)
	go func() {
		defer wg.Done()
		start := time.Now()
		result, err := e.rustEngine.ProcessEvent(rawEvent)
		processingTime := time.Since(start)

		rustResult = result
		rustErr = err

		atomic.AddUint64(&e.rustStats.EventsProcessed, 1)
		e.updateAverageProcessingTime(&e.rustStats, processingTime)

		if result != nil && len(result.MatchedRules) > 0 {
			atomic.AddUint64(&e.rustStats.AlertsGenerated, uint64(len(result.MatchedRules)))
		}
	}()

	wg.Wait()

	// Log comparison results
	if rustResult != nil && len(rustResult.MatchedRules) > 0 {
		logrus.Debugf("Rust engine found %d matches for event", len(rustResult.MatchedRules))
		e.generateAlertsFromRustResult(rustResult, rawEvent)
	}

	// Return first error encountered
	if goErr != nil {
		return fmt.Errorf("Go engine error: %w", goErr)
	}
	if rustErr != nil {
		return fmt.Errorf("Rust engine error: %w", rustErr)
	}

	return nil
}

// generateAlertsFromRustResult creates alerts from Rust engine results
func (e *HybridEngine) generateAlertsFromRustResult(result *RustEngineResult, rawEvent json.RawMessage) {
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
				Title:       fmt.Sprintf("Rust Rule %d", ruleIndex),
				Description: fmt.Sprintf("Rule %d matched by Rust engine", ruleIndex),
				Level:       "medium",
				Tags:        []string{"rust-engine"},
			},
			Event:       eventData,
			Severity:    "medium",
			Description: fmt.Sprintf("Event matched rule %d (Rust engine)", ruleIndex),
			Tags:        []string{"rust-engine", "sigma-rule"},
		}

		e.addAlertToQueue(alert)
	}
}

// updateAverageProcessingTime updates the average processing time for an engine
func (e *HybridEngine) updateAverageProcessingTime(stats *EngineStats, processingTime time.Duration) {
	// Simple moving average - could be improved with more sophisticated averaging
	oldAvg := stats.AverageProcessingTime
	newCount := atomic.LoadUint64(&stats.EventsProcessed)

	if newCount == 1 {
		stats.AverageProcessingTime = processingTime
	} else {
		// Weighted average: (old_avg * (n-1) + new_time) / n
		stats.AverageProcessingTime = time.Duration(
			(int64(oldAvg)*int64(newCount-1) + int64(processingTime)) / int64(newCount),
		)
	}
}

// addAlertToQueue adds an alert to the processing queue
func (e *HybridEngine) addAlertToQueue(alert *Alert) {
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

// GetComparativeStats returns statistics comparing both engines
func (e *HybridEngine) GetComparativeStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	goEventsProcessed := atomic.LoadUint64(&e.goStats.EventsProcessed)
	rustEventsProcessed := atomic.LoadUint64(&e.rustStats.EventsProcessed)
	goAlertsGenerated := atomic.LoadUint64(&e.goStats.AlertsGenerated)
	rustAlertsGenerated := atomic.LoadUint64(&e.rustStats.AlertsGenerated)

	stats := map[string]interface{}{
		"uptime": time.Since(e.startTime).String(),
		"mode": func() string {
			if e.useRustOnly {
				return "rust-only"
			}
			return "comparison"
		}(),
		"go_engine": map[string]interface{}{
			"events_processed":    goEventsProcessed,
			"alerts_generated":    goAlertsGenerated,
			"avg_processing_time": e.goStats.AverageProcessingTime.String(),
		},
		"rust_engine": map[string]interface{}{
			"events_processed":    rustEventsProcessed,
			"alerts_generated":    rustAlertsGenerated,
			"avg_processing_time": e.rustStats.AverageProcessingTime.String(),
		},
		"performance_comparison": map[string]interface{}{
			"rust_faster_by": func() string {
				if e.goStats.AverageProcessingTime > 0 && e.rustStats.AverageProcessingTime > 0 {
					ratio := float64(e.goStats.AverageProcessingTime) / float64(e.rustStats.AverageProcessingTime)
					return fmt.Sprintf("%.2fx", ratio)
				}
				return "insufficient data"
			}(),
		},
	}

	return stats
}

// Start starts the hybrid engine
func (e *HybridEngine) Start(ctx context.Context) error {
	logrus.Info("Starting Hybrid Detection Engine...")

	// Start Go engine
	if err := e.goEngine.Start(ctx); err != nil {
		return fmt.Errorf("failed to start Go engine: %w", err)
	}

	// Start background workers
	e.wg.Add(2)
	go e.alertProcessor()
	go e.siemForwarder()

	logrus.Info("Hybrid Detection Engine started successfully")
	return nil
}

// Stop gracefully stops the hybrid engine
func (e *HybridEngine) Stop() error {
	logrus.Info("Stopping Hybrid Engine...")

	// Stop Go engine
	if err := e.goEngine.Stop(); err != nil {
		logrus.Errorf("Error stopping Go engine: %v", err)
	}

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

	logrus.Info("Hybrid Engine stopped")
	return nil
}

// alertProcessor processes alerts from the queue (similar to original engine)
func (e *HybridEngine) alertProcessor() {
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

// siemForwarder forwards alerts to SIEM (similar to original engine)
func (e *HybridEngine) siemForwarder() {
	defer e.wg.Done()

	// Implementation similar to original engine
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-time.After(time.Second * 10):
			// Batch forward alerts to SIEM
			// Implementation would be similar to original
		}
	}
}
