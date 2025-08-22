package engine

import (
	"context"
	"sync"
	"time"

	"github.com/markuskont/go-sigma-rule-engine"
)

// Config holds engine configuration
type Config struct {
	RulesDirectory []string
	SIEMEndpoint   string
	BatchSize      int
}

// Engine is the main EDR detection engine
type Engine struct {
	config    Config
	ruleset   *sigma.Ruleset
	mu        sync.RWMutex
	startTime time.Time

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
}

// RuleInfo contains metadata about a Sigma rule
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
