package engine

/*
#cgo LDFLAGS: -L../../lib -lsigma_engine
#include "../../lib/sigma_engine.h"
#include <stdlib.h>

typedef struct {
    size_t* matched_rules_ptr;
    size_t matched_rules_len;
    size_t nodes_evaluated;
    size_t primitive_evaluations;
    int error_code;
} CEngineResult;

typedef void CSigmaEngine;

CSigmaEngine* sigma_engine_create(char** rules_ptr, size_t rules_len);
CEngineResult sigma_engine_evaluate(CSigmaEngine* engine_ptr, char* json_event);
void sigma_engine_free_result(size_t* matched_rules_ptr, size_t matched_rules_len);
void sigma_engine_destroy(CSigmaEngine* engine_ptr);
int sigma_engine_stats(CSigmaEngine* engine_ptr, size_t* rule_count, size_t* node_count, size_t* primitive_count);
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/sirupsen/logrus"
)

// RustSigmaEngine wraps the Rust sigma-engine via FFI
type RustSigmaEngine struct {
	engine    *C.CSigmaEngine
	mu        sync.RWMutex
	ruleYamls []string
	ruleCount uint64
	startTime time.Time

	// Statistics
	eventsProcessed uint64
	alertsGenerated uint64
}

// RustEngineResult represents the result from Rust engine evaluation
type RustEngineResult struct {
	MatchedRules         []int `json:"matched_rules"`
	NodesEvaluated       int   `json:"nodes_evaluated"`
	PrimitiveEvaluations int   `json:"primitive_evaluations"`
}

// NewRustSigmaEngine creates a new Rust-based sigma engine
func NewRustSigmaEngine(ruleYamls []string) (*RustSigmaEngine, error) {
	if len(ruleYamls) == 0 {
		return nil, fmt.Errorf("no rules provided")
	}

	// Convert Go strings to C strings
	cRules := make([]*C.char, len(ruleYamls))
	for i, rule := range ruleYamls {
		cRules[i] = C.CString(rule)
	}

	// Create the engine
	engine := C.sigma_engine_create((**C.char)(unsafe.Pointer(&cRules[0])), C.size_t(len(cRules)))

	// Free C strings
	for _, cRule := range cRules {
		C.free(unsafe.Pointer(cRule))
	}

	if engine == nil {
		return nil, fmt.Errorf("failed to create Rust sigma engine")
	}

	rustEngine := &RustSigmaEngine{
		engine:    engine,
		ruleYamls: ruleYamls,
		ruleCount: uint64(len(ruleYamls)),
		startTime: time.Now(),
	}

	logrus.Infof("Created Rust Sigma Engine with %d rules", len(ruleYamls))
	return rustEngine, nil
}

// ProcessEvent processes a single event through the Rust engine
func (e *RustSigmaEngine) ProcessEvent(rawEvent json.RawMessage) (*RustEngineResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Convert JSON to C string
	jsonStr := string(rawEvent)
	cJsonStr := C.CString(jsonStr)
	defer C.free(unsafe.Pointer(cJsonStr))

	// Call Rust engine
	result := C.sigma_engine_evaluate(e.engine, cJsonStr)

	if result.error_code != 0 {
		return nil, fmt.Errorf("Rust engine evaluation failed with error code: %d", result.error_code)
	}

	// Convert result
	rustResult := &RustEngineResult{
		NodesEvaluated:       int(result.nodes_evaluated),
		PrimitiveEvaluations: int(result.primitive_evaluations),
	}

	// Convert matched rules if any
	if result.matched_rules_ptr != nil && result.matched_rules_len > 0 {
		// Convert C array to Go slice
		matchedRules := (*[1 << 30]C.size_t)(unsafe.Pointer(result.matched_rules_ptr))[:result.matched_rules_len:result.matched_rules_len]

		rustResult.MatchedRules = make([]int, result.matched_rules_len)
		for i, rule := range matchedRules {
			rustResult.MatchedRules[i] = int(rule)
		}

		// Free the result
		C.sigma_engine_free_result(result.matched_rules_ptr, result.matched_rules_len)
	}

	// Update statistics
	atomic.AddUint64(&e.eventsProcessed, 1)
	if len(rustResult.MatchedRules) > 0 {
		atomic.AddUint64(&e.alertsGenerated, uint64(len(rustResult.MatchedRules)))
	}

	return rustResult, nil
}

// GetStats returns engine statistics
func (e *RustSigmaEngine) GetStats() (*Stats, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var ruleCount, nodeCount, primitiveCount C.size_t
	errorCode := C.sigma_engine_stats(e.engine, &ruleCount, &nodeCount, &primitiveCount)

	if errorCode != 0 {
		return nil, fmt.Errorf("failed to get engine stats, error code: %d", errorCode)
	}

	uptime := time.Since(e.startTime)

	return &Stats{
		EventsProcessed: atomic.LoadUint64(&e.eventsProcessed),
		AlertsGenerated: atomic.LoadUint64(&e.alertsGenerated),
		RulesLoaded:     uint64(ruleCount),
		Uptime:          uptime.String(),
	}, nil
}

// GetRuleCount returns the number of loaded rules
func (e *RustSigmaEngine) GetRuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var ruleCount, nodeCount, primitiveCount C.size_t
	C.sigma_engine_stats(e.engine, &ruleCount, &nodeCount, &primitiveCount)

	return int(ruleCount)
}

// Close properly shuts down the engine and frees memory
func (e *RustSigmaEngine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.engine != nil {
		C.sigma_engine_destroy(e.engine)
		e.engine = nil
		logrus.Info("Rust Sigma Engine destroyed")
	}

	return nil
}

// ProcessEventsBatch processes multiple events efficiently using Rust batch processing
func (e *RustSigmaEngine) ProcessEventsBatch(events []json.RawMessage) ([]*RustEngineResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	results := make([]*RustEngineResult, len(events))

	// For now, process individually - we can optimize later with true Rust batch API
	for i, event := range events {
		result, err := e.ProcessEvent(event)
		if err != nil {
			return nil, fmt.Errorf("failed to process event %d: %w", i, err)
		}
		results[i] = result
	}

	return results, nil
}
