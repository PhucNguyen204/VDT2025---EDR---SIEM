package engine

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRustEngineIntegration tests the basic Rust engine functionality
func TestRustEngineIntegration(t *testing.T) {
	ruleYamls := []string{
		`title: Test Authentication Rule
logsource:
    category: authentication
detection:
    selection:
        EventID: 4624
        LogonType: 2
    condition: selection`,
		`title: Test Process Rule
detection:
    selection:
        ProcessName|endswith: "powershell.exe"
    condition: selection`,
	}

	rustEngine, err := NewRustSigmaEngine(ruleYamls)
	require.NoError(t, err)
	defer rustEngine.Close()

	t.Run("BasicEventProcessing", func(t *testing.T) {
		// Test matching event
		event := json.RawMessage(`{
			"EventID": "4624",
			"LogonType": 2,
			"TargetUserName": "admin"
		}`)

		result, err := rustEngine.ProcessEvent(event)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Greater(t, result.NodesEvaluated, 0)

		t.Logf("Processed event: %d nodes evaluated, %d primitive evaluations",
			result.NodesEvaluated, result.PrimitiveEvaluations)
	})

	t.Run("NonMatchingEvent", func(t *testing.T) {
		// Test non-matching event
		event := json.RawMessage(`{
			"EventID": "1234",
			"SomeField": "value"
		}`)

		result, err := rustEngine.ProcessEvent(event)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, 0, len(result.MatchedRules))
	})

	t.Run("BatchProcessing", func(t *testing.T) {
		events := []json.RawMessage{
			json.RawMessage(`{"EventID": "4624", "LogonType": 2}`),
			json.RawMessage(`{"ProcessName": "powershell.exe"}`),
			json.RawMessage(`{"EventID": "1234"}`),
		}

		results, err := rustEngine.ProcessEventsBatch(events)
		require.NoError(t, err)
		assert.Len(t, results, 3)

		// At least first two events should trigger some processing
		assert.Greater(t, results[0].NodesEvaluated, 0)
		assert.Greater(t, results[1].NodesEvaluated, 0)
	})

	t.Run("EngineStats", func(t *testing.T) {
		stats, err := rustEngine.GetStats()
		require.NoError(t, err)
		assert.NotNil(t, stats)
		assert.Greater(t, stats.EventsProcessed, uint64(0))
		assert.Equal(t, uint64(2), stats.RulesLoaded) // We loaded 2 rules

		t.Logf("Engine stats: %+v", stats)
	})
}

// TestHybridEngineIntegration tests the hybrid engine functionality
func TestHybridEngineIntegration(t *testing.T) {
	config := Config{
		RulesDirectory: []string{"../../sigma/rules"},
		SIEMEndpoint:   "http://localhost:9200",
		BatchSize:      100,
	}

	ruleYamls := []string{
		`title: Integration Test Rule
detection:
    selection:
        EventID: 4624
    condition: selection`,
	}

	hybridEngine, err := NewHybridEngine(config, ruleYamls)
	require.NoError(t, err)
	defer hybridEngine.Stop()

	t.Run("ComparisonMode", func(t *testing.T) {
		// Set to comparison mode
		hybridEngine.SetRustOnly(false)

		event := json.RawMessage(`{
			"EventID": "4624",
			"LogonType": 2,
			"TargetUserName": "testuser"
		}`)

		err := hybridEngine.ProcessEvent(event)
		require.NoError(t, err)

		// Get comparative stats
		stats := hybridEngine.GetComparativeStats()
		assert.Equal(t, "comparison", stats["mode"])

		goStats := stats["go_engine"].(map[string]interface{})
		rustStats := stats["rust_engine"].(map[string]interface{})

		// Both engines should have processed the event
		assert.Greater(t, goStats["events_processed"], uint64(0))
		assert.Greater(t, rustStats["events_processed"], uint64(0))

		t.Logf("Comparison stats: %+v", stats)
	})

	t.Run("RustOnlyMode", func(t *testing.T) {
		// Switch to Rust-only mode
		hybridEngine.SetRustOnly(true)

		event := json.RawMessage(`{
			"EventID": "4624",
			"LogonType": 3,
			"TargetUserName": "rustuser"
		}`)

		err := hybridEngine.ProcessEvent(event)
		require.NoError(t, err)

		// Get stats
		stats := hybridEngine.GetComparativeStats()
		assert.Equal(t, "rust-only", stats["mode"])

		t.Logf("Rust-only stats: %+v", stats)
	})

	t.Run("EngineLifecycle", func(t *testing.T) {
		// Test engine start/stop lifecycle
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		err := hybridEngine.Start(ctx)
		require.NoError(t, err)

		// Process some events
		for i := 0; i < 5; i++ {
			event := json.RawMessage(`{"EventID": "4624", "Index": ` + string(rune(i+'0')) + `}`)
			err := hybridEngine.ProcessEvent(event)
			require.NoError(t, err)
		}

		// Stop the engine
		err = hybridEngine.Stop()
		require.NoError(t, err)
	})
}

// TestFFIIntegration tests the FFI layer between Go and Rust
func TestFFIIntegration(t *testing.T) {
	ruleYamls := []string{
		`title: FFI Test Rule
detection:
    selection:
        TestField: "test_value"
    condition: selection`,
	}

	t.Run("EngineCreation", func(t *testing.T) {
		rustEngine, err := NewRustSigmaEngine(ruleYamls)
		require.NoError(t, err)
		assert.NotNil(t, rustEngine)

		// Test rule count
		ruleCount := rustEngine.GetRuleCount()
		assert.Equal(t, 1, ruleCount)

		err = rustEngine.Close()
		require.NoError(t, err)
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		rustEngine, err := NewRustSigmaEngine(ruleYamls)
		require.NoError(t, err)
		defer rustEngine.Close()

		// Test with invalid JSON
		invalidJSON := json.RawMessage(`{"invalid": json"}`)
		_, err = rustEngine.ProcessEvent(invalidJSON)
		assert.Error(t, err)
	})

	t.Run("EmptyEvent", func(t *testing.T) {
		rustEngine, err := NewRustSigmaEngine(ruleYamls)
		require.NoError(t, err)
		defer rustEngine.Close()

		// Test with empty event
		emptyEvent := json.RawMessage(`{}`)
		result, err := rustEngine.ProcessEvent(emptyEvent)
		require.NoError(t, err)
		assert.Equal(t, 0, len(result.MatchedRules))
	})

	t.Run("LargeEvent", func(t *testing.T) {
		rustEngine, err := NewRustSigmaEngine(ruleYamls)
		require.NoError(t, err)
		defer rustEngine.Close()

		// Test with large event
		largeEvent := json.RawMessage(`{
			"TestField": "test_value",
			"LargeField": "` + string(make([]byte, 1000)) + `",
			"NestedObject": {
				"Field1": "value1",
				"Field2": "value2",
				"Array": [1, 2, 3, 4, 5]
			}
		}`)

		result, err := rustEngine.ProcessEvent(largeEvent)
		require.NoError(t, err)
		assert.Greater(t, result.NodesEvaluated, 0)
	})
}

// TestMemoryLeaks tests for memory leaks in FFI operations
func TestMemoryLeaks(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory leak test in short mode")
	}

	ruleYamls := []string{
		`title: Memory Test Rule
detection:
    selection:
        EventID: 4624
    condition: selection`,
	}

	t.Run("MultipleEngineCreation", func(t *testing.T) {
		// Create and destroy multiple engines
		for i := 0; i < 100; i++ {
			rustEngine, err := NewRustSigmaEngine(ruleYamls)
			require.NoError(t, err)

			// Process a few events
			for j := 0; j < 10; j++ {
				event := json.RawMessage(`{"EventID": "4624", "Index": ` + string(rune(j+'0')) + `}`)
				_, err := rustEngine.ProcessEvent(event)
				require.NoError(t, err)
			}

			err = rustEngine.Close()
			require.NoError(t, err)

			if i%10 == 0 {
				t.Logf("Created and destroyed %d engines", i+1)
			}
		}
	})

	t.Run("ManyEvents", func(t *testing.T) {
		rustEngine, err := NewRustSigmaEngine(ruleYamls)
		require.NoError(t, err)
		defer rustEngine.Close()

		// Process many events
		for i := 0; i < 1000; i++ {
			event := json.RawMessage(`{"EventID": "4624", "Counter": ` + string(rune(i%10+'0')) + `}`)
			_, err := rustEngine.ProcessEvent(event)
			require.NoError(t, err)

			if i%100 == 0 {
				t.Logf("Processed %d events", i+1)
			}
		}

		// Get final stats
		stats, err := rustEngine.GetStats()
		require.NoError(t, err)
		assert.Equal(t, uint64(1000), stats.EventsProcessed)
	})
}

// TestConcurrency tests concurrent access to the engines
func TestConcurrency(t *testing.T) {
	ruleYamls := []string{
		`title: Concurrency Test Rule
detection:
    selection:
        EventID: 4624
    condition: selection`,
	}

	rustEngine, err := NewRustSigmaEngine(ruleYamls)
	require.NoError(t, err)
	defer rustEngine.Close()

	t.Run("ConcurrentEventProcessing", func(t *testing.T) {
		const numGoroutines = 10
		const eventsPerGoroutine = 100

		done := make(chan bool, numGoroutines)

		// Start multiple goroutines processing events
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer func() { done <- true }()

				for j := 0; j < eventsPerGoroutine; j++ {
					event := json.RawMessage(`{"EventID": "4624", "GoID": ` + string(rune(id+'0')) + `, "EventNum": ` + string(rune(j%10+'0')) + `}`)
					_, err := rustEngine.ProcessEvent(event)
					assert.NoError(t, err)
				}
			}(i)
		}

		// Wait for all goroutines to complete
		for i := 0; i < numGoroutines; i++ {
			select {
			case <-done:
				// Goroutine completed successfully
			case <-time.After(30 * time.Second):
				t.Fatal("Timeout waiting for goroutines to complete")
			}
		}

		// Verify total events processed
		stats, err := rustEngine.GetStats()
		require.NoError(t, err)
		assert.Equal(t, uint64(numGoroutines*eventsPerGoroutine), stats.EventsProcessed)

		t.Logf("Successfully processed %d events concurrently", numGoroutines*eventsPerGoroutine)
	})
}

// TestErrorHandling tests error handling in various scenarios
func TestErrorHandling(t *testing.T) {
	t.Run("InvalidRules", func(t *testing.T) {
		invalidRules := []string{
			`invalid yaml content [[[`,
			`title: Incomplete Rule
detection:`,
		}

		_, err := NewRustSigmaEngine(invalidRules)
		assert.Error(t, err)
	})

	t.Run("EmptyRules", func(t *testing.T) {
		emptyRules := []string{}

		_, err := NewRustSigmaEngine(emptyRules)
		assert.Error(t, err)
	})

	t.Run("ProcessingAfterClose", func(t *testing.T) {
		ruleYamls := []string{
			`title: Test Rule
detection:
    selection:
        EventID: 4624
    condition: selection`,
		}

		rustEngine, err := NewRustSigmaEngine(ruleYamls)
		require.NoError(t, err)

		// Close the engine
		err = rustEngine.Close()
		require.NoError(t, err)

		// Try to process event after close
		event := json.RawMessage(`{"EventID": "4624"}`)
		_, err = rustEngine.ProcessEvent(event)
		assert.Error(t, err)
	})
}
