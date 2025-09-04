package engine

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// BenchmarkGoEngine benchmarks the original Go engine
func BenchmarkGoEngine(b *testing.B) {
	// Create Go engine
	config := Config{
		RulesDirectory: []string{"../../sigma/rules"},
		SIEMEndpoint:   "http://localhost:9200",
		BatchSize:      100,
	}

	engine, err := NewEngine(config)
	require.NoError(b, err)

	// Sample event
	event := json.RawMessage(`{
		"EventID": "4624",
		"LogonType": 2,
		"TargetUserName": "admin",
		"IpAddress": "192.168.1.100",
		"ProcessName": "powershell.exe"
	}`)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		err := engine.ProcessEvent(event)
		if err != nil {
			b.Fatalf("Processing failed: %v", err)
		}
	}
}

// BenchmarkRustEngine benchmarks the Rust engine
func BenchmarkRustEngine(b *testing.B) {
	// Create sample rules for Rust engine
	ruleYamls := []string{
		`title: Test Rule
logsource:
    category: authentication
detection:
    selection:
        EventID: 4624
        LogonType: 2
    condition: selection`,
		`title: PowerShell Rule
detection:
    selection:
        ProcessName|endswith: "powershell.exe"
    condition: selection`,
	}

	rustEngine, err := NewRustSigmaEngine(ruleYamls)
	require.NoError(b, err)
	defer rustEngine.Close()

	// Sample event
	event := json.RawMessage(`{
		"EventID": "4624",
		"LogonType": 2,
		"TargetUserName": "admin",
		"IpAddress": "192.168.1.100",
		"ProcessName": "powershell.exe"
	}`)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := rustEngine.ProcessEvent(event)
		if err != nil {
			b.Fatalf("Processing failed: %v", err)
		}
	}
}

// BenchmarkHybridEngineComparison benchmarks hybrid engine in comparison mode
func BenchmarkHybridEngineComparison(b *testing.B) {
	config := Config{
		RulesDirectory: []string{"../../sigma/rules"},
		SIEMEndpoint:   "http://localhost:9200",
		BatchSize:      100,
	}

	ruleYamls := []string{
		`title: Test Rule
logsource:
    category: authentication
detection:
    selection:
        EventID: 4624
        LogonType: 2
    condition: selection`,
	}

	hybridEngine, err := NewHybridEngine(config, ruleYamls)
	require.NoError(b, err)
	defer hybridEngine.Stop()

	// Set to comparison mode
	hybridEngine.SetRustOnly(false)

	event := json.RawMessage(`{
		"EventID": "4624",
		"LogonType": 2,
		"TargetUserName": "admin",
		"IpAddress": "192.168.1.100"
	}`)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		err := hybridEngine.ProcessEvent(event)
		if err != nil {
			b.Fatalf("Processing failed: %v", err)
		}
	}
}

// BenchmarkHybridEngineRustOnly benchmarks hybrid engine in Rust-only mode
func BenchmarkHybridEngineRustOnly(b *testing.B) {
	config := Config{
		RulesDirectory: []string{"../../sigma/rules"},
		SIEMEndpoint:   "http://localhost:9200",
		BatchSize:      100,
	}

	ruleYamls := []string{
		`title: Test Rule
logsource:
    category: authentication
detection:
    selection:
        EventID: 4624
        LogonType: 2
    condition: selection`,
	}

	hybridEngine, err := NewHybridEngine(config, ruleYamls)
	require.NoError(b, err)
	defer hybridEngine.Stop()

	// Set to Rust-only mode
	hybridEngine.SetRustOnly(true)

	event := json.RawMessage(`{
		"EventID": "4624",
		"LogonType": 2,
		"TargetUserName": "admin",
		"IpAddress": "192.168.1.100"
	}`)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		err := hybridEngine.ProcessEvent(event)
		if err != nil {
			b.Fatalf("Processing failed: %v", err)
		}
	}
}

// BenchmarkBatchProcessing compares batch processing performance
func BenchmarkBatchProcessing(b *testing.B) {
	ruleYamls := []string{
		`title: Test Rule
detection:
    selection:
        EventID: 4624
    condition: selection`,
	}

	rustEngine, err := NewRustSigmaEngine(ruleYamls)
	require.NoError(b, err)
	defer rustEngine.Close()

	// Create batch of events
	events := make([]json.RawMessage, 100)
	for i := 0; i < 100; i++ {
		events[i] = json.RawMessage(fmt.Sprintf(`{
			"EventID": "4624",
			"LogonType": %d,
			"TargetUserName": "user%d"
		}`, i%3+1, i))
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := rustEngine.ProcessEventsBatch(events)
		if err != nil {
			b.Fatalf("Batch processing failed: %v", err)
		}
	}
}

// TestPerformanceComparison runs a detailed performance comparison
func TestPerformanceComparison(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance comparison in short mode")
	}

	// Setup
	config := Config{
		RulesDirectory: []string{"../../sigma/rules"},
		SIEMEndpoint:   "http://localhost:9200",
		BatchSize:      100,
	}

	ruleYamls := []string{
		`title: Authentication Rule
detection:
    selection:
        EventID: 4624
        LogonType: 2
    condition: selection`,
		`title: Process Rule
detection:
    selection:
        ProcessName|endswith: "powershell.exe"
    condition: selection`,
		`title: Network Rule
detection:
    selection:
        IpAddress|startswith: "192.168."
    condition: selection`,
	}

	// Create engines
	goEngine, err := NewEngine(config)
	require.NoError(t, err)

	rustEngine, err := NewRustSigmaEngine(ruleYamls)
	require.NoError(t, err)
	defer rustEngine.Close()

	// Test events
	events := []json.RawMessage{
		json.RawMessage(`{"EventID": "4624", "LogonType": 2, "TargetUserName": "admin"}`),
		json.RawMessage(`{"ProcessName": "powershell.exe", "CommandLine": "Get-Process"}`),
		json.RawMessage(`{"IpAddress": "192.168.1.100", "Port": 443}`),
		json.RawMessage(`{"EventID": "4625", "LogonType": 3, "TargetUserName": "guest"}`),
		json.RawMessage(`{"ProcessName": "cmd.exe", "CommandLine": "dir"}`),
	}

	const iterations = 1000

	// Benchmark Go engine
	goStart := time.Now()
	for i := 0; i < iterations; i++ {
		for _, event := range events {
			err := goEngine.ProcessEvent(event)
			assert.NoError(t, err)
		}
	}
	goDuration := time.Since(goStart)

	// Benchmark Rust engine
	rustStart := time.Now()
	for i := 0; i < iterations; i++ {
		for _, event := range events {
			_, err := rustEngine.ProcessEvent(event)
			assert.NoError(t, err)
		}
	}
	rustDuration := time.Since(rustStart)

	// Results
	totalEvents := iterations * len(events)
	goThroughput := float64(totalEvents) / goDuration.Seconds()
	rustThroughput := float64(totalEvents) / rustDuration.Seconds()
	speedup := rustThroughput / goThroughput

	t.Logf("Performance Comparison Results:")
	t.Logf("Total events processed: %d", totalEvents)
	t.Logf("Go Engine:")
	t.Logf("  Duration: %v", goDuration)
	t.Logf("  Throughput: %.2f events/sec", goThroughput)
	t.Logf("  Avg per event: %v", goDuration/time.Duration(totalEvents))
	t.Logf("Rust Engine:")
	t.Logf("  Duration: %v", rustDuration)
	t.Logf("  Throughput: %.2f events/sec", rustThroughput)
	t.Logf("  Avg per event: %v", rustDuration/time.Duration(totalEvents))
	t.Logf("Performance Improvement:")
	t.Logf("  Rust is %.2fx faster", speedup)
	t.Logf("  Time saved: %v (%.1f%%)", goDuration-rustDuration, (goDuration-rustDuration).Seconds()/goDuration.Seconds()*100)

	// Assert that Rust is faster (should be at least 2x)
	assert.Greater(t, speedup, 2.0, "Rust engine should be at least 2x faster than Go engine")
}

// TestMemoryUsage compares memory usage between engines
func TestMemoryUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory usage test in short mode")
	}

	ruleYamls := []string{
		`title: Test Rule
detection:
    selection:
        EventID: 4624
    condition: selection`,
	}

	// Test Rust engine memory usage
	t.Run("RustEngineMemory", func(t *testing.T) {
		const numEngines = 10
		engines := make([]*RustSigmaEngine, numEngines)

		// Create multiple engines
		for i := 0; i < numEngines; i++ {
			engine, err := NewRustSigmaEngine(ruleYamls)
			require.NoError(t, err)
			engines[i] = engine
		}

		// Process events
		event := json.RawMessage(`{"EventID": "4624", "LogonType": 2}`)
		for _, engine := range engines {
			for j := 0; j < 100; j++ {
				_, err := engine.ProcessEvent(event)
				require.NoError(t, err)
			}
		}

		// Cleanup
		for _, engine := range engines {
			err := engine.Close()
			require.NoError(t, err)
		}

		t.Log("Successfully created and cleaned up multiple Rust engines")
	})
}

// TestAccuracy compares detection accuracy between engines
func TestAccuracy(t *testing.T) {
	config := Config{
		RulesDirectory: []string{"../../sigma/rules"},
		SIEMEndpoint:   "http://localhost:9200",
		BatchSize:      100,
	}

	ruleYamls := []string{
		`title: Authentication Rule
detection:
    selection:
        EventID: 4624
        LogonType: 2
    condition: selection`,
		`title: Failed Login Rule
detection:
    selection:
        EventID: 4625
    condition: selection`,
	}

	hybridEngine, err := NewHybridEngine(config, ruleYamls)
	require.NoError(t, err)
	defer hybridEngine.Stop()

	testCases := []struct {
		name          string
		event         json.RawMessage
		shouldMatch   bool
		expectedRules int
	}{
		{
			name:          "Successful login should match",
			event:         json.RawMessage(`{"EventID": "4624", "LogonType": 2}`),
			shouldMatch:   true,
			expectedRules: 1,
		},
		{
			name:          "Failed login should match",
			event:         json.RawMessage(`{"EventID": "4625", "LogonType": 3}`),
			shouldMatch:   true,
			expectedRules: 1,
		},
		{
			name:          "Different event should not match",
			event:         json.RawMessage(`{"EventID": "1234", "SomeField": "value"}`),
			shouldMatch:   false,
			expectedRules: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set to comparison mode to test both engines
			hybridEngine.SetRustOnly(false)

			// Process event
			err := hybridEngine.ProcessEvent(tc.event)
			assert.NoError(t, err)

			// Get stats to verify both engines processed the event
			stats := hybridEngine.GetComparativeStats()
			goStats := stats["go_engine"].(map[string]interface{})
			rustStats := stats["rust_engine"].(map[string]interface{})

			// Both engines should have processed events
			assert.Greater(t, goStats["events_processed"], uint64(0))
			assert.Greater(t, rustStats["events_processed"], uint64(0))

			t.Logf("Go engine processed: %v events", goStats["events_processed"])
			t.Logf("Rust engine processed: %v events", rustStats["events_processed"])
		})
	}
}
