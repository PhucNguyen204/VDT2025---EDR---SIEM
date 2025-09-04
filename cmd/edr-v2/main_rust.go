package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/VDT2025_PhucNguyen204/cmd/edr-v2/internal/config"
	"github.com/VDT2025_PhucNguyen204/cmd/edr-v2/internal/server"
	"github.com/VDT2025_PhucNguyen204/internal/engine"
	"github.com/sirupsen/logrus"
)

func main() {
	// Initialize configuration
	cfg := config.ParseFlags()

	// Set up logging
	config.SetupLogging(cfg.LogLevel)

	logrus.Info("Starting EDR v2 with Rust Sigma Engine...")

	// Load Sigma rules from directory
	ruleYamls, err := loadSigmaRules(cfg.RulesDir)
	if err != nil {
		logrus.Fatalf("Failed to load Sigma rules: %v", err)
	}

	logrus.Infof("Loaded %d Sigma rules from %s", len(ruleYamls), cfg.RulesDir)

	// Create engine configuration
	engineConfig := engine.Config{
		RulesDirectory: []string{cfg.RulesDir},
		SIEMEndpoint:   cfg.SiemURL,
		BatchSize:      cfg.BatchSize,
	}

	// Create Rust-only engine
	rustEngine, err := engine.NewEngine(engineConfig, ruleYamls)
	if err != nil {
		logrus.Fatalf("Failed to create Rust engine: %v", err)
	}

	// Convert port to int
	var port int
	fmt.Sscanf(cfg.Port, "%d", &port)

	// Create HTTP server
	httpServer := server.NewServer(cfg, rustEngine)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the Rust engine
	if err := rustEngine.Start(ctx); err != nil {
		logrus.Fatalf("Failed to start Rust engine: %v", err)
	}

	// Start HTTP server in a goroutine
	go func() {
		logrus.Infof("Starting HTTP server on port %d", port)
		if err := httpServer.Start(); err != nil && err != http.ErrServerClosed {
			logrus.Fatalf("HTTP server failed: %v", err)
		}
	}()

	// Add endpoint to get engine statistics
	http.HandleFunc("/api/engine/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		stats, err := rustEngine.GetStats()
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get stats: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"engine_type": "rust-sigma-engine",
			"stats":       stats,
			"rule_count":  rustEngine.GetRuleCount(),
		})
	})

	// Wait for interrupt signal for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	logrus.Info("🚀 EDR v2 with Rust Sigma Engine is running...")
	logrus.Info("📊 API Endpoints:")
	logrus.Infof("  - Health Check: http://localhost:%d/health", port)
	logrus.Infof("  - Stats: http://localhost:%d/api/stats", port)
	logrus.Infof("  - Engine Stats: http://localhost:%d/api/engine/stats", port)

	<-quit
	logrus.Info("Shutting down EDR v2...")

	// Stop HTTP server
	if err := httpServer.Stop(); err != nil {
		logrus.Errorf("HTTP server shutdown error: %v", err)
	}

	// Stop Rust engine
	if err := rustEngine.Stop(); err != nil {
		logrus.Errorf("Rust engine shutdown error: %v", err)
	}

	logrus.Info("EDR v2 stopped gracefully")
}

// loadSigmaRules loads all YAML rule files from the specified directory
func loadSigmaRules(rulesDir string) ([]string, error) {
	var ruleYamls []string

	err := filepath.Walk(rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Process .yml and .yaml files
		if !info.IsDir() && (filepath.Ext(path) == ".yml" || filepath.Ext(path) == ".yaml") {
			content, err := os.ReadFile(path)
			if err != nil {
				logrus.Warnf("Failed to read rule file %s: %v", path, err)
				return nil // Continue processing other files
			}

			ruleYamls = append(ruleYamls, string(content))
			logrus.Debugf("Loaded rule file: %s", path)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk rules directory: %w", err)
	}

	if len(ruleYamls) == 0 {
		return nil, fmt.Errorf("no YAML rule files found in directory: %s", rulesDir)
	}

	return ruleYamls, nil
}
