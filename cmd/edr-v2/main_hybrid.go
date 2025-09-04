package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/VDT2025_PhucNguyen204/cmd/edr-v2/internal/app"
	"github.com/VDT2025_PhucNguyen204/cmd/edr-v2/internal/config"
	"github.com/VDT2025_PhucNguyen204/cmd/edr-v2/internal/server"
	"github.com/VDT2025_PhucNguyen204/internal/engine"
	"github.com/sirupsen/logrus"
)

func main() {
	// Initialize configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Set log level
	logLevel, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		logrus.Warnf("Invalid log level '%s', using 'info'", cfg.LogLevel)
		logLevel = logrus.InfoLevel
	}
	logrus.SetLevel(logLevel)

	logrus.Info("Starting EDR v2 with Hybrid Engine (Go + Rust)...")

	// Load Sigma rules from directory
	ruleYamls, err := loadSigmaRules(cfg.RulesDir)
	if err != nil {
		logrus.Fatalf("Failed to load Sigma rules: %v", err)
	}

	logrus.Infof("Loaded %d Sigma rules from %s", len(ruleYamls), cfg.RulesDir)

	// Create engine configuration
	engineConfig := engine.Config{
		RulesDirectory: []string{cfg.RulesDir},
		SIEMEndpoint:   cfg.SIEMEndpoint,
		BatchSize:      100,
	}

	// Create hybrid engine (Go + Rust)
	hybridEngine, err := engine.NewHybridEngine(engineConfig, ruleYamls)
	if err != nil {
		logrus.Fatalf("Failed to create hybrid engine: %v", err)
	}

	// Create application with hybrid engine
	application := app.NewApp(hybridEngine)

	// Create HTTP server
	httpServer := server.NewServer(cfg.Port, application)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the hybrid engine
	if err := hybridEngine.Start(ctx); err != nil {
		logrus.Fatalf("Failed to start hybrid engine: %v", err)
	}

	// Start HTTP server in a goroutine
	go func() {
		logrus.Infof("Starting HTTP server on port %d", cfg.Port)
		if err := httpServer.Start(); err != nil && err != http.ErrServerClosed {
			logrus.Fatalf("HTTP server failed: %v", err)
		}
	}()

	// Add endpoint to switch between Go and Rust engines
	http.HandleFunc("/api/engine/mode", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// Get current mode and statistics
			stats := hybridEngine.GetComparativeStats()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(stats)

		case http.MethodPost:
			// Switch engine mode
			var req struct {
				UseRustOnly bool `json:"use_rust_only"`
			}

			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid JSON", http.StatusBadRequest)
				return
			}

			hybridEngine.SetRustOnly(req.UseRustOnly)

			response := map[string]interface{}{
				"success": true,
				"mode": func() string {
					if req.UseRustOnly {
						return "rust-only"
					}
					return "comparison"
				}(),
				"message": fmt.Sprintf("Switched to %s mode", func() string {
					if req.UseRustOnly {
						return "Rust-only"
					}
					return "comparison"
				}()),
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Wait for interrupt signal for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	logrus.Info("🚀 EDR v2 Hybrid Engine is running...")
	logrus.Info("📊 API Endpoints:")
	logrus.Infof("  - Health Check: http://localhost:%d/health", cfg.Port)
	logrus.Infof("  - Stats: http://localhost:%d/api/stats", cfg.Port)
	logrus.Infof("  - Engine Mode: http://localhost:%d/api/engine/mode", cfg.Port)
	logrus.Info("💡 Use POST /api/engine/mode with {\"use_rust_only\": true} to switch to Rust-only mode")

	<-quit
	logrus.Info("Shutting down EDR v2...")

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Stop HTTP server
	if err := httpServer.Stop(shutdownCtx); err != nil {
		logrus.Errorf("HTTP server shutdown error: %v", err)
	}

	// Stop hybrid engine
	if err := hybridEngine.Stop(); err != nil {
		logrus.Errorf("Hybrid engine shutdown error: %v", err)
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
