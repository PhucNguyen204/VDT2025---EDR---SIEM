package app

import (
	"context"

	"github.com/VDT2025_PhucNguyen204/cmd/edr-v2/internal/config"
	"github.com/VDT2025_PhucNguyen204/cmd/edr-v2/internal/server"
	"github.com/VDT2025_PhucNguyen204/internal/engine"
	"github.com/sirupsen/logrus"
)

// App represents the EDR application
type App struct {
	config *config.AppConfig
	engine *engine.Engine
	server *server.Server
}

// New creates a new EDR application
func New() (*App, error) {
	// Parse configuration
	cfg := config.ParseFlags()

	// Setup logging
	config.SetupLogging(cfg.LogLevel)

	// Create EDR engine
	edrEngine, err := createEngine(cfg)
	if err != nil {
		return nil, err
	}

	// Create server
	srv := server.NewServer(cfg, edrEngine)

	return &App{
		config: cfg,
		engine: edrEngine,
		server: srv,
	}, nil
}

// Run starts the application
func (app *App) Run() error {
	// Start engine
	if err := app.startEngine(); err != nil {
		return err
	}

	// Run server (blocks until shutdown)
	return app.server.Run()
}

// createEngine creates and configures the EDR engine
func createEngine(cfg *config.AppConfig) (*engine.Engine, error) {
	engineConfig := cfg.ToEngineConfig()

	edrEngine, err := engine.NewEngine(engineConfig)
	if err != nil {
		return nil, err
	}

	return edrEngine, nil
}

// startEngine starts the EDR engine with background workers
func (app *App) startEngine() error {
	ctx := context.Background()

	if err := app.engine.Start(ctx); err != nil {
		return err
	}

	logrus.Info("EDR engine started successfully")
	return nil
}
