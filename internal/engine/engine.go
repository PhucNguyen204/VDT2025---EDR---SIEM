package engine

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
)

// NewEngine creates a new detection engine instance
func NewEngine(config Config) (*Engine, error) {
	ctx, cancel := context.WithCancel(context.Background())

	engine := &Engine{
		config:     config,
		ctx:        ctx,
		cancel:     cancel,
		alertQueue: make(chan *Alert, 1000),
		startTime:  time.Now(),
	}

	// Load Sigma rules
	if err := engine.loadRules(); err != nil {
		cancel()
		return nil, err
	}

	return engine, nil
}

// Start starts the detection engine
func (e *Engine) Start(ctx context.Context) error {
	logrus.Info("Starting EDR Detection Engine...")

	// Start background workers
	e.wg.Add(2)
	go e.alertProcessor()
	go e.siemForwarder()

	logrus.Info("EDR Detection Engine started successfully")
	return nil
}

// Stop gracefully stops the detection engine
func (e *Engine) Stop() error {
	logrus.Info("Stopping EDR Engine...")

	// Cancel context to signal shutdown
	e.cancel()

	// Close alert queue
	close(e.alertQueue)

	// Wait for workers to finish
	e.wg.Wait()

	logrus.Info("EDR Engine stopped")
	return nil
}
