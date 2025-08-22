package main

import (
	"github.com/VDT2025_PhucNguyen204/cmd/edr-v2/internal/app"
	"github.com/sirupsen/logrus"
)

func main() {
	// Create application
	edrApp, err := app.New()
	if err != nil {
		logrus.Fatalf("Failed to create EDR application: %v", err)
	}

	// Run application
	if err := edrApp.Run(); err != nil {
		logrus.Fatalf("Application error: %v", err)
	}
}
