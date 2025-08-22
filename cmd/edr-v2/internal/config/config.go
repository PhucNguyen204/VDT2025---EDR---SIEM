package config

import (
	"flag"
	"log"
	"time"

	"github.com/VDT2025_PhucNguyen204/internal/engine"
	"github.com/sirupsen/logrus"
)

// AppConfig holds application configuration
type AppConfig struct {
	Port      string
	RulesDir  string
	LogLevel  string
	SiemURL   string
	BatchSize int
}

// ParseFlags parses command line flags and returns AppConfig
func ParseFlags() *AppConfig {
	config := &AppConfig{}

	flag.StringVar(&config.Port, "port", "8090", "HTTP server port")
	flag.StringVar(&config.RulesDir, "rules", "./sigma/rules", "Sigma rules directory")
	flag.StringVar(&config.LogLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	flag.StringVar(&config.SiemURL, "siem-url", "", "SIEM endpoint URL for forwarding alerts")
	flag.IntVar(&config.BatchSize, "batch-size", 100, "Alert batch size for SIEM forwarding")

	flag.Parse()
	return config
}

// SetupLogging configures logrus based on the log level
func SetupLogging(logLevel string) {
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		log.Fatalf("Invalid log level: %v", err)
	}

	logrus.SetLevel(level)
	logrus.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
	})
}

// ToEngineConfig converts AppConfig to engine.Config
func (c *AppConfig) ToEngineConfig() engine.Config {
	return engine.Config{
		RulesDirectory: []string{c.RulesDir},
		SIEMEndpoint:   c.SiemURL,
		BatchSize:      c.BatchSize,
	}
}
