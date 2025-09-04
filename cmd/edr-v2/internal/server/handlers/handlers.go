package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/VDT2025_PhucNguyen204/internal/engine"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// Health returns health status of the EDR engine
func Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"version":   "2.0.0",
		"service":   "EDR Detection Engine",
	})
}

// Events processes incoming security events
func Events(engine *engine.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Read raw body first
		body, err := c.GetRawData()
		if err != nil {
			logrus.Errorf("Failed to read request body: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Failed to read request body",
			})
			return
		}

		logrus.Debugf("Received raw body: %s", string(body))

		// Parse events (single event or array)
		events, err := parseEvents(body)
		if err != nil {
			logrus.Errorf("JSON parse error: %v, body: %s", err, string(body))
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Invalid JSON format: %v", err),
			})
			return
		}

		logrus.Infof("Parsed %d events from request", len(events))
		for i, evt := range events {
			logrus.Infof("Event %d: %s", i, string(evt))
		}

		// Process events and track statistics
		result := processEventsWithStats(engine, events)

		c.JSON(http.StatusOK, result)
	}
}

// Stats returns current engine statistics
func Stats(engine *engine.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		stats, err := engine.GetStats()
		if err != nil {
			logrus.Errorf("Failed to get engine stats: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get engine statistics",
			})
			return
		}
		c.JSON(http.StatusOK, stats)
	}
}

// Alerts returns recent security alerts
func Alerts(engine *engine.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		limit := 100
		if l := c.Query("limit"); l != "" {
			fmt.Sscanf(l, "%d", &limit)
		}

		alerts := engine.GetRecentAlerts(limit)
		c.JSON(http.StatusOK, gin.H{
			"alerts": alerts,
			"count":  len(alerts),
			"limit":  limit,
		})
	}
}

// Rules returns information about loaded detection rules
func Rules(engine *engine.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		rules := engine.GetLoadedRules()
		c.JSON(http.StatusOK, gin.H{
			"rules": rules,
			"count": len(rules),
		})
	}
}

// parseEvents parses JSON body into events (single event or array)
func parseEvents(body []byte) ([]json.RawMessage, error) {
	var events []json.RawMessage

	// Try to parse as array first
	if err := json.Unmarshal(body, &events); err == nil {
		return events, nil
	}

	// Try to parse as single event
	var singleEvent json.RawMessage
	if err := json.Unmarshal(body, &singleEvent); err != nil {
		return nil, err
	}

	events = []json.RawMessage{singleEvent}
	return events, nil
}

// processEventsWithStats processes events and returns statistics
func processEventsWithStats(engine *engine.Engine, events []json.RawMessage) gin.H {
	// Get initial stats
	initialStats, err := engine.GetStats()
	var initialAlerts uint64 = 0
	if err != nil {
		logrus.Errorf("Failed to get initial stats: %v", err)
	} else {
		initialAlerts = initialStats.AlertsGenerated
	}

	processed := 0
	errors := 0

	// Process each event
	for _, rawEvent := range events {
		if err := engine.ProcessEvent(rawEvent); err != nil {
			logrus.Errorf("Failed to process event: %v", err)
			errors++
		} else {
			processed++
		}
	}

	// Get final stats to calculate alerts generated
	finalStats, err := engine.GetStats()
	var alertsGenerated uint64 = 0
	if err != nil {
		logrus.Errorf("Failed to get final stats: %v", err)
	} else {
		alertsGenerated = finalStats.AlertsGenerated - initialAlerts
	}

	return gin.H{
		"processed":        processed,
		"errors":           errors,
		"alerts_generated": alertsGenerated,
		"total_events":     len(events),
		"timestamp":        time.Now().UTC(),
	}
}
