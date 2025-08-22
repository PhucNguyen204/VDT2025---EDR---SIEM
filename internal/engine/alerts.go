package engine

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/VDT2025_PhucNguyen204/internal/event"
	"github.com/markuskont/go-sigma-rule-engine"
	"github.com/sirupsen/logrus"
)

// createAlert creates an alert from a matched rule and event
func (e *Engine) createAlert(rule *sigma.Tree, evt event.Event, index int) *Alert {
	// Try to extract rule metadata from file path or other sources
	ruleInfo := e.extractRuleMetadata(rule, index)

	alert := &Alert{
		ID:          fmt.Sprintf("%s-%d", ruleInfo.ID, time.Now().UnixNano()),
		Timestamp:   time.Now().UTC(),
		Event:       evt.GetData(),
		Severity:    e.mapLevelToSeverity(ruleInfo.Level),
		Description: ruleInfo.Description,
		Tags:        append(ruleInfo.Tags, "sigma", "detection"),
	}

	// Set rule info
	alert.Rule = ruleInfo

	return alert
}

// alertProcessor processes alerts from the queue
func (e *Engine) alertProcessor() {
	defer e.wg.Done()

	for {
		select {
		case alert := <-e.alertQueue:
			if alert == nil {
				return
			}

			// Add to recent alerts with size limit
			e.alertsMutex.Lock()
			e.recentAlerts = append(e.recentAlerts, alert)
			if len(e.recentAlerts) > 1000 { // Keep last 1000 alerts
				e.recentAlerts = e.recentAlerts[1:]
			}
			e.alertsMutex.Unlock()

			// Console log với màu sắc và thông tin chi tiết
			fmt.Printf("\n🚨 ===== SECURITY ALERT DETECTED ===== 🚨\n")
			fmt.Printf("⏰ Time: %s\n", alert.Timestamp.Format("2006-01-02 15:04:05 UTC"))
			fmt.Printf("🆔 Alert ID: %s\n", alert.ID)
			fmt.Printf("⚠️  Severity: %s\n", alert.Severity)
			fmt.Printf("📋 Rule: %s (%s)\n", alert.Rule.Title, alert.Rule.ID)
			fmt.Printf("📝 Description: %s\n", alert.Description)

			// Attack Type Classification
			attackType := "Unknown Attack"
			mitreID := ""
			if len(alert.Tags) > 0 {
				fmt.Printf("🏷️  Tags: %s\n", strings.Join(alert.Tags, ", "))

				// Classify attack type based on command line and fields
				if cmdLine, exists := alert.Event["CommandLine"]; exists {
					if strings.Contains(strings.ToLower(fmt.Sprintf("%v", cmdLine)), "hydra") {
						attackType = "SSH Brute Force Attack"
						mitreID = "T1110.001 - Password Guessing"
					}
				}

				// Extract MITRE techniques from tags
				for _, tag := range alert.Tags {
					if strings.HasPrefix(strings.ToUpper(tag), "T") && len(tag) >= 5 {
						mitreID = tag
						break
					}
				}
			}

			fmt.Printf("🎯 Attack Type: %s\n", attackType)
			if mitreID != "" {
				fmt.Printf("� MITRE ATT&CK: %s\n", mitreID)
			}

			// Event details
			if cmdLine, exists := alert.Event["CommandLine"]; exists {
				fmt.Printf("💻 Command Line: %s\n", cmdLine)
			}
			if image, exists := alert.Event["Image"]; exists {
				fmt.Printf("📁 Process Image: %s\n", image)
			}
			if computer, exists := alert.Event["ComputerName"]; exists {
				fmt.Printf("🖥️  Computer: %s\n", computer)
			}
			if sourceIP, exists := alert.Event["source_ip"]; exists {
				fmt.Printf("🌐 Source IP: %s\n", sourceIP)
			}

			// Get current stats for context
			currentStats := e.GetStats()
			fmt.Printf("📊 Detection Stats:\n")
			fmt.Printf("   - Total Events Processed: %d\n", currentStats.EventsProcessed)
			fmt.Printf("   - Total Alerts Generated: %d\n", currentStats.AlertsGenerated)
			fmt.Printf("   - Detection Rate: %.2f%%\n", float64(currentStats.AlertsGenerated)/float64(currentStats.EventsProcessed)*100)

			fmt.Printf("========================================\n\n")

			logrus.WithFields(logrus.Fields{
				"alert_id": alert.ID,
				"rule_id":  alert.Rule.ID,
				"severity": alert.Severity,
			}).Info("Alert processed and stored")

		case <-e.ctx.Done():
			return
		}
	}
}

// GetRecentAlerts returns recent alerts with optional limit
func (e *Engine) GetRecentAlerts(limit int) []*Alert {
	e.alertsMutex.RLock()
	defer e.alertsMutex.RUnlock()

	if limit <= 0 || limit > len(e.recentAlerts) {
		limit = len(e.recentAlerts)
	}

	// Return most recent alerts
	start := len(e.recentAlerts) - limit
	if start < 0 {
		start = 0
	}

	result := make([]*Alert, limit)
	copy(result, e.recentAlerts[start:])

	// Reverse to get most recent first
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return result
}

// mapLevelToSeverity converts Sigma level to standard severity
func (e *Engine) mapLevelToSeverity(level string) string {
	switch strings.ToLower(level) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	case "informational", "info":
		return "Info"
	default:
		return "Medium"
	}
}

// extractMITRETags extracts MITRE ATT&CK technique IDs from tags
func (e *Engine) extractMITRETags(tags []string) []string {
	var mitreTags []string
	for _, tag := range tags {
		if strings.HasPrefix(strings.ToUpper(tag), "T") && len(tag) >= 4 {
			// Simple pattern matching for MITRE technique IDs (T1234)
			if len(tag) >= 5 && tag[1:5] != "" {
				mitreTags = append(mitreTags, tag)
			}
		}
	}
	return mitreTags
}

// addAlertToQueue safely adds an alert to the processing queue
func (e *Engine) addAlertToQueue(alert *Alert) {
	// Update statistics
	atomic.AddUint64(&e.alertsGenerated, 1)

	// Try to add to queue (non-blocking)
	select {
	case e.alertQueue <- alert:
		logrus.WithFields(logrus.Fields{
			"rule_id":    alert.Rule.ID,
			"rule_title": alert.Rule.Title,
			"severity":   alert.Severity,
		}).Info("Alert generated")
	default:
		logrus.Warn("Alert queue full, dropping alert")
	}
}
