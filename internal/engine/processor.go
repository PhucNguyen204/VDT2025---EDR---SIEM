package engine

import (
	"encoding/json"
	"fmt"
	"sync/atomic"

	"github.com/VDT2025_PhucNguyen204/internal/event"
	"github.com/markuskont/go-sigma-rule-engine"
	"github.com/sirupsen/logrus"
)

// ProcessEvent processes a single event through the detection engine
func (e *Engine) ProcessEvent(rawEvent json.RawMessage) error {
	// Parse event
	evt, err := event.ParseEvent(rawEvent)
	if err != nil {
		return fmt.Errorf("failed to parse event: %w", err)
	}

	// Update statistics
	atomic.AddUint64(&e.eventsProcessed, 1)

	// Debug: Log event fields for SSH events
	eventData := evt.GetData()
	if eventID, hasEventID := eventData["EventID"]; hasEventID {
		logrus.Debugf("Processing event with EventID: %v", eventID)
		if targetUser, hasTargetUser := eventData["TargetUserName"]; hasTargetUser {
			logrus.Debugf("SSH event with TargetUserName: %v", targetUser)
		}
		if ipAddr, hasIP := eventData["IpAddress"]; hasIP {
			logrus.Debugf("SSH event with IpAddress: %v", ipAddr)
		}
	}

	// Evaluate against all rules
	matchedRules := e.evaluateEvent(evt)

	logrus.Infof("Event evaluated against %d rules, %d matches found", len(e.ruleset.Rules), len(matchedRules))

	if len(matchedRules) == 0 {
		return nil // No match, but not an error
	}

	// Generate alerts for matches
	e.generateAlertsFromMatches(matchedRules, evt)

	return nil
}

// evaluateEvent checks the event against all loaded rules
func (e *Engine) evaluateEvent(evt event.Event) []*RuleMatch {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var matchedRules []*RuleMatch

	// Debug: Log event data for troubleshooting
	eventData := evt.GetData()
	if method, hasMethod := eventData["cs-method"]; hasMethod {
		logrus.Debugf("Processing web event with method: %v", method)
		if query, hasQuery := eventData["cs-uri-query"]; hasQuery {
			logrus.Debugf("Web event query: %v", query)
		}
	}

	// Check each rule individually
	for i, rule := range e.ruleset.Rules {
		if match, ok := rule.Match(evt); ok && match {
			matchedRules = append(matchedRules, &RuleMatch{
				Rule:  rule,
				Index: i,
			})
			logrus.Debugf("Rule %d matched event", i)
		} else {
			// Debug: Log why webserver rules don't match
			if category, hasCategory := eventData["event"].(map[string]interface{}); hasCategory {
				if catArray, isCatArray := category["category"].([]interface{}); isCatArray {
					for _, cat := range catArray {
						if cat == "webserver" {
							logrus.Debugf("Rule %d did not match webserver event", i)
						}
					}
				}
			}
		}
	}

	return matchedRules
}

// generateAlertsFromMatches creates alerts for all matched rules
func (e *Engine) generateAlertsFromMatches(matches []*RuleMatch, evt event.Event) {
	for _, match := range matches {
		alert := e.createAlert(match.Rule, evt, match.Index)
		e.addAlertToQueue(alert)
	}
}

// RuleMatch represents a rule that matched an event
type RuleMatch struct {
	Rule  *sigma.Tree
	Index int
}
