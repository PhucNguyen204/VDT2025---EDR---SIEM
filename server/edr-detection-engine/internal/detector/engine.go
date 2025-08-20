// ====================================================================
// EDR DETECTION ENGINE - DETECTION ENGINE
// ====================================================================
// Tác giả: Senior Software Engineer - EDR Platform Team
// Mô tả: Core detection engine để match events với Sigma rules
// ====================================================================

package detector

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"edr-detection-engine/internal/models"
	"edr-detection-engine/internal/sigma"

	"github.com/sirupsen/logrus"
)

// DetectionEngine là core engine để detect threats
type DetectionEngine struct {
	rules      []*models.DetectionRule
	rulesMutex sync.RWMutex
	logger     *logrus.Logger
	stats      *DetectionStats

	// Sigma engine for improved rule processing
	sigmaEngine *sigma.SigmaEngine

	// Event correlation (simple implementation)
	eventBuffer map[string][]*models.Event
	bufferMutex sync.RWMutex
	bufferTTL   time.Duration
}

// DetectionStats chứa thống kê detection
type DetectionStats struct {
	EventsProcessed int64
	AlertsGenerated int64
	RulesMatched    map[string]int64
	LastReset       time.Time
	mutex           sync.RWMutex
}

// MatchResult chứa kết quả match của một rule
type MatchResult struct {
	Rule    *models.DetectionRule
	Event   *models.Event
	Matched bool
	Details map[string]interface{}
}

// NewDetectionEngine tạo instance mới của detection engine
func NewDetectionEngine() *DetectionEngine {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	return &DetectionEngine{
		rules:       make([]*models.DetectionRule, 0),
		logger:      logger,
		stats:       NewDetectionStats(),
		sigmaEngine: sigma.NewSigmaEngine(),
		eventBuffer: make(map[string][]*models.Event),
		bufferTTL:   time.Minute * 10, // 10 minutes buffer
	}
}

// NewDetectionStats tạo instance mới của detection stats
func NewDetectionStats() *DetectionStats {
	return &DetectionStats{
		RulesMatched: make(map[string]int64),
		LastReset:    time.Now(),
	}
}

// LoadRules load danh sách rules vào engine
func (e *DetectionEngine) LoadRules(rules []*models.DetectionRule) {
	e.rulesMutex.Lock()
	defer e.rulesMutex.Unlock()

	e.rules = rules
	e.logger.Infof("Loaded %d detection rules", len(rules))
}

// LoadSigmaRulesFromDirectory load Sigma rules từ directory
func (e *DetectionEngine) LoadSigmaRulesFromDirectory(rulesDir string) error {
	e.logger.Infof("🔍 Loading Sigma rules from: %s", rulesDir)

	err := e.sigmaEngine.LoadRulesFromDirectory(rulesDir)
	if err != nil {
		return fmt.Errorf("failed to load Sigma rules: %w", err)
	}

	// Update internal rules list với Sigma rules
	sigmaRules := e.sigmaEngine.GetAllRules()
	e.rulesMutex.Lock()
	e.rules = append(e.rules, sigmaRules...)
	e.rulesMutex.Unlock()

	e.logger.Infof("✅ Total rules loaded: %d (including %d Sigma rules)", len(e.rules), len(sigmaRules))

	return nil
}

// AddRule thêm một rule vào engine
func (e *DetectionEngine) AddRule(rule *models.DetectionRule) {
	e.rulesMutex.Lock()
	defer e.rulesMutex.Unlock()

	e.rules = append(e.rules, rule)
	e.logger.Infof("Added rule: %s (%s)", rule.Title, rule.ID)
}

// ProcessEvent xử lý một event và trả về alerts nếu có
func (e *DetectionEngine) ProcessEvent(event *models.Event) ([]*models.Alert, error) {
	e.stats.IncrementEventsProcessed()

	var alerts []*models.Alert

	// Get rules applicable cho event này
	applicableRules := e.getApplicableRules(event)
	e.logger.Debugf("Found %d applicable rules for event %s", len(applicableRules), event.ID)

	// Test từng rule
	for _, rule := range applicableRules {
		result := e.matchRule(rule, event)
		if result.Matched {
			e.logger.Infof("Rule matched: %s for event %s", rule.Title, event.ID)

			// Tạo alert
			alert := e.createAlert(rule, event, result)
			alerts = append(alerts, alert)

			// Update stats
			e.stats.IncrementRuleMatched(rule.ID)
			e.stats.IncrementAlertsGenerated()
		}
	}

	// Store event in buffer cho correlation (nếu cần)
	e.storeEventInBuffer(event)

	return alerts, nil
}

// getApplicableRules lấy danh sách rules có thể áp dụng cho event
func (e *DetectionEngine) getApplicableRules(event *models.Event) []*models.DetectionRule {
	// Sử dụng Sigma engine để get applicable rules (improved performance)
	sigmaApplicable := e.sigmaEngine.GetApplicableRules(event)

	// Fallback to original logic cho non-Sigma rules
	e.rulesMutex.RLock()
	defer e.rulesMutex.RUnlock()

	var applicable []*models.DetectionRule
	applicable = append(applicable, sigmaApplicable...)

	// Add non-Sigma rules nếu có
	for _, rule := range e.rules {
		// Skip rules đã được handle bởi Sigma engine
		found := false
		for _, sigmaRule := range sigmaApplicable {
			if rule.ID == sigmaRule.ID {
				found = true
				break
			}
		}

		if !found && event.MatchesLogSource(rule.LogSource) {
			applicable = append(applicable, rule)
		}
	}

	return applicable
}

// matchRule kiểm tra event có match với rule không
func (e *DetectionEngine) matchRule(rule *models.DetectionRule, event *models.Event) *MatchResult {
	result := &MatchResult{
		Rule:    rule,
		Event:   event,
		Matched: false,
		Details: make(map[string]interface{}),
	}

	// Sử dụng Sigma engine để evaluate rule (improved accuracy)
	matched := e.sigmaEngine.EvaluateRule(rule, event)
	result.Matched = matched

	// Add debug info
	if matched {
		result.Details["sigma_engine"] = "rule matched using Sigma engine"
		e.logger.Debugf("✅ Sigma rule matched: %s (%s) for event %s", rule.Title, rule.ID, event.ID)
	} else {
		result.Details["sigma_engine"] = "rule did not match using Sigma engine"
		e.logger.Debugf("❌ Sigma rule not matched: %s (%s) for event %s", rule.Title, rule.ID, event.ID)
	}

	return result
}

// evaluateSimpleCondition đánh giá condition đơn giản
func (e *DetectionEngine) evaluateSimpleCondition(condition string, selections map[string]interface{}, event *models.Event, details map[string]interface{}) bool {
	// Xử lý condition đơn giản dạng "selection" hoặc "sel1 and sel2"
	condition = strings.TrimSpace(condition)

	// Nếu condition chỉ là một selection name
	if selection, exists := selections[condition]; exists {
		return e.evaluateSelection(condition, selection, event, details)
	}

	// Xử lý condition phức tạp hơn (simplified)
	if strings.Contains(condition, " and ") {
		parts := strings.Split(condition, " and ")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if selection, exists := selections[part]; exists {
				if !e.evaluateSelection(part, selection, event, details) {
					return false
				}
			}
		}
		return true
	}

	if strings.Contains(condition, " or ") {
		parts := strings.Split(condition, " or ")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if selection, exists := selections[part]; exists {
				if e.evaluateSelection(part, selection, event, details) {
					return true
				}
			}
		}
		return false
	}

	// Default: try to find selection with this name
	for selName, selection := range selections {
		if selName == condition {
			return e.evaluateSelection(selName, selection, event, details)
		}
	}

	return false
}

// evaluateSelection đánh giá một selection
func (e *DetectionEngine) evaluateSelection(name string, selection interface{}, event *models.Event, details map[string]interface{}) bool {
	selMap, ok := selection.(map[string]interface{})
	if !ok {
		e.logger.Warnf("Invalid selection format for %s", name)
		return false
	}

	details[name] = make(map[string]interface{})
	selDetails := details[name].(map[string]interface{})

	// Convert event to map để dễ access fields
	eventMap := e.eventToMap(event)

	// Kiểm tra từng field trong selection
	for field, expectedValue := range selMap {
		if !e.matchField(field, expectedValue, eventMap, selDetails) {
			return false
		}
	}

	return true
}

// matchField kiểm tra field có match với expected value không
func (e *DetectionEngine) matchField(field string, expectedValue interface{}, eventMap map[string]interface{}, details map[string]interface{}) bool {
	// Get actual value từ event
	actualValue := e.getFieldValue(field, eventMap)
	if actualValue == nil {
		details[field] = "field not found"
		return false
	}

	// Xử lý các operator khác nhau
	matched := e.matchValue(field, expectedValue, actualValue, details)

	if matched {
		details[field] = fmt.Sprintf("matched: %v", actualValue)
	} else {
		details[field] = fmt.Sprintf("not matched: expected %v, got %v", expectedValue, actualValue)
	}

	return matched
}

// matchValue so sánh expected value với actual value
func (e *DetectionEngine) matchValue(field string, expected, actual interface{}, details map[string]interface{}) bool {
	switch exp := expected.(type) {
	case string:
		return e.matchStringValue(field, exp, actual)
	case []interface{}:
		// OR logic cho array values
		for _, item := range exp {
			if e.matchValue(field, item, actual, details) {
				return true
			}
		}
		return false
	case map[string]interface{}:
		// Xử lý operators như contains, endswith, etc.
		return e.matchWithOperators(field, exp, actual)
	default:
		// Direct comparison
		return reflect.DeepEqual(expected, actual)
	}
}

// matchStringValue match string values với wildcard support
func (e *DetectionEngine) matchStringValue(field, expected string, actual interface{}) bool {
	actualStr, ok := actual.(string)
	if !ok {
		return false
	}

	// Exact match
	if expected == actualStr {
		return true
	}

	// Wildcard match
	if strings.Contains(expected, "*") {
		pattern := strings.ReplaceAll(expected, "*", ".*")
		matched, _ := regexp.MatchString("^"+pattern+"$", actualStr)
		return matched
	}

	return false
}

// matchWithOperators xử lý các operators như contains, endswith
func (e *DetectionEngine) matchWithOperators(field string, operators map[string]interface{}, actual interface{}) bool {
	actualStr, ok := actual.(string)
	if !ok {
		return false
	}

	for op, value := range operators {
		valueStr, ok := value.(string)
		if !ok {
			continue
		}

		switch op {
		case "contains":
			if !strings.Contains(actualStr, valueStr) {
				return false
			}
		case "endswith":
			if !strings.HasSuffix(actualStr, valueStr) {
				return false
			}
		case "startswith":
			if !strings.HasPrefix(actualStr, valueStr) {
				return false
			}
		case "re":
			matched, _ := regexp.MatchString(valueStr, actualStr)
			if !matched {
				return false
			}
		}
	}

	return true
}

// getFieldValue lấy value của field từ event map
func (e *DetectionEngine) getFieldValue(field string, eventMap map[string]interface{}) interface{} {
	// Xử lý nested fields như "process.executable"
	parts := strings.Split(field, ".")

	current := eventMap
	for i, part := range parts {
		if i == len(parts)-1 {
			// Last part
			return current[part]
		}

		// Navigate deeper
		if next, ok := current[part].(map[string]interface{}); ok {
			current = next
		} else {
			return nil
		}
	}

	return nil
}

// eventToMap chuyển Event struct thành map để dễ access
func (e *DetectionEngine) eventToMap(event *models.Event) map[string]interface{} {
	// Simple conversion - trong production nên dùng reflection hoặc JSON marshal/unmarshal
	eventMap := map[string]interface{}{
		"timestamp": event.Timestamp,
		"id":        event.ID,
		"message":   event.Message,
		"host": map[string]interface{}{
			"id":   event.Host.ID,
			"name": event.Host.Name,
		},
		"event": map[string]interface{}{
			"kind":     event.Event.Kind,
			"category": event.Event.Category,
			"type":     event.Event.Type,
			"action":   event.Event.Action,
			"provider": event.Event.Provider,
			"code":     event.Event.Code,
		},
	}

	// Add Sigma-compatible field mappings
	// Map ECS fields to Sigma expected fields
	if event.Event.Code != "" {
		eventMap["EventID"] = event.Event.Code
	}
	if event.Host.Name != "" {
		eventMap["ComputerName"] = event.Host.Name
	}

	// Add authentication fields
	if event.User != nil {
		eventMap["user"] = map[string]interface{}{
			"name":   event.User.Name,
			"domain": event.User.Domain,
		}
		// Sigma compatibility
		eventMap["TargetUserName"] = event.User.Name
		eventMap["TargetDomainName"] = event.User.Domain
	}

	// Add source IP mapping
	if event.Source != nil {
		eventMap["source"] = map[string]interface{}{
			"ip": event.Source.IP,
		}
		// Sigma compatibility
		eventMap["IpAddress"] = event.Source.IP
		eventMap["SourceNetworkAddress"] = event.Source.IP
	}

	// Add winlog fields if available
	if event.Winlog != nil {
		eventMap["winlog"] = map[string]interface{}{
			"event_id":      event.Winlog.EventID,
			"channel":       event.Winlog.Channel,
			"computer_name": event.Winlog.ComputerName,
		}
		// Additional Sigma mappings
		eventMap["Channel"] = event.Winlog.Channel
		eventMap["LogonType"] = event.Winlog.LogonType
		if event.Winlog.Logon != nil && event.Winlog.Logon.Failure != nil {
			eventMap["Status"] = event.Winlog.Logon.Failure.Status
			eventMap["SubStatus"] = event.Winlog.Logon.Failure.SubStatus
			eventMap["FailureReason"] = event.Winlog.Logon.Failure.Reason
		}
	}

	// Add process info if available
	if event.Process != nil {
		eventMap["process"] = map[string]interface{}{
			"pid":          event.Process.PID,
			"executable":   event.Process.Executable,
			"name":         event.Process.Name,
			"command_line": event.Process.CommandLine,
		}

		if event.Process.Parent != nil {
			eventMap["process"].(map[string]interface{})["parent"] = map[string]interface{}{
				"executable": event.Process.Parent.Executable,
				"name":       event.Process.Parent.Name,
			}
		}
	}

	// Add network info if available
	if event.Network != nil {
		eventMap["network"] = map[string]interface{}{
			"transport": event.Network.Transport,
			"direction": event.Network.Direction,
		}

		if event.Destination != nil {
			eventMap["destination"] = map[string]interface{}{
				"ip":   event.Destination.IP,
				"port": event.Destination.Port,
			}
		}
	}

	return eventMap
}

// createAlert tạo alert từ matched rule và event
func (e *DetectionEngine) createAlert(rule *models.DetectionRule, event *models.Event, result *MatchResult) *models.Alert {
	now := time.Now()

	alert := &models.Alert{
		ID:          fmt.Sprintf("alert-%d-%s", now.Unix(), rule.ID),
		Timestamp:   now,
		RuleID:      rule.ID,
		RuleName:    rule.Title,
		Severity:    e.mapLevelToSeverity(rule.Level),
		Status:      "open",
		Description: rule.Description,
		Events:      []models.Event{*event},
		Host:        event.Host,
		Context:     result.Details,
		FirstSeen:   now,
		LastSeen:    now,
		Count:       1,
	}

	// Extract MITRE info từ tags
	alert.MITRE = e.extractMITREInfo(rule.Tags)

	return alert
}

// mapLevelToSeverity map Sigma level sang alert severity
func (e *DetectionEngine) mapLevelToSeverity(level string) string {
	switch level {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "medium"
	}
}

// extractMITREInfo extract MITRE ATT&CK info từ tags
func (e *DetectionEngine) extractMITREInfo(tags []string) models.MITREInfo {
	mitre := models.MITREInfo{}

	for _, tag := range tags {
		if strings.HasPrefix(tag, "attack.t") {
			// Extract technique ID
			parts := strings.Split(tag, ".")
			if len(parts) >= 2 {
				mitre.TechniqueID = strings.ToUpper(parts[1])
			}
		} else if strings.HasPrefix(tag, "attack.ta") {
			// Extract tactic ID
			parts := strings.Split(tag, ".")
			if len(parts) >= 2 {
				mitre.TacticID = strings.ToUpper(parts[1])
			}
		}
	}

	return mitre
}

// storeEventInBuffer lưu event vào buffer cho correlation
func (e *DetectionEngine) storeEventInBuffer(event *models.Event) {
	e.bufferMutex.Lock()
	defer e.bufferMutex.Unlock()

	key := event.Host.ID
	if e.eventBuffer[key] == nil {
		e.eventBuffer[key] = make([]*models.Event, 0)
	}

	e.eventBuffer[key] = append(e.eventBuffer[key], event)

	// Simple cleanup - remove events older than TTL
	cutoff := time.Now().Add(-e.bufferTTL)
	var filtered []*models.Event
	for _, bufferedEvent := range e.eventBuffer[key] {
		if bufferedEvent.Timestamp.After(cutoff) {
			filtered = append(filtered, bufferedEvent)
		}
	}
	e.eventBuffer[key] = filtered
}

// GetStats trả về detection statistics
func (e *DetectionEngine) GetStats() *DetectionStats {
	return e.stats
}

// GetRulesCount trả về số lượng rules đã load
func (e *DetectionEngine) GetRulesCount() int {
	e.rulesMutex.RLock()
	defer e.rulesMutex.RUnlock()
	return len(e.rules)
}

// GetRules trả về danh sách rules (for API)
func (e *DetectionEngine) GetRules() []*models.DetectionRule {
	e.rulesMutex.RLock()
	defer e.rulesMutex.RUnlock()

	// Return copy để tránh race condition
	rules := make([]*models.DetectionRule, len(e.rules))
	copy(rules, e.rules)
	return rules
}

// ResetStats reset detection statistics
func (e *DetectionEngine) ResetStats() {
	e.stats.mutex.Lock()
	defer e.stats.mutex.Unlock()

	e.stats.EventsProcessed = 0
	e.stats.AlertsGenerated = 0
	e.stats.RulesMatched = make(map[string]int64)
	e.stats.LastReset = time.Now()
}

// Stats methods
func (s *DetectionStats) IncrementEventsProcessed() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.EventsProcessed++
}

func (s *DetectionStats) IncrementAlertsGenerated() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.AlertsGenerated++
}

func (s *DetectionStats) IncrementRuleMatched(ruleID string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.RulesMatched[ruleID]++
}

func (s *DetectionStats) GetEventsProcessed() int64 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.EventsProcessed
}

func (s *DetectionStats) GetAlertsGenerated() int64 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.AlertsGenerated
}

func (s *DetectionStats) GetRulesMatched() map[string]int64 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	result := make(map[string]int64)
	for k, v := range s.RulesMatched {
		result[k] = v
	}
	return result
}
