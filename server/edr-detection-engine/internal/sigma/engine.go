// ====================================================================
// EDR DETECTION ENGINE - SIGMA RULE ENGINE (Go Implementation)
// ====================================================================
// Tác giả: Senior Software Engineer - EDR Platform Team
// Mô tả: Go implementation của Sigma rule engine, inspired by Python tools
// ====================================================================

package sigma

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"edr-detection-engine/internal/models"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// SigmaEngine là Go implementation của Sigma rule processing engine
type SigmaEngine struct {
	rules      map[string]*models.DetectionRule
	rulesMutex sync.RWMutex
	logger     *logrus.Logger

	// Rule categorization (như Python version)
	windowsProcessCreationRules map[string]*models.DetectionRule
	windowsSecurityRules        map[string]*models.DetectionRule
	windowsPowerShellRules      map[string]*models.DetectionRule

	// Field mappings
	fieldMappings map[string]map[string]string
}

// SigmaRuleYAML đại diện cho raw Sigma rule từ YAML file
type SigmaRuleYAML struct {
	Title          string                 `yaml:"title"`
	ID             string                 `yaml:"id"`
	Description    string                 `yaml:"description"`
	Status         string                 `yaml:"status"`
	Level          string                 `yaml:"level"`
	Author         string                 `yaml:"author"`
	Date           string                 `yaml:"date"`
	Modified       string                 `yaml:"modified,omitempty"`
	Tags           []string               `yaml:"tags"`
	LogSource      map[string]interface{} `yaml:"logsource"`
	Detection      map[string]interface{} `yaml:"detection"`
	FalsePositives []string               `yaml:"falsepositives,omitempty"`
	References     []string               `yaml:"references,omitempty"`
}

// FieldExtractor helper để extract fields từ detection logic
type FieldExtractor struct {
	fields map[string]bool
}

// NewSigmaEngine tạo instance mới của Sigma engine
func NewSigmaEngine() *SigmaEngine {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	return &SigmaEngine{
		rules:                       make(map[string]*models.DetectionRule),
		windowsProcessCreationRules: make(map[string]*models.DetectionRule),
		windowsSecurityRules:        make(map[string]*models.DetectionRule),
		windowsPowerShellRules:      make(map[string]*models.DetectionRule),
		logger:                      logger,
		fieldMappings:               createFieldMappings(),
	}
}

// createFieldMappings tạo mapping giữa Sigma fields và ECS fields
func createFieldMappings() map[string]map[string]string {
	mappings := make(map[string]map[string]string)

	// Windows Security Event mappings
	mappings["security"] = map[string]string{
		"EventID":          "event.code",
		"TargetUserName":   "user.name",
		"TargetDomainName": "user.domain",
		"IpAddress":        "source.ip",
		"LogonType":        "winlog.logon_type",
		"Status":           "winlog.logon.failure.status",
		"SubStatus":        "winlog.logon.failure.sub_status",
		"ComputerName":     "host.name",
		"Channel":          "winlog.channel",
	}

	// Process Creation mappings
	mappings["process_creation"] = map[string]string{
		"EventID":           "event.code",
		"Image":             "process.executable",
		"CommandLine":       "process.command_line",
		"ProcessId":         "process.pid",
		"User":              "user.name",
		"ParentImage":       "process.parent.executable",
		"ParentCommandLine": "process.parent.command_line",
		"ComputerName":      "host.name",
	}

	// PowerShell mappings
	mappings["powershell"] = map[string]string{
		"EventID":     "event.code",
		"ScriptBlock": "powershell.script_block",
		"Path":        "powershell.script_path",
		"CommandName": "powershell.command_name",
		"CommandType": "powershell.command_type",
	}

	return mappings
}

// LoadRulesFromDirectory load tất cả Sigma rules từ directory (recursive)
func (s *SigmaEngine) LoadRulesFromDirectory(rulesDir string) error {
	s.rulesMutex.Lock()
	defer s.rulesMutex.Unlock()

	s.logger.Infof("🔍 Loading Sigma rules from directory: %s", rulesDir)

	ruleCount := 0
	err := filepath.Walk(rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(strings.ToLower(path), ".yml") {
			rule, err := s.loadRuleFromFile(path)
			if err != nil {
				s.logger.Warnf("Failed to load rule from %s: %v", path, err)
				return nil // Continue với files khác
			}

			if rule != nil {
				s.rules[rule.ID] = rule
				s.categorizeRule(rule)
				ruleCount++

				if ruleCount%100 == 0 {
					s.logger.Infof("📋 Loaded %d rules...", ruleCount)
				}
			}
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk rules directory: %w", err)
	}

	s.logger.Infof("✅ Successfully loaded %d Sigma rules", ruleCount)
	s.printRuleStatistics()

	return nil
}

// loadRuleFromFile load một Sigma rule từ YAML file
func (s *SigmaEngine) loadRuleFromFile(filePath string) (*models.DetectionRule, error) {
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var sigmaRule SigmaRuleYAML
	err = yaml.Unmarshal(content, &sigmaRule)
	if err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Convert SigmaRuleYAML to DetectionRule
	rule := s.convertToDetectionRule(&sigmaRule, filePath)

	return rule, nil
}

// convertToDetectionRule convert SigmaRuleYAML to internal DetectionRule model
func (s *SigmaEngine) convertToDetectionRule(sigmaRule *SigmaRuleYAML, filePath string) *models.DetectionRule {
	rule := &models.DetectionRule{
		ID:             sigmaRule.ID,
		Title:          sigmaRule.Title,
		Description:    sigmaRule.Description,
		Status:         sigmaRule.Status,
		Level:          sigmaRule.Level,
		Author:         sigmaRule.Author,
		Date:           sigmaRule.Date,
		Modified:       sigmaRule.Modified,
		Tags:           sigmaRule.Tags,
		FalsePositives: sigmaRule.FalsePositives,
		References:     sigmaRule.References,
	}

	// Convert LogSource
	rule.LogSource = models.LogSourceSpec{}
	if category, ok := sigmaRule.LogSource["category"].(string); ok {
		rule.LogSource.Category = category
	}
	if product, ok := sigmaRule.LogSource["product"].(string); ok {
		rule.LogSource.Product = product
	}
	if service, ok := sigmaRule.LogSource["service"].(string); ok {
		rule.LogSource.Service = service
	}

	// Convert Detection logic
	rule.Detection = models.DetectionLogic{
		Selections: make(map[string]interface{}),
	}

	// Extract condition
	if condition, ok := sigmaRule.Detection["condition"].(string); ok {
		rule.Detection.Condition = condition
	}

	// Extract timeframe
	if timeframe, ok := sigmaRule.Detection["timeframe"].(string); ok {
		rule.Detection.Timeframe = timeframe
	}

	// Extract selections (tất cả keys trừ condition và timeframe)
	for key, value := range sigmaRule.Detection {
		if key != "condition" && key != "timeframe" {
			rule.Detection.Selections[key] = value
		}
	}

	return rule
}

// categorizeRule phân loại rule theo logsource (như Python version)
func (s *SigmaEngine) categorizeRule(rule *models.DetectionRule) {
	if rule.LogSource.Product == "windows" {
		if rule.LogSource.Category == "process_creation" {
			s.windowsProcessCreationRules[rule.ID] = rule
		} else if rule.LogSource.Service == "security" {
			s.windowsSecurityRules[rule.ID] = rule
		} else if rule.LogSource.Service == "powershell" {
			s.windowsPowerShellRules[rule.ID] = rule
		}
	}
}

// printRuleStatistics in thống kê rules (như Python version)
func (s *SigmaEngine) printRuleStatistics() {
	stats := map[string]interface{}{
		"total": len(s.rules),
		"by_category": map[string]int{
			"process_creation": len(s.windowsProcessCreationRules),
			"security":         len(s.windowsSecurityRules),
			"powershell":       len(s.windowsPowerShellRules),
		},
		"by_level":  s.getRulesByLevel(),
		"by_status": s.getRulesByStatus(),
	}

	s.logger.Infof("📈 Rule Statistics: %+v", stats)
}

// getRulesByLevel thống kê rules theo level
func (s *SigmaEngine) getRulesByLevel() map[string]int {
	stats := make(map[string]int)
	for _, rule := range s.rules {
		stats[rule.Level]++
	}
	return stats
}

// getRulesByStatus thống kê rules theo status
func (s *SigmaEngine) getRulesByStatus() map[string]int {
	stats := make(map[string]int)
	for _, rule := range s.rules {
		stats[rule.Status]++
	}
	return stats
}

// GetApplicableRules lấy rules applicable cho event (improved version)
func (s *SigmaEngine) GetApplicableRules(event *models.Event) []*models.DetectionRule {
	s.rulesMutex.RLock()
	defer s.rulesMutex.RUnlock()

	var applicable []*models.DetectionRule

	// Determine event category
	eventCategory := s.determineEventCategory(event)

	switch eventCategory {
	case "process_creation":
		for _, rule := range s.windowsProcessCreationRules {
			if s.isRuleApplicable(rule, event) {
				applicable = append(applicable, rule)
			}
		}
	case "security":
		for _, rule := range s.windowsSecurityRules {
			if s.isRuleApplicable(rule, event) {
				applicable = append(applicable, rule)
			}
		}
	case "powershell":
		for _, rule := range s.windowsPowerShellRules {
			if s.isRuleApplicable(rule, event) {
				applicable = append(applicable, rule)
			}
		}
	default:
		// Fallback: check all rules
		for _, rule := range s.rules {
			if s.isRuleApplicable(rule, event) {
				applicable = append(applicable, rule)
			}
		}
	}

	return applicable
}

// determineEventCategory xác định category của event
func (s *SigmaEngine) determineEventCategory(event *models.Event) string {
	// Check event categories
	for _, category := range event.Event.Category {
		switch category {
		case "process":
			return "process_creation"
		case "authentication":
			return "security"
		}
	}

	// Check event module
	switch event.Event.Module {
	case "security":
		return "security"
	case "powershell":
		return "powershell"
	case "sysmon":
		if len(event.Event.Category) > 0 && event.Event.Category[0] == "process" {
			return "process_creation"
		}
	}

	return "unknown"
}

// isRuleApplicable kiểm tra rule có applicable với event không
func (s *SigmaEngine) isRuleApplicable(rule *models.DetectionRule, event *models.Event) bool {
	// Basic logsource matching
	if rule.LogSource.Product != "" {
		if event.Host.OS.Platform != rule.LogSource.Product {
			return false
		}
	}

	if rule.LogSource.Service != "" {
		if event.Event.Module != rule.LogSource.Service {
			return false
		}
	}

	if rule.LogSource.Category != "" {
		found := false
		for _, category := range event.Event.Category {
			if category == rule.LogSource.Category {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// EvaluateRule đánh giá rule với event (improved version)
func (s *SigmaEngine) EvaluateRule(rule *models.DetectionRule, event *models.Event) bool {
	// Convert event to map với field mappings
	eventMap := s.convertEventToSigmaFields(event, rule)

	// Parse và evaluate condition
	return s.evaluateCondition(rule.Detection.Condition, rule.Detection.Selections, eventMap)
}

// convertEventToSigmaFields convert event sang Sigma field format
func (s *SigmaEngine) convertEventToSigmaFields(event *models.Event, rule *models.DetectionRule) map[string]interface{} {
	eventMap := make(map[string]interface{})

	// TODO: Implement advanced field mapping based on rule category
	_ = rule // Suppress unused variable warning for now

	// Basic event fields
	eventMap["EventID"] = event.Event.Code
	eventMap["ComputerName"] = event.Host.Name

	// User fields
	if event.User != nil {
		eventMap["TargetUserName"] = event.User.Name
		eventMap["TargetDomainName"] = event.User.Domain
		eventMap["User"] = event.User.Name
	}

	// Source IP
	if event.Source != nil {
		eventMap["IpAddress"] = event.Source.IP
		eventMap["SourceNetworkAddress"] = event.Source.IP
	}

	// Process fields
	if event.Process != nil {
		eventMap["Image"] = event.Process.Executable
		eventMap["CommandLine"] = event.Process.CommandLine
		eventMap["ProcessId"] = event.Process.PID

		if event.Process.Parent != nil {
			eventMap["ParentImage"] = event.Process.Parent.Executable
			eventMap["ParentCommandLine"] = event.Process.Parent.CommandLine
		}
	}

	// Winlog fields
	if event.Winlog != nil {
		eventMap["LogonType"] = event.Winlog.LogonType
		eventMap["Channel"] = event.Winlog.Channel

		if event.Winlog.Logon != nil && event.Winlog.Logon.Failure != nil {
			eventMap["Status"] = event.Winlog.Logon.Failure.Status
			eventMap["SubStatus"] = event.Winlog.Logon.Failure.SubStatus
		}
	}

	return eventMap
}

// evaluateCondition evaluate Sigma condition
func (s *SigmaEngine) evaluateCondition(condition string, selections map[string]interface{}, eventMap map[string]interface{}) bool {
	condition = strings.TrimSpace(condition)

	// Simple condition evaluation
	if selection, exists := selections[condition]; exists {
		return s.evaluateSelection(selection, eventMap)
	}

	// Handle "and" conditions
	if strings.Contains(condition, " and ") {
		parts := strings.Split(condition, " and ")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if selection, exists := selections[part]; exists {
				if !s.evaluateSelection(selection, eventMap) {
					return false
				}
			}
		}
		return true
	}

	// Handle "or" conditions
	if strings.Contains(condition, " or ") {
		parts := strings.Split(condition, " or ")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if selection, exists := selections[part]; exists {
				if s.evaluateSelection(selection, eventMap) {
					return true
				}
			}
		}
		return false
	}

	return false
}

// evaluateSelection evaluate một selection với event
func (s *SigmaEngine) evaluateSelection(selection interface{}, eventMap map[string]interface{}) bool {
	selMap, ok := selection.(map[string]interface{})
	if !ok {
		return false
	}

	// Tất cả conditions trong selection phải match
	for field, expectedValue := range selMap {
		if !s.matchField(field, expectedValue, eventMap) {
			return false
		}
	}

	return true
}

// matchField kiểm tra field match với expected value
func (s *SigmaEngine) matchField(field string, expectedValue interface{}, eventMap map[string]interface{}) bool {
	// Get actual value từ event
	actualValue, exists := eventMap[field]
	if !exists {
		return false
	}

	// Handle different value types
	switch exp := expectedValue.(type) {
	case string:
		return s.matchStringValue(exp, actualValue)
	case int:
		if actualInt, ok := actualValue.(int); ok {
			return exp == actualInt
		}
		if actualStr, ok := actualValue.(string); ok {
			return fmt.Sprintf("%d", exp) == actualStr
		}
		return false
	case []interface{}:
		// OR logic for array values
		for _, item := range exp {
			if s.matchField(field, item, eventMap) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// matchStringValue match string values với wildcard và contains
func (s *SigmaEngine) matchStringValue(expected string, actual interface{}) bool {
	actualStr, ok := actual.(string)
	if !ok {
		return false
	}

	// Case insensitive comparison
	expectedLower := strings.ToLower(expected)
	actualLower := strings.ToLower(actualStr)

	// Exact match
	if expectedLower == actualLower {
		return true
	}

	// Contains match (if expected contains wildcards or is substring)
	if strings.Contains(actualLower, expectedLower) {
		return true
	}

	// Wildcard match
	if strings.Contains(expected, "*") {
		pattern := strings.ReplaceAll(expectedLower, "*", ".*")
		matched, _ := regexp.MatchString("^"+pattern+"$", actualLower)
		return matched
	}

	return false
}

// GetRuleCount trả về số lượng rules đã load
func (s *SigmaEngine) GetRuleCount() int {
	s.rulesMutex.RLock()
	defer s.rulesMutex.RUnlock()
	return len(s.rules)
}

// GetRulesByCategory trả về rules theo category
func (s *SigmaEngine) GetRulesByCategory(category string) []*models.DetectionRule {
	s.rulesMutex.RLock()
	defer s.rulesMutex.RUnlock()

	var rules []*models.DetectionRule

	switch category {
	case "process_creation":
		for _, rule := range s.windowsProcessCreationRules {
			rules = append(rules, rule)
		}
	case "security":
		for _, rule := range s.windowsSecurityRules {
			rules = append(rules, rule)
		}
	case "powershell":
		for _, rule := range s.windowsPowerShellRules {
			rules = append(rules, rule)
		}
	default:
		for _, rule := range s.rules {
			rules = append(rules, rule)
		}
	}

	return rules
}

// GetAllRules trả về tất cả rules
func (s *SigmaEngine) GetAllRules() []*models.DetectionRule {
	s.rulesMutex.RLock()
	defer s.rulesMutex.RUnlock()

	var rules []*models.DetectionRule
	for _, rule := range s.rules {
		rules = append(rules, rule)
	}

	return rules
}
