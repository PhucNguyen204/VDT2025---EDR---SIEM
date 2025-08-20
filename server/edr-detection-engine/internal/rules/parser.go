// ====================================================================
// EDR DETECTION ENGINE - SIGMA RULE PARSER
// ====================================================================
// Tác giả: Senior Software Engineer - EDR Platform Team
// Mô tả: Parser để đọc và parse Sigma rules từ YAML
// ====================================================================

package rules

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"edr-detection-engine/internal/models"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// SigmaRuleYAML đại diện cho cấu trúc YAML của Sigma rule
type SigmaRuleYAML struct {
	Title          string                 `yaml:"title"`
	ID             string                 `yaml:"id"`
	Description    string                 `yaml:"description"`
	Status         string                 `yaml:"status"`
	Level          string                 `yaml:"level"`
	Author         string                 `yaml:"author"`
	Date           string                 `yaml:"date"`
	Modified       string                 `yaml:"modified"`
	Tags           []string               `yaml:"tags"`
	References     []string               `yaml:"references"`
	FalsePositives []string               `yaml:"falsepositives"`
	LogSource      LogSourceYAML          `yaml:"logsource"`
	Detection      map[string]interface{} `yaml:"detection"`
}

// LogSourceYAML đại diện cho log source trong YAML
type LogSourceYAML struct {
	Category string `yaml:"category"`
	Product  string `yaml:"product"`
	Service  string `yaml:"service"`
}

// RuleParser chịu trách nhiệm parse Sigma rules
type RuleParser struct {
	logger *logrus.Logger
}

// NewRuleParser tạo instance mới của RuleParser
func NewRuleParser() *RuleParser {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	return &RuleParser{
		logger: logger,
	}
}

// ParseRuleFile parse một file rule YAML
func (p *RuleParser) ParseRuleFile(filePath string) (*models.DetectionRule, error) {
	p.logger.Debugf("Parsing rule file: %s", filePath)

	// Đọc file
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read rule file %s: %v", filePath, err)
	}

	// Parse YAML
	var sigmaRule SigmaRuleYAML
	if err := yaml.Unmarshal(data, &sigmaRule); err != nil {
		return nil, fmt.Errorf("failed to parse YAML in %s: %v", filePath, err)
	}

	// Validate rule
	if err := p.validateRule(&sigmaRule); err != nil {
		return nil, fmt.Errorf("invalid rule in %s: %v", filePath, err)
	}

	// Convert sang internal model
	rule := p.convertToDetectionRule(&sigmaRule)

	p.logger.Infof("Successfully parsed rule: %s (%s)", rule.Title, rule.ID)
	return rule, nil
}

// ParseRulesDirectory parse tất cả rules trong một directory
func (p *RuleParser) ParseRulesDirectory(dirPath string) ([]*models.DetectionRule, error) {
	p.logger.Infof("Parsing rules directory: %s", dirPath)

	var rules []*models.DetectionRule
	var errors []string

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Chỉ parse file .yml và .yaml
		if !info.IsDir() && (strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
			rule, parseErr := p.ParseRuleFile(path)
			if parseErr != nil {
				errors = append(errors, fmt.Sprintf("Error parsing %s: %v", path, parseErr))
				p.logger.Warnf("Failed to parse rule %s: %v", path, parseErr)
			} else {
				rules = append(rules, rule)
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory %s: %v", dirPath, err)
	}

	p.logger.Infof("Successfully parsed %d rules from %s", len(rules), dirPath)
	if len(errors) > 0 {
		p.logger.Warnf("Encountered %d parsing errors", len(errors))
		for _, errMsg := range errors {
			p.logger.Debug(errMsg)
		}
	}

	return rules, nil
}

// validateRule kiểm tra tính hợp lệ của rule
func (p *RuleParser) validateRule(rule *SigmaRuleYAML) error {
	if rule.Title == "" {
		return fmt.Errorf("rule title is required")
	}

	if rule.ID == "" {
		return fmt.Errorf("rule ID is required")
	}

	if rule.Detection == nil || len(rule.Detection) == 0 {
		return fmt.Errorf("detection section is required")
	}

	// Kiểm tra có condition không
	if _, hasCondition := rule.Detection["condition"]; !hasCondition {
		return fmt.Errorf("detection condition is required")
	}

	return nil
}

// convertToDetectionRule chuyển đổi từ YAML struct sang internal model
func (p *RuleParser) convertToDetectionRule(sigmaRule *SigmaRuleYAML) *models.DetectionRule {
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
		References:     sigmaRule.References,
		FalsePositives: sigmaRule.FalsePositives,
		LogSource: models.LogSourceSpec{
			Category: sigmaRule.LogSource.Category,
			Product:  sigmaRule.LogSource.Product,
			Service:  sigmaRule.LogSource.Service,
		},
	}

	// Parse detection logic
	rule.Detection = p.parseDetectionLogic(sigmaRule.Detection)

	return rule
}

// parseDetectionLogic parse phần detection của rule
func (p *RuleParser) parseDetectionLogic(detection map[string]interface{}) models.DetectionLogic {
	logic := models.DetectionLogic{
		Selections: make(map[string]interface{}),
	}

	// Tách condition và selections
	for key, value := range detection {
		if key == "condition" {
			if condStr, ok := value.(string); ok {
				logic.Condition = condStr
			}
		} else if key == "timeframe" {
			if timeStr, ok := value.(string); ok {
				logic.Timeframe = timeStr
			}
		} else {
			// Đây là selection
			logic.Selections[key] = value
		}
	}

	return logic
}

// GetSupportedCategories trả về danh sách categories được hỗ trợ
func (p *RuleParser) GetSupportedCategories() []string {
	return []string{
		"process_creation",
		"network_connection",
		"file_event",
		"registry_event",
		"image_load",
		"dns_query",
		"pipe_created",
	}
}

// FilterRulesByCategory lọc rules theo category
func (p *RuleParser) FilterRulesByCategory(rules []*models.DetectionRule, category string) []*models.DetectionRule {
	var filtered []*models.DetectionRule

	for _, rule := range rules {
		if rule.LogSource.Category == category {
			filtered = append(filtered, rule)
		}
	}

	p.logger.Infof("Filtered %d rules for category '%s'", len(filtered), category)
	return filtered
}

// FilterRulesByProduct lọc rules theo product (windows/linux)
func (p *RuleParser) FilterRulesByProduct(rules []*models.DetectionRule, product string) []*models.DetectionRule {
	var filtered []*models.DetectionRule

	for _, rule := range rules {
		if rule.LogSource.Product == "" || rule.LogSource.Product == product {
			filtered = append(filtered, rule)
		}
	}

	p.logger.Infof("Filtered %d rules for product '%s'", len(filtered), product)
	return filtered
}

// FilterRulesByLevel lọc rules theo severity level
func (p *RuleParser) FilterRulesByLevel(rules []*models.DetectionRule, minLevel string) []*models.DetectionRule {
	levelPriority := map[string]int{
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}

	minPriority, exists := levelPriority[minLevel]
	if !exists {
		p.logger.Warnf("Unknown level '%s', using 'low'", minLevel)
		minPriority = 1
	}

	var filtered []*models.DetectionRule

	for _, rule := range rules {
		rulePriority, exists := levelPriority[rule.Level]
		if !exists {
			rulePriority = 1 // Default to low
		}

		if rulePriority >= minPriority {
			filtered = append(filtered, rule)
		}
	}

	p.logger.Infof("Filtered %d rules with level >= '%s'", len(filtered), minLevel)
	return filtered
}

// GetRuleStats trả về thống kê về rules
func (p *RuleParser) GetRuleStats(rules []*models.DetectionRule) map[string]interface{} {
	stats := map[string]interface{}{
		"total":       len(rules),
		"by_status":   make(map[string]int),
		"by_level":    make(map[string]int),
		"by_category": make(map[string]int),
		"by_product":  make(map[string]int),
	}

	for _, rule := range rules {
		// Count by status
		if statusMap, ok := stats["by_status"].(map[string]int); ok {
			statusMap[rule.Status]++
		}

		// Count by level
		if levelMap, ok := stats["by_level"].(map[string]int); ok {
			levelMap[rule.Level]++
		}

		// Count by category
		if categoryMap, ok := stats["by_category"].(map[string]int); ok {
			categoryMap[rule.LogSource.Category]++
		}

		// Count by product
		if productMap, ok := stats["by_product"].(map[string]int); ok {
			productMap[rule.LogSource.Product]++
		}
	}

	return stats
}
