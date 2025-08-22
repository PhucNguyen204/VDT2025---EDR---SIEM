package event

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Event implements the sigma.Event interface for dynamic events
type Event struct {
	data map[string]interface{}
}

// ParseEvent parses raw JSON into an Event
func ParseEvent(raw json.RawMessage) (Event, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return Event{}, fmt.Errorf("failed to unmarshal event: %w", err)
	}

	return Event{data: data}, nil
}

// Keywords implements sigma.Keyworder interface
// Returns relevant string fields that could contain keywords
func (e Event) Keywords() ([]string, bool) {
	keywords := []string{}

	// Common fields that might contain keywords
	keywordFields := []string{
		"message",
		"msg",
		"command_line",
		"CommandLine",
		"process.command_line",
		"powershell.command.value",
		"file.path",
		"registry.path",
		"dns.question.name",
		"http.request.body.content",
		"alert.signature",
		"payload_printable",
		"cs-uri-query",
		"cs-uri-stem",
		"url.query",
		"url.original",
		"http.request.body",
		"request_body",
	}

	for _, field := range keywordFields {
		if val, ok := e.getNestedValue(field); ok {
			if str, ok := val.(string); ok && str != "" {
				keywords = append(keywords, str)
			}
		}
	}

	// Also check for Windows event specific fields
	if winlog, ok := e.data["winlog"].(map[string]interface{}); ok {
		if eventData, ok := winlog["event_data"].(map[string]interface{}); ok {
			for _, v := range eventData {
				if str, ok := v.(string); ok && str != "" {
					keywords = append(keywords, str)
				}
			}
		}
	}

	// Debug: log extracted keywords
	if len(keywords) > 0 {
		for _, keyword := range keywords {
			if strings.Contains(keyword, "<script>") || strings.Contains(keyword, "select") || strings.Contains(keyword, "=") {
				fmt.Printf("[DEBUG] Extracted keyword: %s\n", keyword)
			}
		}
	}

	return keywords, len(keywords) > 0
}

// Select implements sigma.Selector interface
// Handles field selection with dot notation support
func (e Event) Select(field string) (interface{}, bool) {
	// First try direct lookup
	if val, ok := e.data[field]; ok {
		return val, true
	}

	// Try nested lookup
	if val, ok := e.getNestedValue(field); ok {
		return val, true
	}

	// Handle special field mappings for Sigma compatibility
	mappedValue, found := e.handleFieldMapping(field)
	if found {
		return mappedValue, true
	}

	return nil, false
}

// GetData returns the underlying event data
func (e Event) GetData() map[string]interface{} {
	return e.data
}

// getNestedValue retrieves nested values using dot notation
func (e Event) getNestedValue(path string) (interface{}, bool) {
	parts := strings.Split(path, ".")
	current := interface{}(e.data)

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			val, ok := v[part]
			if !ok {
				return nil, false
			}
			current = val
		default:
			return nil, false
		}
	}

	return current, true
}

// handleFieldMapping handles common field mappings for Sigma rules
func (e Event) handleFieldMapping(field string) (interface{}, bool) {
	// Debug: log field lookups for web events
	if strings.Contains(field, "cs-") || strings.Contains(field, "sc-") {
		// This helps debug web field mappings
	}

	// Map common Sigma fields to ECS-like fields
	fieldMappings := map[string][]string{
		// Windows Event Log mappings
		"EventID":           {"event.code", "winlog.event_id"},
		"Channel":           {"winlog.channel"},
		"Computer":          {"host.name", "winlog.computer_name"},
		"TargetUserName":    {"user.name", "winlog.event_data.TargetUserName"},
		"TargetDomainName":  {"user.domain", "winlog.event_data.TargetDomainName"},
		"SubjectUserName":   {"winlog.event_data.SubjectUserName"},
		"SubjectDomainName": {"winlog.event_data.SubjectDomainName"},
		"LogonType":         {"winlog.logon_type", "winlog.event_data.LogonType"},
		"IpAddress":         {"source.ip", "winlog.event_data.IpAddress"},
		"Status":            {"winlog.event_data.Status"},
		"SubStatus":         {"winlog.event_data.SubStatus"},

		// Process mappings
		"CommandLine":       {"process.command_line", "winlog.event_data.CommandLine"},
		"Image":             {"process.executable", "winlog.event_data.Image"},
		"ParentImage":       {"process.parent.executable", "winlog.event_data.ParentImage"},
		"ProcessName":       {"process.name", "winlog.event_data.ProcessName"},
		"ParentProcessName": {"process.parent.name", "winlog.event_data.ParentProcessName"},
		"OriginalFileName":  {"process.original_file_name", "winlog.event_data.OriginalFileName"},
		"Company":           {"process.company", "winlog.event_data.Company"},
		"Product":           {"process.product", "winlog.event_data.Product"},
		"Description":       {"process.description", "winlog.event_data.Description"},
		"User":              {"user.name", "winlog.event_data.User"},
		"IntegrityLevel":    {"process.integrity_level", "winlog.event_data.IntegrityLevel"},
		"ProcessId":         {"process.pid", "winlog.event_data.ProcessId"},
		"ParentProcessId":   {"process.parent.pid", "winlog.event_data.ParentProcessId"},

		// File mappings
		"TargetFilename": {"file.path", "winlog.event_data.TargetFilename"},
		"FileName":       {"file.name", "winlog.event_data.FileName"},
		"FilePath":       {"file.path", "winlog.event_data.FilePath"},

		// Registry mappings
		"TargetObject": {"registry.path", "winlog.event_data.TargetObject"},
		"Details":      {"registry.data.strings", "winlog.event_data.Details"},

		// Network mappings
		"DestinationIp":   {"destination.ip", "winlog.event_data.DestinationIp"},
		"DestinationPort": {"destination.port", "winlog.event_data.DestinationPort"},
		"SourceIp":        {"source.ip", "winlog.event_data.SourceIp"},
		"SourcePort":      {"source.port", "winlog.event_data.SourcePort"},

		// DNS mappings
		"QueryName":    {"dns.question.name", "winlog.event_data.QueryName"},
		"QueryResults": {"dns.answers", "winlog.event_data.QueryResults"},

		// PowerShell mappings
		"ScriptBlockText": {"powershell.command.value", "winlog.event_data.ScriptBlockText"},
		"Path":            {"file.path", "winlog.event_data.Path"},

		// Web server mappings (Common Log Format and Extended)
		"cs-method":     {"http.request.method", "cs-method"},
		"cs-uri-stem":   {"url.path", "cs-uri-stem"},
		"cs-uri-query":  {"url.query", "cs-uri-query"},
		"sc-status":     {"http.response.status_code", "sc-status"},
		"c-ip":          {"source.ip", "c-ip"},
		"cs-user-agent": {"user_agent.original", "cs-user-agent"},
		"cs-referer":    {"http.request.referrer", "cs-referer"},
		"cs-host":       {"url.domain", "cs-host"},
		"cs-bytes":      {"http.request.bytes", "cs-bytes"},
		"sc-bytes":      {"http.response.bytes", "sc-bytes"},
		"time-taken":    {"event.duration", "time-taken"},
	}

	// Check if we have a mapping for this field
	if mappedFields, ok := fieldMappings[field]; ok {
		for _, mappedField := range mappedFields {
			if val, ok := e.getNestedValue(mappedField); ok {
				return val, true
			}
		}
	}

	// Try to find field in winlog.event_data
	if val, ok := e.getNestedValue("winlog.event_data." + field); ok {
		return val, true
	}

	return nil, false
}
