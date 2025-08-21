// ====================================================================
// EDR DETECTION ENGINE - EVENT MODELS
// ====================================================================
// Tác giả: Senior Software Engineer - EDR Platform Team
// Mô tả: Định nghĩa các model cho events và alerts
// ====================================================================

package models

import (
	"encoding/json"
	"time"
)

// Event đại diện cho một sự kiện từ endpoint
type Event struct {
	// Metadata cơ bản
	Timestamp time.Time `json:"@timestamp"`
	ID        string    `json:"id,omitempty"`

	// Host information
	Host HostInfo `json:"host"`

	// Agent information
	Agent AgentInfo `json:"agent"`

	// Event details
	Event EventDetails `json:"event"`

	// Process information (cho process events)
	Process *ProcessInfo `json:"process,omitempty"`

	// Network information (cho network events)
	Network     *NetworkInfo     `json:"network,omitempty"`
	Source      *NetworkEndpoint `json:"source,omitempty"`
	Destination *NetworkEndpoint `json:"destination,omitempty"`

	// File information (cho file events)
	File *FileInfo `json:"file,omitempty"`

	// User information
	User *UserInfo `json:"user,omitempty"`

	// Windows Event Log specific fields
	Winlog *WinlogInfo `json:"winlog,omitempty"`

	// Raw message
	Message string `json:"message,omitempty"`

	// ECS version
	ECS ECSInfo `json:"ecs"`

	// Additional fields
	Labels map[string]string `json:"labels,omitempty"`
}

// HostInfo chứa thông tin về endpoint
type HostInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	OS   OSInfo `json:"os,omitempty"`
}

// OSInfo chứa thông tin về hệ điều hành
type OSInfo struct {
	Platform string `json:"platform,omitempty"` // windows, linux
	Family   string `json:"family,omitempty"`   // windows, unix
	Name     string `json:"name,omitempty"`     // Windows 10, Ubuntu
	Version  string `json:"version,omitempty"`
}

// AgentInfo chứa thông tin về agent
type AgentInfo struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Version string `json:"version"`
}

// EventDetails chứa thông tin chi tiết về event
type EventDetails struct {
	Kind     string   `json:"kind"`               // event, alert, metric
	Category []string `json:"category,omitempty"` // process, network, file, etc.
	Type     []string `json:"type,omitempty"`     // start, end, creation, etc.
	Action   string   `json:"action,omitempty"`   // process_created, network_connection
	Outcome  string   `json:"outcome,omitempty"`  // success, failure
	Provider string   `json:"provider,omitempty"` // Microsoft-Windows-Sysmon
	Code     string   `json:"code,omitempty"`     // Event ID
	Module   string   `json:"module,omitempty"`   // sysmon, security
	Original string   `json:"original,omitempty"` // Raw event message
}

// ProcessInfo chứa thông tin về process
type ProcessInfo struct {
	PID         int          `json:"pid,omitempty"`
	EntityID    string       `json:"entity_id,omitempty"`  // Process GUID
	Executable  string       `json:"executable,omitempty"` // Full path
	Name        string       `json:"name,omitempty"`       // Process name
	CommandLine string       `json:"command_line,omitempty"`
	Start       *time.Time   `json:"start,omitempty"`
	Hash        *HashInfo    `json:"hash,omitempty"`
	Parent      *ProcessInfo `json:"parent,omitempty"`
}

// NetworkInfo chứa thông tin về network connection
type NetworkInfo struct {
	Transport string `json:"transport,omitempty"` // tcp, udp
	Direction string `json:"direction,omitempty"` // inbound, outbound
	Type      string `json:"type,omitempty"`      // internal, external
	Initiated bool   `json:"initiated,omitempty"` // Connection initiated by process
}

// NetworkEndpoint chứa thông tin về network endpoint
type NetworkEndpoint struct {
	IP     string `json:"ip,omitempty"`
	Port   int    `json:"port,omitempty"`
	Domain string `json:"domain,omitempty"`
}

// FileInfo chứa thông tin về file
type FileInfo struct {
	Path      string     `json:"path,omitempty"`
	Name      string     `json:"name,omitempty"`
	Extension string     `json:"extension,omitempty"`
	Size      int64      `json:"size,omitempty"`
	Created   *time.Time `json:"created,omitempty"`
	Hash      *HashInfo  `json:"hash,omitempty"`
}

// HashInfo chứa thông tin hash của file/process
type HashInfo struct {
	SHA256 string `json:"sha256,omitempty"`
	MD5    string `json:"md5,omitempty"`
}

// UserInfo chứa thông tin về user
type UserInfo struct {
	Name   string `json:"name,omitempty"`
	Domain string `json:"domain,omitempty"`
	ID     string `json:"id,omitempty"`
}

// WinlogInfo chứa thông tin Windows Event Log specific
type WinlogInfo struct {
	EventID      int              `json:"event_id,omitempty"`
	Channel      string           `json:"channel,omitempty"`
	ComputerName string           `json:"computer_name,omitempty"`
	LogonType    int              `json:"logon_type,omitempty"`
	Logon        *WinlogLogonInfo `json:"logon,omitempty"`
}

// WinlogLogonInfo chứa thông tin về logon events
type WinlogLogonInfo struct {
	Failure *WinlogLogonFailure `json:"failure,omitempty"`
}

// WinlogLogonFailure chứa thông tin về logon failures
type WinlogLogonFailure struct {
	Reason    string `json:"reason,omitempty"`
	Status    string `json:"status,omitempty"`
	SubStatus string `json:"sub_status,omitempty"`
}

// ECSInfo chứa thông tin về ECS version
type ECSInfo struct {
	Version string `json:"version"`
}

// Alert đại diện cho một alert được generate từ detection rule
type Alert struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"@timestamp"`
	RuleID      string    `json:"rule_id"`
	RuleName    string    `json:"rule_name"`
	Severity    string    `json:"severity"` // low, medium, high, critical
	Status      string    `json:"status"`   // open, closed, suppressed
	Description string    `json:"description"`

	// MITRE ATT&CK information
	MITRE MITREInfo `json:"mitre,omitempty"`

	// Related events
	Events []Event `json:"events"`

	// Host affected
	Host HostInfo `json:"host"`

	// Additional context
	Context map[string]interface{} `json:"context,omitempty"`

	// Timestamps
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	// Count of related events
	Count int `json:"count"`
}

// MITREInfo chứa thông tin về MITRE ATT&CK
type MITREInfo struct {
	TechniqueID   string `json:"technique_id,omitempty"`   // T1055
	TechniqueName string `json:"technique_name,omitempty"` // Process Injection
	TacticID      string `json:"tactic_id,omitempty"`      // TA0005
	TacticName    string `json:"tactic_name,omitempty"`    // Defense Evasion
	SubTechnique  string `json:"sub_technique,omitempty"`  // T1055.001
}

// DetectionRule đại diện cho một Sigma rule đã được parse
type DetectionRule struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Status      string `json:"status"` // stable, test, experimental
	Level       string `json:"level"`  // low, medium, high, critical
	Author      string `json:"author"`
	Date        string `json:"date"`
	Modified    string `json:"modified,omitempty"`

	// MITRE ATT&CK tags
	Tags []string `json:"tags"`

	// Log source specification
	LogSource LogSourceSpec `json:"logsource"`

	// Detection logic
	Detection DetectionLogic `json:"detection"`

	// False positives
	FalsePositives []string `json:"falsepositives,omitempty"`

	// References
	References []string `json:"references,omitempty"`
}

// LogSourceSpec định nghĩa nguồn log mà rule áp dụng
type LogSourceSpec struct {
	Category string `json:"category,omitempty"` // process_creation, network_connection
	Product  string `json:"product,omitempty"`  // windows, linux
	Service  string `json:"service,omitempty"`  // sysmon, security
}

// DetectionLogic chứa logic detection của rule
type DetectionLogic struct {
	// Selection conditions
	Selections map[string]interface{} `json:"selections"`

	// Condition logic
	Condition string `json:"condition"`

	// Timeframe (for correlation rules)
	Timeframe string `json:"timeframe,omitempty"`
}

// ParseEvent parse JSON event từ Vector thành Event struct
func ParseEvent(data []byte) (*Event, error) {
	var event Event
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, err
	}

	// Set ID nếu chưa có
	if event.ID == "" {
		event.ID = generateEventID()
	}

	return &event, nil
}

// ToJSON chuyển Event thành JSON
func (e *Event) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// ToJSON chuyển Alert thành JSON
func (a *Alert) ToJSON() ([]byte, error) {
	return json.Marshal(a)
}

// generateEventID tạo unique ID cho event
func generateEventID() string {
	// Simple implementation - trong production nên dùng UUID
	return time.Now().Format("20060102150405") + "-" + randomString(8)
}

// randomString tạo random string
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}

// MatchesLogSource kiểm tra event có match với log source của rule không
func (e *Event) MatchesLogSource(logSource LogSourceSpec) bool {
	// Kiểm tra category
	if logSource.Category != "" {
		found := false
		for _, category := range e.Event.Category {
			if category == logSource.Category {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Kiểm tra product
	if logSource.Product != "" {
		if e.Host.OS.Platform != logSource.Product {
			return false
		}
	}

	// Kiểm tra service
	if logSource.Service != "" {
		if e.Event.Module != logSource.Service {
			return false
		}
	}

	return true
}

// GetSeverityScore trả về điểm số severity (để sắp xếp)
func (a *Alert) GetSeverityScore() int {
	switch a.Severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// IsProcessEvent kiểm tra có phải process event không
func (e *Event) IsProcessEvent() bool {
	for _, category := range e.Event.Category {
		if category == "process" {
			return true
		}
	}
	return false
}

// IsNetworkEvent kiểm tra có phải network event không
func (e *Event) IsNetworkEvent() bool {
	for _, category := range e.Event.Category {
		if category == "network" {
			return true
		}
	}
	return false
}

// IsFileEvent kiểm tra có phải file event không
func (e *Event) IsFileEvent() bool {
	for _, category := range e.Event.Category {
		if category == "file" {
			return true
		}
	}
	return false
}
