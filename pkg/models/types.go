package models

import "time"

// ConfidenceLevel represents the confidence in a finding
type ConfidenceLevel string

const (
	ConfidenceHigh      ConfidenceLevel = "HIGH"
	ConfidenceMedium    ConfidenceLevel = "MEDIUM"
	ConfidenceLow       ConfidenceLevel = "LOW"
	ConfidencePlausible ConfidenceLevel = "PLAUSIBLE"
)

// Finding represents a security vulnerability finding
type Finding struct {
	Category    string          `json:"category"`
	Description string          `json:"description"`
	Confidence  ConfidenceLevel `json:"confidence"`
	Evidence    string          `json:"evidence"`
	Severity    string          `json:"severity"`
}

// FormData represents a discovered form on a page
type FormData struct {
	Method string   `json:"method"`
	Action string   `json:"action"`
	Inputs []string `json:"input_names"`
	URL    string   `json:"found_on_url"`
	ID     string   `json:"form_id,omitempty"`
	Name   string   `json:"form_name,omitempty"`
}

// PayloadResult represents the result of testing a single payload
type PayloadResult struct {
	Payload         string          `json:"payload"`
	ResponseTime    time.Duration   `json:"response_time_ms"`
	StatusCode      int             `json:"status_code"`
	ResponseLength  int             `json:"response_length"`
	Error           string          `json:"error,omitempty"`
	Confidence      ConfidenceLevel `json:"confidence"`
	ExploitDetected bool            `json:"exploit_detected"`
	Indicators      []string        `json:"indicators,omitempty"`
	Parameter       string          `json:"parameter,omitempty"`
	HTTPMethod      string          `json:"http_method,omitempty"`
}

// SoftwareInfo describes a piece of software or platform component
// discovered on the target system.  By keeping it generic we can record
// headers such as `Server` / `X-Powered-By` as well as TLS versions and
// certificate metadata.
type SoftwareInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Details string `json:"details,omitempty"`
	Source  string `json:"source,omitempty"` // where the information was observed (header,url,body, tls, etc.)
}

// ScanResult represents the complete scan result for a single URL
type ScanResult struct {
	URL          string          `json:"url"`
	Findings     []Finding       `json:"findings"`
	PayloadTests []PayloadResult `json:"payload_tests,omitempty"`
	FormsFound   []FormData      `json:"forms_found,omitempty"`
	Software     []SoftwareInfo  `json:"software,omitempty"`
	Timestamp    time.Time       `json:"timestamp"`
	ScanDuration time.Duration   `json:"scan_duration_ms"`
}

// ScanReport represents the complete scan report
type ScanReport struct {
	TargetURL         string        `json:"target_url"`
	ScanStartTime     time.Time     `json:"scan_start_time"`
	ScanEndTime       time.Time     `json:"scan_end_time"`
	TotalDuration     time.Duration `json:"total_duration_ms"`
	PagesScanned      int           `json:"pages_scanned"`
	PayloadsUsed      int           `json:"payloads_used"`
	Results           []ScanResult  `json:"results"`
	HighConfidence    int           `json:"high_confidence_findings"`
	MediumConfidence  int           `json:"medium_confidence_findings"`
	LowConfidence     int           `json:"low_confidence_findings"`
	PlausibleFindings int           `json:"plausible_findings"`
	ConfirmedExploits int           `json:"confirmed_exploits"`
}
