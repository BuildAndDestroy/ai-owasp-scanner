package models

import (
	"testing"
	"time"
)

func TestConfidenceLevelValues(t *testing.T) {
	tests := []struct {
		name       string
		confidence ConfidenceLevel
		expected   string
	}{
		{"high", ConfidenceHigh, "HIGH"},
		{"medium", ConfidenceMedium, "MEDIUM"},
		{"low", ConfidenceLow, "LOW"},
		{"plausible", ConfidencePlausible, "PLAUSIBLE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.confidence) != tt.expected {
				t.Errorf("got %s, expected %s", tt.confidence, tt.expected)
			}
		})
	}
}

func TestFindingStructure(t *testing.T) {
	finding := Finding{
		Category:    "Injection",
		Description: "SQL injection vulnerability",
		Confidence:  ConfidenceHigh,
		Evidence:    "Error: syntax error in query",
		Severity:    "CRITICAL",
	}

	if finding.Category == "" {
		t.Error("category should not be empty")
	}

	if finding.Confidence != ConfidenceHigh {
		t.Errorf("confidence should be HIGH")
	}
}

func TestPayloadResultStructure(t *testing.T) {
	result := PayloadResult{
		Payload:         "' OR '1'='1",
		ResponseTime:    1500 * time.Millisecond,
		StatusCode:      200,
		ResponseLength:  5000,
		Error:           "",
		Confidence:      ConfidenceHigh,
		ExploitDetected: true,
		Indicators:      []string{"SQL error detected"},
		Parameter:       "username",
		HTTPMethod:      "POST",
	}

	if result.Payload == "" {
		t.Error("payload should not be empty")
	}

	if result.HTTPMethod != "POST" {
		t.Errorf("HTTP method should be POST")
	}

	if result.Parameter != "username" {
		t.Errorf("parameter should be username")
	}

	if result.StatusCode != 200 {
		t.Errorf("status code should be 200")
	}
}

func TestFormDataStructure(t *testing.T) {
	form := FormData{
		Method: "POST",
		Action: "http://example.com/submit",
		Inputs: []string{"name", "email", "message"},
		URL:    "http://example.com/contact",
		ID:     "contactForm",
		Name:   "contact",
	}

	if form.Method != "POST" {
		t.Error("method should be POST")
	}

	if len(form.Inputs) != 3 {
		t.Errorf("should have 3 inputs, got %d", len(form.Inputs))
	}

	if form.Action == "" {
		t.Error("action should not be empty")
	}
}

func TestSoftwareInfoStructure(t *testing.T) {
	info := SoftwareInfo{
		Name:    "Server",
		Version: "1.2.3",
		Details: "TestServer/1.2.3",
		Source:  "header:Server",
	}

	if info.Name == "" {
		t.Error("name should not be empty")
	}

	if info.Version != "1.2.3" {
		t.Errorf("version should be 1.2.3, got %s", info.Version)
	}

	if info.Source == "" {
		t.Error("source should be populated")
	}
}
func TestScanResultStructure(t *testing.T) {
	now := time.Now()

	scanResult := ScanResult{
		URL: "http://example.com",
		Findings: []Finding{
			{
				Category:    "Injection",
				Description: "SQL injection",
				Confidence:  ConfidenceHigh,
			},
		},
		PayloadTests: []PayloadResult{
			{
				Payload:    "' OR '1'='1",
				HTTPMethod: "POST",
				Parameter:  "username",
			},
		},
		FormsFound: []FormData{
			{
				Method: "POST",
				Action: "http://example.com/login",
				Inputs: []string{"username", "password"},
			},
		},
		Software: []SoftwareInfo{
			{Name: "Server", Version: "TestServer/1.0"},
		},
		Timestamp:    now,
		ScanDuration: 5 * time.Second,
	}

	if scanResult.URL == "" {
		t.Error("URL should not be empty")
	}

	if len(scanResult.Findings) != 1 {
		t.Error("should have 1 finding")
	}

	if len(scanResult.PayloadTests) != 1 {
		t.Error("should have 1 payload test")
	}

	if len(scanResult.FormsFound) != 1 {
		t.Error("should have 1 form")
	}

	if len(scanResult.Software) != 1 {
		t.Error("should have 1 software entry")
	}
}

func TestScanReportStructure(t *testing.T) {
	startTime := time.Now()
	endTime := startTime.Add(10 * time.Second)

	report := ScanReport{
		TargetURL:         "http://example.com",
		ScanStartTime:     startTime,
		ScanEndTime:       endTime,
		TotalDuration:     endTime.Sub(startTime),
		PagesScanned:      5,
		PayloadsUsed:      29,
		Results:           []ScanResult{},
		HighConfidence:    2,
		MediumConfidence:  1,
		LowConfidence:     0,
		PlausibleFindings: 3,
		ConfirmedExploits: 1,
	}

	if report.TargetURL == "" {
		t.Error("target URL should not be empty")
	}

	if report.PagesScanned != 5 {
		t.Errorf("pages scanned should be 5, got %d", report.PagesScanned)
	}

	if report.PayloadsUsed != 29 {
		t.Errorf("payloads used should be 29, got %d", report.PayloadsUsed)
	}

	if report.HighConfidence != 2 {
		t.Errorf("high confidence should be 2, got %d", report.HighConfidence)
	}
}

func TestPayloadResultTracking(t *testing.T) {
	results := []PayloadResult{
		{
			Payload:         "payload1",
			HTTPMethod:      "GET",
			Parameter:       "id",
			StatusCode:      200,
			ExploitDetected: false,
		},
		{
			Payload:         "payload2",
			HTTPMethod:      "POST",
			Parameter:       "username",
			StatusCode:      500,
			ExploitDetected: true,
		},
		{
			Payload:         "payload3",
			HTTPMethod:      "POST",
			Parameter:       "email",
			StatusCode:      200,
			ExploitDetected: false,
		},
	}

	// Verify tracking
	getCount := 0
	postCount := 0
	exploitCount := 0

	for _, r := range results {
		if r.HTTPMethod == "GET" {
			getCount++
		} else if r.HTTPMethod == "POST" {
			postCount++
		}
		if r.ExploitDetected {
			exploitCount++
		}
	}

	if getCount != 1 {
		t.Errorf("expected 1 GET, got %d", getCount)
	}

	if postCount != 2 {
		t.Errorf("expected 2 POST, got %d", postCount)
	}

	if exploitCount != 1 {
		t.Errorf("expected 1 exploit, got %d", exploitCount)
	}
}
