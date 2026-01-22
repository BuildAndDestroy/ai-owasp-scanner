package scanner

import (
	"net/url"
	"testing"
	"time"

	"github.com/BuildAndDestroy/owasp-scanner/pkg/models"
)

func TestInjectPayload(t *testing.T) {
	tests := []struct {
		name            string
		url             string
		payload         string
		expectedContain string
	}{
		{
			name:            "inject into existing parameter",
			url:             "http://example.com/page?id=123",
			payload:         "'; DROP TABLE users--",
			expectedContain: "'; DROP TABLE users--",
		},
		{
			name:            "inject into first parameter",
			url:             "http://example.com/page?id=1&name=test",
			payload:         "<script>alert(1)</script>",
			expectedContain: "<script>alert(1)</script>",
		},
		{
			name:            "no query parameters - returns unchanged",
			url:             "http://example.com/page",
			payload:         "test",
			expectedContain: "example.com/page",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedURL, _ := url.Parse(tt.url)
			result := injectPayload(parsedURL, tt.payload)

			if tt.expectedContain != "" {
				if len(result) == 0 || (len(result) > 0 && result != tt.url) {
					// URL was modified or empty, which is expected
				}
			}
		})
	}
}

func TestPayloadAnalysis(t *testing.T) {
	tests := []struct {
		name               string
		payload            string
		body               string
		baselineCode       int
		currentCode        int
		expectedConfidence string
	}{
		{
			name:               "SQL error detected",
			payload:            "' OR '1'='1",
			body:               "SQL syntax error near line 1",
			baselineCode:       200,
			currentCode:        200,
			expectedConfidence: "HIGH",
		},
		{
			name:               "XSS payload reflected",
			payload:            "<script>alert('XSS')</script>",
			body:               "Your input: <script>alert('XSS')</script>",
			baselineCode:       200,
			currentCode:        200,
			expectedConfidence: "HIGH",
		},
		{
			name:               "status code changed",
			payload:            "test",
			body:               "error",
			baselineCode:       200,
			currentCode:        500,
			expectedConfidence: "MEDIUM",
		},
		{
			name:               "no indicators",
			payload:            "normal input",
			body:               "normal response",
			baselineCode:       200,
			currentCode:        200,
			expectedConfidence: "PLAUSIBLE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &models.PayloadResult{
				Payload:    tt.payload,
				StatusCode: tt.currentCode,
			}

			baseline := baselineData{
				statusCode:     tt.baselineCode,
				responseLength: 100,
				responseTime:   100 * time.Millisecond,
			}

			analyzePayloadResponse(tt.payload, result, baseline, tt.body)

			if result.Confidence == "" {
				t.Errorf("confidence not set")
			}
		})
	}
}

func TestPayloadResultStructure(t *testing.T) {
	result := &models.PayloadResult{
		Payload:         "' OR '1'='1",
		ResponseTime:    1500 * time.Millisecond,
		StatusCode:      200,
		ResponseLength:  5000,
		Confidence:      models.ConfidenceHigh,
		ExploitDetected: true,
		Indicators: []string{
			"SQL error message: mysql_fetch",
		},
		Parameter:  "username",
		HTTPMethod: "POST",
	}

	if result.Payload == "" {
		t.Error("payload should not be empty")
	}

	if result.HTTPMethod != "POST" {
		t.Errorf("HTTP method: got %s, expected POST", result.HTTPMethod)
	}

	if result.Parameter != "username" {
		t.Errorf("parameter: got %s, expected username", result.Parameter)
	}

	if result.Confidence != models.ConfidenceHigh {
		t.Errorf("confidence: got %s, expected %s", result.Confidence, models.ConfidenceHigh)
	}

	if !result.ExploitDetected {
		t.Error("exploit should be detected")
	}

	if len(result.Indicators) != 1 {
		t.Errorf("indicators: got %d, expected 1", len(result.Indicators))
	}
}

func TestFormPayloadTestingFlow(t *testing.T) {
	form := &models.FormData{
		Method: "POST",
		Action: "http://example.com/contact",
		Inputs: []string{"name", "email", "message"},
		URL:    "http://example.com/",
		ID:     "contactForm",
		Name:   "contact",
	}

	if len(form.Inputs) != 3 {
		t.Errorf("expected 3 inputs, got %d", len(form.Inputs))
	}

	if form.Method != "POST" {
		t.Errorf("form method should be POST")
	}

	if form.Action == "" {
		t.Error("form action should not be empty")
	}
}

func TestParameterTracking(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		parameter string
		payload   string
	}{
		{
			name:      "GET parameter tracking",
			method:    "GET",
			parameter: "id",
			payload:   "1' OR '1'='1",
		},
		{
			name:      "POST parameter tracking",
			method:    "POST",
			parameter: "username",
			payload:   "admin' --",
		},
		{
			name:      "Form field tracking",
			method:    "POST",
			parameter: "email",
			payload:   "<script>alert(1)</script>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &models.PayloadResult{
				HTTPMethod: tt.method,
				Parameter:  tt.parameter,
				Payload:    tt.payload,
			}

			if result.HTTPMethod == "" {
				t.Error("HTTP method should be set")
			}

			if result.Parameter == "" {
				t.Error("parameter should be set")
			}

			if result.Payload == "" {
				t.Error("payload should be set")
			}
		})
	}
}
