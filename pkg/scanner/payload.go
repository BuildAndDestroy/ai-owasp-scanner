package scanner

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/BuildAndDestroy/owasp-scanner/pkg/models"
)

// PayloadTester handles payload testing and exploit detection
type PayloadTester struct {
	httpClient *http.Client
	userAgent  string
}

// NewPayloadTester creates a new PayloadTester instance
func NewPayloadTester(client *http.Client, userAgent string) *PayloadTester {
	return &PayloadTester{
		httpClient: client,
		userAgent:  userAgent,
	}
}

// TestPayloads tests all payloads against a URL
func (pt *PayloadTester) TestPayloads(targetURL string, payloads []string, baseline baselineData) []models.PayloadResult {
	var results []models.PayloadResult

	fmt.Printf("Testing %d payloads with confidence scoring...\n", len(payloads))

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return results
	}

	for i, payload := range payloads {
		if i > 0 && i%10 == 0 {
			fmt.Printf("  Tested %d/%d payloads...\n", i, len(payloads))
		}

		testURL := injectPayload(parsedURL, payload)

		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			results = append(results, models.PayloadResult{
				Payload:    payload,
				Error:      err.Error(),
				Confidence: models.ConfidenceLow,
			})
			continue
		}
		req.Header.Set("User-Agent", pt.userAgent)

		start := time.Now()
		resp, err := pt.httpClient.Do(req)
		responseTime := time.Since(start)

		result := models.PayloadResult{
			Payload:      payload,
			ResponseTime: responseTime,
		}

		if err != nil {
			result.Error = err.Error()
			result.Confidence = models.ConfidenceLow
		} else {
			result.StatusCode = resp.StatusCode
			body, _ := readBody(resp)
			result.ResponseLength = len(body)
			bodyStr := string(body)
			resp.Body.Close()

			analyzePayloadResponse(payload, &result, baseline, bodyStr)
		}

		results = append(results, result)
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Printf("✓ Completed payload testing\n")
	return results
}

// analyzePayloadResponse analyzes the response for exploit indicators
func analyzePayloadResponse(payload string, result *models.PayloadResult, baseline baselineData, body string) {
	var indicators []string
	confidence := models.ConfidencePlausible
	exploitDetected := false

	// SQL Injection indicators
	sqlErrors := []string{
		"SQL syntax error",
		"mysql_fetch",
		"pg_query",
		"ORA-",
		"SQLServer",
		"ODBC",
		"syntax error",
		"unclosed quotation",
		"quoted string not properly terminated",
	}

	for _, errPattern := range sqlErrors {
		if strings.Contains(strings.ToLower(body), strings.ToLower(errPattern)) {
			indicators = append(indicators, fmt.Sprintf("SQL error message: %s", errPattern))
			confidence = models.ConfidenceHigh
			exploitDetected = true
		}
	}

	// XSS indicators
	if strings.Contains(payload, "<script>") || strings.Contains(payload, "alert(") {
		if strings.Contains(body, payload) {
			indicators = append(indicators, "Payload reflected in response without sanitization")
			confidence = models.ConfidenceHigh
			exploitDetected = true
		} else if containsSimilarPattern(body, payload) {
			indicators = append(indicators, "Payload partially reflected")
			confidence = models.ConfidenceMedium
		}
	}

	// Path Traversal indicators
	if strings.Contains(payload, "../") || strings.Contains(payload, "..\\") {
		if strings.Contains(body, "root:") || strings.Contains(body, "[boot loader]") {
			indicators = append(indicators, "System file content detected in response")
			confidence = models.ConfidenceHigh
			exploitDetected = true
		}
	}

	// Command Injection indicators
	cmdPatterns := []string{"uid=", "gid=", "groups=", "Windows IP Configuration", "Volume Serial Number"}
	for _, pattern := range cmdPatterns {
		if strings.Contains(body, pattern) {
			indicators = append(indicators, fmt.Sprintf("Command execution output detected: %s", pattern))
			confidence = models.ConfidenceHigh
			exploitDetected = true
		}
	}

	// Timing-based analysis
	if strings.Contains(strings.ToLower(payload), "sleep") || strings.Contains(strings.ToLower(payload), "waitfor") {
		timeDiff := result.ResponseTime - baseline.responseTime
		if timeDiff > 5*time.Second {
			indicators = append(indicators, fmt.Sprintf("Significant delay detected: %v", timeDiff))
			confidence = models.ConfidenceHigh
			exploitDetected = true
		} else if timeDiff > 2*time.Second {
			indicators = append(indicators, fmt.Sprintf("Moderate delay detected: %v", timeDiff))
			confidence = models.ConfidenceMedium
		}
	}

	// Status code changes
	if baseline.statusCode != result.StatusCode {
		indicators = append(indicators, fmt.Sprintf("Status code changed: %d -> %d", baseline.statusCode, result.StatusCode))
		if result.StatusCode == 500 && confidence == models.ConfidencePlausible {
			confidence = models.ConfidenceMedium
		}
	}

	// Response length analysis
	lengthDiff := abs(baseline.responseLength - result.ResponseLength)
	percentChange := float64(lengthDiff) / float64(baseline.responseLength) * 100

	if percentChange > 50 {
		indicators = append(indicators, fmt.Sprintf("Significant response length change: %.1f%%", percentChange))
		if confidence == models.ConfidencePlausible {
			confidence = models.ConfidenceMedium
		}
	} else if percentChange > 20 {
		indicators = append(indicators, fmt.Sprintf("Response length changed: %.1f%%", percentChange))
	}

	// LDAP/XXE/SSRF indicators
	if strings.Contains(payload, "jndi:") || strings.Contains(payload, "<!ENTITY") {
		if strings.Contains(body, "Error") || result.StatusCode == 500 {
			indicators = append(indicators, "Injection attempt caused error state")
			confidence = models.ConfidenceMedium
		}
	}

	result.Confidence = confidence
	result.ExploitDetected = exploitDetected
	result.Indicators = indicators
}

// injectPayload injects a payload into a URL
func injectPayload(parsedURL *url.URL, payload string) string {
	query := parsedURL.Query()

	if len(query) > 0 {
		for key := range query {
			query.Set(key, payload)
			break
		}
	} else {
		query.Set("test", payload)
	}

	parsedURL.RawQuery = query.Encode()
	return parsedURL.String()
}

// containsSimilarPattern checks for partial payload reflection
func containsSimilarPattern(body, payload string) bool {
	if len(payload) > 10 {
		return strings.Contains(body, payload[:len(payload)/2])
	}
	return false
}

// abs returns the absolute value of an integer
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
