package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/BuildAndDestroy/owasp-scanner/pkg/models"
)

// Analyzer handles AI-powered vulnerability analysis
type Analyzer struct {
	ollamaURL   string
	ollamaModel string
}

type ollamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type ollamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

// NewAnalyzer creates a new Analyzer instance
func NewAnalyzer(ollamaURL, ollamaModel string) (*Analyzer, error) {
	return &Analyzer{
		ollamaURL:   ollamaURL,
		ollamaModel: ollamaModel,
	}, nil
}

// Analyze performs AI-powered vulnerability analysis
func (a *Analyzer) Analyze(url, body string, headers http.Header, payloadResults []models.PayloadResult) []models.Finding {
	prompt := a.buildPrompt(url, body, headers, payloadResults)

	response, err := a.callOllama(prompt)
	if err != nil {
		fmt.Printf("Error calling Ollama: %v\n", err)
		return nil
	}

	findings := a.parseFindings(response)

	if len(findings) > 0 {
		highCount := 0
		for _, f := range findings {
			if f.Confidence == models.ConfidenceHigh {
				highCount++
			}
		}
		fmt.Printf("⚠️  Found %d findings (%d high confidence)\n", len(findings), highCount)
	} else {
		fmt.Println("✓ No vulnerabilities detected")
	}

	return findings
}

// buildPrompt constructs the AI prompt for vulnerability analysis
func (a *Analyzer) buildPrompt(url, body string, headers http.Header, payloadResults []models.PayloadResult) string {
	maxBodyLen := 4000
	truncatedBody := body
	if len(body) > maxBodyLen {
		truncatedBody = body[:maxBodyLen] + "...[truncated]"
	}

	headerStr := ""
	for key, values := range headers {
		headerStr += fmt.Sprintf("%s: %s\n", key, strings.Join(values, ", "))
	}

	exploitInfo := ""
	if len(payloadResults) > 0 {
		exploitInfo = "\n\nPAYLOAD TEST RESULTS:\n"
		for _, pr := range payloadResults {
			if pr.ExploitDetected {
				exploitInfo += fmt.Sprintf("CONFIRMED EXPLOIT - %s: %v\n", pr.Payload, pr.Indicators)
			}
		}
	}

	prompt := fmt.Sprintf(`You are a security expert analyzing a web page for OWASP Top 10 vulnerabilities.

URL: %s

HTTP Headers:
%s

HTML Content (partial):
%s
%s

Analyze this page and assign CONFIDENCE LEVELS to each finding:
- HIGH: Strong evidence of exploitable vulnerability (missing critical headers, confirmed exploits, obvious flaws)
- MEDIUM: Likely vulnerability but needs verification (suspicious patterns, weak configurations)
- LOW: Potential issue but uncertain (could be false positive)
- PLAUSIBLE: Theoretical concern without concrete evidence

OWASP Top 10 Categories:
1. Broken Access Control
2. Cryptographic Failures
3. Injection (SQL, XSS, etc.)
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable and Outdated Components
7. Identification and Authentication Failures
8. Software and Data Integrity Failures
9. Security Logging and Monitoring Failures
10. Server-Side Request Forgery (SSRF)

For each finding, respond in this EXACT format:
FINDING: [Category] | [CONFIDENCE_LEVEL] | [SEVERITY] | [Description] | [Evidence]

CONFIDENCE_LEVEL must be: HIGH, MEDIUM, LOW, or PLAUSIBLE
SEVERITY must be: CRITICAL, HIGH, MEDIUM, or LOW

Examples:
FINDING: Security Misconfiguration | HIGH | HIGH | Missing HSTS header | Strict-Transport-Security header not found
FINDING: Injection | MEDIUM | CRITICAL | Potential XSS in form | Input field lacks sanitization attributes

If no vulnerabilities found, respond with:
NO_VULNERABILITIES_FOUND`, url, headerStr, truncatedBody, exploitInfo)

	return prompt
}

// callOllama makes an API call to Ollama
func (a *Analyzer) callOllama(prompt string) (string, error) {
	reqBody := ollamaRequest{
		Model:  a.ollamaModel,
		Prompt: prompt,
		Stream: false,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	resp, err := http.Post(
		a.ollamaURL+"/api/generate",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var ollamaResp ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return "", err
	}

	return ollamaResp.Response, nil
}

// parseFindings extracts findings from Ollama response
func (a *Analyzer) parseFindings(response string) []models.Finding {
	var findings []models.Finding

	if strings.Contains(response, "NO_VULNERABILITIES_FOUND") {
		return findings
	}

	lines := strings.Split(response, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "FINDING:") {
			if finding := parseFindingLine(line); finding != nil {
				findings = append(findings, *finding)
			}
		}
	}

	return findings
}

// parseFindingLine parses a single finding line
func parseFindingLine(line string) *models.Finding {
	line = strings.TrimPrefix(line, "FINDING:")
	line = strings.TrimSpace(line)

	parts := strings.Split(line, "|")
	if len(parts) < 5 {
		return nil
	}

	category := strings.TrimSpace(parts[0])
	confidenceStr := strings.TrimSpace(parts[1])
	severity := strings.TrimSpace(parts[2])
	description := strings.TrimSpace(parts[3])
	evidence := strings.TrimSpace(parts[4])

	var confidence models.ConfidenceLevel
	switch strings.ToUpper(confidenceStr) {
	case "HIGH":
		confidence = models.ConfidenceHigh
	case "MEDIUM":
		confidence = models.ConfidenceMedium
	case "LOW":
		confidence = models.ConfidenceLow
	case "PLAUSIBLE":
		confidence = models.ConfidencePlausible
	default:
		confidence = models.ConfidencePlausible
	}

	return &models.Finding{
		Category:    category,
		Description: description,
		Confidence:  confidence,
		Evidence:    evidence,
		Severity:    severity,
	}
}
