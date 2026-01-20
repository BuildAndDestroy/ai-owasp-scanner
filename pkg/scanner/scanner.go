package scanner

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/BuildAndDestroy/owasp-scanner/pkg/config"
	"github.com/BuildAndDestroy/owasp-scanner/pkg/models"
)

// Scanner handles the web vulnerability scanning
type Scanner struct {
	baseURL       *url.URL
	visited       map[string]bool
	results       []models.ScanResult
	config        *config.Config
	httpClient    *http.Client
	baselineCache map[string]baselineData
	analyzer      *Analyzer
}

type baselineData struct {
	statusCode     int
	responseLength int
	responseTime   time.Duration
}

// New creates a new Scanner instance
func New(cfg *config.Config) (*Scanner, error) {
	parsedURL, err := url.Parse(cfg.TargetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target URL: %w", err)
	}

	analyzer, err := NewAnalyzer(cfg.OllamaURL, cfg.OllamaModel)
	if err != nil {
		return nil, fmt.Errorf("failed to create analyzer: %w", err)
	}

	return &Scanner{
		baseURL:       parsedURL,
		visited:       make(map[string]bool),
		results:       []models.ScanResult{},
		config:        cfg,
		httpClient:    &http.Client{Timeout: cfg.Timeout},
		baselineCache: make(map[string]baselineData),
		analyzer:      analyzer,
	}, nil
}

// Scan performs the vulnerability scan
func (s *Scanner) Scan() []models.ScanResult {
	s.scanURL(s.config.TargetURL, 0)
	return s.results
}

// Visited returns the visited URLs map
func (s *Scanner) Visited() map[string]bool {
	return s.visited
}

// scanURL recursively scans a URL and its links
func (s *Scanner) scanURL(targetURL string, depth int) {
	if depth > s.config.MaxDepth || s.visited[targetURL] {
		return
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return
	}

	if !s.isSameDomain(parsedURL) {
		return
	}

	s.visited[targetURL] = true
	fmt.Printf("\n[Depth %d] Scanning: %s\n", depth, targetURL)

	scanStart := time.Now()

	// Establish baseline
	baseline := s.getBaseline(targetURL)

	// Fetch the page
	body, headers, err := s.fetchPage(targetURL)
	if err != nil {
		fmt.Printf("Error fetching %s: %v\n", targetURL, err)
		return
	}

	// Test payloads if provided
	var payloadResults []models.PayloadResult
	if len(s.config.Payloads()) > 0 {
		tester := NewPayloadTester(s.httpClient, s.config.UserAgent)
		payloadResults = tester.TestPayloads(targetURL, s.config.Payloads(), baseline)
	}

	// Analyze for OWASP vulnerabilities
	findings := s.analyzer.Analyze(targetURL, body, headers, payloadResults)
	scanDuration := time.Since(scanStart)

	if len(findings) > 0 || len(payloadResults) > 0 {
		s.results = append(s.results, models.ScanResult{
			URL:          targetURL,
			Findings:     findings,
			PayloadTests: payloadResults,
			Timestamp:    time.Now(),
			ScanDuration: scanDuration,
		})
	}

	// Extract and scan links
	crawler := NewCrawler()
	links := crawler.ExtractLinks(body, parsedURL)
	for _, link := range links {
		s.scanURL(link, depth+1)
	}
}

// isSameDomain checks if a URL is within the same domain
func (s *Scanner) isSameDomain(targetURL *url.URL) bool {
	return strings.HasSuffix(targetURL.Host, s.baseURL.Host) ||
		targetURL.Host == s.baseURL.Host
}

// getBaseline establishes a baseline for the URL
func (s *Scanner) getBaseline(targetURL string) baselineData {
	if baseline, exists := s.baselineCache[targetURL]; exists {
		return baseline
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return baselineData{}
	}
	req.Header.Set("User-Agent", s.config.UserAgent)

	start := time.Now()
	resp, err := s.httpClient.Do(req)
	responseTime := time.Since(start)

	baseline := baselineData{
		responseTime: responseTime,
	}

	if err == nil {
		baseline.statusCode = resp.StatusCode
		body, _ := readBody(resp)
		baseline.responseLength = len(body)
		resp.Body.Close()
	}

	s.baselineCache[targetURL] = baseline
	return baseline
}

// fetchPage fetches a web page and returns its body and headers
func (s *Scanner) fetchPage(targetURL string) (string, http.Header, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("User-Agent", s.config.UserAgent)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	body, err := readBody(resp)
	if err != nil {
		return "", nil, err
	}

	return string(body), resp.Header, nil
}
