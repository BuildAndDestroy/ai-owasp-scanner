package scanner

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
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
	visitedMutex  sync.RWMutex
	resultsMutex  sync.Mutex
	baselineMutex sync.RWMutex
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
	// First, collect all URLs to scan using breadth-first search
	allURLs := s.collectURLs(s.config.TargetURL, s.config.MaxDepth)

	// Then process them in parallel
	return s.processURLsInParallel(allURLs)
}

// collectURLs performs breadth-first search to collect all URLs
func (s *Scanner) collectURLs(startURL string, maxDepth int) []scanTask {
	var allURLs []scanTask
	visited := make(map[string]bool)
	queue := []scanTask{{url: startURL, depth: 0}}

	// Limit the number of URLs to prevent memory issues
	const maxURLs = 10000

	for len(queue) > 0 && len(allURLs) < maxURLs {
		task := queue[0]
		queue = queue[1:]

		if task.depth > maxDepth || visited[task.url] {
			continue
		}

		visited[task.url] = true
		allURLs = append(allURLs, task)

		// Show progress every 100 URLs
		if len(allURLs)%100 == 0 && len(allURLs) > 0 {
			fmt.Printf("Collected %d URLs so far (depth %d)...\n", len(allURLs), task.depth)
		}

		// Get links from this URL
		if len(allURLs) < maxURLs && task.depth < maxDepth {
			links := s.getLinksFromURL(task.url)
			for _, link := range links {
				if !visited[link] && len(queue) < maxURLs {
					queue = append(queue, scanTask{url: link, depth: task.depth + 1})
					fmt.Printf("  → Queued: %s\n", link)
				} else if visited[link] {
					fmt.Printf("  → Skipped (already visited): %s\n", link)
				}
			}
		}
	}

	if len(allURLs) >= maxURLs {
		fmt.Printf("Warning: Reached maximum URL limit (%d), stopping collection\n", maxURLs)
	}

	fmt.Printf("Collected %d URLs for processing\n", len(allURLs))
	return allURLs
}

// getLinksFromURL fetches a URL and extracts links
func (s *Scanner) getLinksFromURL(targetURL string) []string {
	fmt.Printf("  → Fetching: %s\n", targetURL)

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		fmt.Printf("  → Error parsing URL %s: %v\n", targetURL, err)
		return nil
	}

	if !s.isSameDomain(parsedURL) {
		fmt.Printf("  → Skipped (external domain): %s\n", targetURL)
		return nil
	}

	body, _, statusCode, err := s.fetchPage(targetURL)
	if err != nil {
		fmt.Printf("  → Error fetching %s: %v\n", targetURL, err)
		return nil
	}

	fmt.Printf("  → HTTP %d for %s (%d bytes)\n", statusCode, targetURL, len(body))

	crawler := NewCrawler()
	links := crawler.ExtractLinks(body, parsedURL)
	fmt.Printf("  → Extracted %d links from %s\n", len(links), targetURL)

	return links
}

// processURLsInParallel processes URLs in parallel using worker pool
func (s *Scanner) processURLsInParallel(urls []scanTask) []models.ScanResult {
	if len(urls) == 0 {
		return s.results
	}

	urlChan := make(chan scanTask, len(urls))

	// Start worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < s.config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range urlChan {
				s.processURL(task.url, task.depth)
			}
		}()
	}

	// Send all URLs to workers
	for _, url := range urls {
		urlChan <- url
	}
	close(urlChan)

	wg.Wait()
	return s.results
}

type scanTask struct {
	url   string
	depth int
}

// CrawlOnly performs crawling without OWASP analysis
func (s *Scanner) CrawlOnly() []models.ScanResult {
	// First, collect all URLs to crawl using breadth-first search
	allURLs := s.collectURLs(s.config.TargetURL, s.config.MaxDepth)

	// Then process them in parallel
	return s.crawlURLsInParallel(allURLs)
}

// crawlURLsInParallel processes URLs in parallel for crawling
func (s *Scanner) crawlURLsInParallel(urls []scanTask) []models.ScanResult {
	if len(urls) == 0 {
		return s.results
	}

	urlChan := make(chan scanTask, len(urls))

	// Start worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < s.config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range urlChan {
				s.crawlProcessURL(task.url, task.depth)
			}
		}()
	}

	// Send all URLs to workers
	for _, url := range urls {
		urlChan <- url
	}
	close(urlChan)

	wg.Wait()
	return s.results
}

// Visited returns the visited URLs map
func (s *Scanner) Visited() map[string]bool {
	return s.visited
}

// processURL processes a single URL for scanning (non-recursive, thread-safe)
func (s *Scanner) processURL(targetURL string, depth int) {
	// Check if already visited (thread-safe)
	s.visitedMutex.Lock()
	if s.visited[targetURL] {
		s.visitedMutex.Unlock()
		return
	}
	s.visited[targetURL] = true
	s.visitedMutex.Unlock()

	if depth > s.config.MaxDepth {
		return
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return
	}

	if !s.isSameDomain(parsedURL) {
		return
	}

	fmt.Printf("\n[Depth %d] Scanning: %s\n", depth, targetURL)

	scanStart := time.Now()

	// Establish baseline
	baseline := s.getBaseline(targetURL)

	// Fetch the page
	body, headers, statusCode, err := s.fetchPage(targetURL)
	if err != nil {
		fmt.Printf("Error fetching %s: %v\n", targetURL, err)
		return
	}

	fmt.Printf("  → HTTP %d for %s (%d bytes)\n", statusCode, targetURL, len(body))

	// Extract forms from the page
	crawler := NewCrawler()
	forms := crawler.ExtractForms(body, parsedURL)

	if len(forms) > 0 {
		fmt.Printf("Found %d form(s) on %s\n", len(forms), targetURL)
		for _, f := range forms {
			fmt.Printf("  - Form: %s %s -> %s (inputs: %v)\n", f.Method, f.Action, f.ID, f.Inputs)
		}
	}

	// Test payloads if provided
	var payloadResults []models.PayloadResult
	if len(s.config.Payloads()) > 0 {
		tester := NewPayloadTester(s.httpClient, s.config.UserAgent)
		// Only test GET parameters if URL has query parameters or forms exist
		if len(parsedURL.Query()) > 0 {
			payloadResults = tester.TestPayloads(targetURL, s.config.Payloads(), baseline, forms)
		} else if len(forms) > 0 {
			// If no query params but forms exist, we'll test forms instead via POST
			fmt.Printf("No query parameters found on %s, will test via POST forms instead\n", targetURL)
		}
	}

	// Analyze for OWASP vulnerabilities
	findings := s.analyzer.Analyze(targetURL, body, headers, payloadResults)
	scanDuration := time.Since(scanStart)

	// Test payloads on forms
	var formPayloadResults []models.PayloadResult
	if len(s.config.Payloads()) > 0 && len(forms) > 0 {
		tester := NewPayloadTester(s.httpClient, s.config.UserAgent)
		for _, form := range forms {
			formResults := tester.TestPayloadsOnForm(&form, s.config.Payloads(), baseline)
			formPayloadResults = append(formPayloadResults, formResults...)
		}
	}

	// Combine all payload results
	allPayloadResults := append(payloadResults, formPayloadResults...)

	// Thread-safe append to results
	s.resultsMutex.Lock()
	s.results = append(s.results, models.ScanResult{
		URL:          targetURL,
		Findings:     findings,
		PayloadTests: allPayloadResults,
		FormsFound:   forms,
		Timestamp:    time.Now(),
		ScanDuration: scanDuration,
	})
	s.resultsMutex.Unlock()
}

// crawlProcessURL processes a single URL for crawling (non-recursive, thread-safe)
func (s *Scanner) crawlProcessURL(targetURL string, depth int) {
	// Check if already visited (thread-safe)
	s.visitedMutex.Lock()
	if s.visited[targetURL] {
		s.visitedMutex.Unlock()
		return
	}
	s.visited[targetURL] = true
	s.visitedMutex.Unlock()

	if depth > s.config.MaxDepth {
		return
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return
	}

	if !s.isSameDomain(parsedURL) {
		return
	}

	fmt.Printf("\n[Depth %d] Crawling: %s\n", depth, targetURL)

	// Fetch the page
	body, _, statusCode, err := s.fetchPage(targetURL)
	if err != nil {
		fmt.Printf("Error fetching %s: %v\n", targetURL, err)
		return
	}

	fmt.Printf("  → HTTP %d for %s (%d bytes)\n", statusCode, targetURL, len(body))

	// Extract forms from the page (for crawl-only, we just count them)
	crawler := NewCrawler()
	forms := crawler.ExtractForms(body, parsedURL)

	// Thread-safe append to results
	s.resultsMutex.Lock()
	s.results = append(s.results, models.ScanResult{
		URL:        targetURL,
		Findings:   []models.Finding{}, // No findings in crawl-only mode
		FormsFound: forms,
		Timestamp:  time.Now(),
	})
	s.resultsMutex.Unlock()
}

// isSameDomain checks if a URL is within the same domain
func (s *Scanner) isSameDomain(targetURL *url.URL) bool {
	return strings.HasSuffix(targetURL.Host, s.baseURL.Host) ||
		targetURL.Host == s.baseURL.Host
}

// getBaseline establishes a baseline for the URL
func (s *Scanner) getBaseline(targetURL string) baselineData {
	s.baselineMutex.RLock()
	if baseline, exists := s.baselineCache[targetURL]; exists {
		s.baselineMutex.RUnlock()
		return baseline
	}
	s.baselineMutex.RUnlock()

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

	s.baselineMutex.Lock()
	s.baselineCache[targetURL] = baseline
	s.baselineMutex.Unlock()

	return baseline
}

// fetchPage fetches a web page and returns its body, headers, and status code
func (s *Scanner) fetchPage(targetURL string) (string, http.Header, int, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return "", nil, 0, err
	}
	req.Header.Set("User-Agent", s.config.UserAgent)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", nil, 0, err
	}
	defer resp.Body.Close()

	body, err := readBody(resp)
	if err != nil {
		return "", nil, resp.StatusCode, err
	}

	return string(body), resp.Header, resp.StatusCode, nil
}
