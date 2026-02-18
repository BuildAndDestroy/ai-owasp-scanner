package scanner

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
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

	body, _, statusCode, _, err := s.fetchPage(targetURL)
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

	// Fetch the page and gather software information
	body, headers, statusCode, software, err := s.fetchPage(targetURL)
	if err != nil {
		fmt.Printf("Error fetching %s: %v\n", targetURL, err)
		return
	}
	// augment with hints found in the HTML body and URL
	software = append(software, analyzeBodySoftware(body)...)
	software = append(software, analyzeURLSoftware(targetURL)...)

	fmt.Printf("  → HTTP %d for %s (%d bytes)\n", statusCode, targetURL, len(body))
	if len(software) > 0 {
		for _, s := range software {
			detailStr := s.Details
			if detailStr == "" {
				detailStr = s.Version
			}
			fmt.Printf("  → Detected software: %s %s %s\n", s.Name, s.Version, detailStr)
		}
	}

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
		Software:     software,
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

	// Fetch the page and capture any software information
	body, _, statusCode, software, err := s.fetchPage(targetURL)
	if err != nil {
		fmt.Printf("Error fetching %s: %v\n", targetURL, err)
		return
	}
	// also inspect body and URL for additional software clues
	software = append(software, analyzeBodySoftware(body)...)
	software = append(software, analyzeURLSoftware(targetURL)...)

	fmt.Printf("  → HTTP %d for %s (%d bytes)\n", statusCode, targetURL, len(body))
	if len(software) > 0 {
		for _, s := range software {
			detailStr := s.Details
			if detailStr == "" {
				detailStr = s.Version
			}
			fmt.Printf("  → Detected software: %s %s %s\n", s.Name, s.Version, detailStr)
		}
	}

	// Extract forms from the page (for crawl-only, we just count them)
	crawler := NewCrawler()
	forms := crawler.ExtractForms(body, parsedURL)

	// Thread-safe append to results
	s.resultsMutex.Lock()
	s.results = append(s.results, models.ScanResult{
		URL:        targetURL,
		Findings:   []models.Finding{}, // No findings in crawl-only mode
		FormsFound: forms,
		Software:   software,
		Timestamp:  time.Now(),
	})
	s.resultsMutex.Unlock()
}

// isSameDomain checks if a URL is within the same domain
func (s *Scanner) isSameDomain(targetURL *url.URL) bool {
	return strings.HasSuffix(targetURL.Host, s.baseURL.Host) ||
		targetURL.Host == s.baseURL.Host
}

// extractSoftwareInfo inspects response headers and TLS state to build
// a list of SoftwareInfo entries that can help fingerprint the server or
// connection.  It is invoked for every fetchPage call when crawler or
// scanner activity begins.
func extractSoftwareInfo(resp *http.Response) []models.SoftwareInfo {
	var software []models.SoftwareInfo

	// common headers that indicate server/platform
	headersToCheck := []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"}
	for _, h := range headersToCheck {
		if val := resp.Header.Get(h); val != "" {
			_, version := parseNameVersion(val)
			software = append(software, models.SoftwareInfo{
				Name:    h,
				Version: version,
				Details: val,
				Source:  "header:" + h,
			})
		}
	}

	// TLS/SSL information
	if resp.TLS != nil {
		// version
		software = append(software, models.SoftwareInfo{
			Name:    "TLS",
			Version: tlsVersionString(resp.TLS.Version),
			Source:  "tls",
		})

		// cipher suite
		software = append(software, models.SoftwareInfo{
			Name:    "CipherSuite",
			Details: tls.CipherSuiteName(resp.TLS.CipherSuite),
			Source:  "tls",
		})

		// certificate details (only first cert)
		if len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]
			details := fmt.Sprintf("subject=%s issuer=%s", cert.Subject.CommonName, cert.Issuer.CommonName)
			software = append(software, models.SoftwareInfo{
				Name:    "Certificate",
				Details: details,
				Source:  "tls",
			})
		}
	}

	return software
}

// analyzeURLSoftware inspects the requested URL for library filenames and
// version numbers. Useful when the content itself is not HTML (e.g. JS/CSS
// resources) but the filename indicates the software used.
func analyzeURLSoftware(rawurl string) []models.SoftwareInfo {
	var software []models.SoftwareInfo

	// patterns to look for in the path/query that include version
	libPatterns := map[string]*regexp.Regexp{
		"Jquery":    regexp.MustCompile(`(?i)jquery[-.]?(\d+\.\d+(?:\.\d+)*)`),
		"Bootstrap": regexp.MustCompile(`(?i)bootstrap[-.]?(\d+\.\d+(?:\.\d+)*)`),
		"React":     regexp.MustCompile(`(?i)react[-.]?(\d+\.\d+(?:\.\d+)*)`),
		"Angular":   regexp.MustCompile(`(?i)angular[-.]?(\d+\.\d+(?:\.\d+)*)`),
		"Vue":       regexp.MustCompile(`(?i)vue[-.]?(\d+\.\d+(?:\.\d+)*)`),
	}

	for name, re := range libPatterns {
		if m := re.FindStringSubmatch(rawurl); len(m) > 1 {
			software = append(software, models.SoftwareInfo{
				Name:    name,
				Version: m[1],
				Source:  "url:" + rawurl,
			})
		}
	}

	// catch libraries referenced by directory or file name without version
	plainLibs := []string{"jquery", "bootstrap", "react", "angular", "vue", "easing", "wow", "owlcarousel", "isotope", "lightbox", "touchSwipe"}
	for _, lib := range plainLibs {
		re := regexp.MustCompile(fmt.Sprintf(`(?i)%s`, lib))
		if re.MatchString(rawurl) {
			// only add if not already present
			exists := false
			for _, s := range software {
				if strings.EqualFold(s.Name, lib) {
					exists = true
					break
				}
			}
			if !exists {
				software = append(software, models.SoftwareInfo{Name: strings.Title(lib), Source: "url:" + rawurl})
			}
		}
	}

	return software
}

// parseNameVersion attempts to split a header value like "nginx/1.18.0" into
// name and version components.  If a slash is not present the entire string is
// considered the name and version is empty.
func parseNameVersion(val string) (string, string) {
	if strings.Contains(val, "/") {
		parts := strings.SplitN(val, "/", 2)
		name := parts[0]
		version := strings.Fields(parts[1])[0]
		return name, version
	}
	return val, ""
}

// tlsVersionString converts the uint16 constant to a human readable string.
func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionSSL30:
		return "SSLv3"
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("unknown(0x%x)", v)
	}
}

// analyzeBodySoftware inspects HTML body text to identify frameworks,
// CMS, JavaScript and CSS libraries, and other clues.  Detected items are
// returned as SoftwareInfo entries for inclusion in scan results.
func analyzeBodySoftware(body string) []models.SoftwareInfo {
	var software []models.SoftwareInfo

	// <meta name="generator" content="WordPress 5.8" />
	reGen := regexp.MustCompile(`(?i)<meta\s+name=["']generator["']\s+content=["']([^"']+)["']`)
	if m := reGen.FindStringSubmatch(body); len(m) > 1 {
		software = append(software, models.SoftwareInfo{
			Name:    "Generator",
			Details: m[1],
			Source:  "body:meta-generator",
		})
	}

	// comments or text like "Powered by WordPress 5.8"
	rePowered := regexp.MustCompile(`(?i)powered\s+by\s+([A-Za-z0-9_\-]+)(?:\s+(\d+(?:\.\d+)*))?`)
	if m := rePowered.FindStringSubmatch(body); len(m) > 1 {
		software = append(software, models.SoftwareInfo{
			Name:    m[1],
			Version: m[2],
			Source:  "body:powered-by",
		})
	}

	// look for license header patterns inside JS/CSS that often include name and version
	// allow for arbitrary text between library name and version (e.g. "jQuery JavaScript Library v3.5.1")
	// (?s) makes dot match newline so the pattern can span multiple lines
	licenseRe := regexp.MustCompile(`(?is)(jquery|angular|react|vue|bootstrap).*?v?(\d+\.\d+\.\d+)`)
	if m := licenseRe.FindStringSubmatch(body); len(m) > 2 {
		software = append(software, models.SoftwareInfo{
			Name:    strings.Title(m[1]),
			Version: m[2],
			Source:  "body:license",
		})
	}

	// script/src and link/href patterns for common libraries (with or without versions)
	libs := []string{"jquery", "react", "angular", "vue", "bootstrap", "easing", "wow", "owlcarousel", "isotope", "lightbox", "touchSwipe"}
	for _, lib := range libs {
		// versioned filenames in script src
		re := regexp.MustCompile(fmt.Sprintf(`(?i)<script[^>]+src=["']([^"']*%s[-.](\d+\.\d+(?:\.\d+)*)[^"']*)["']`, lib))
		if m := re.FindStringSubmatch(body); len(m) > 2 {
			software = append(software, models.SoftwareInfo{
				Name:    strings.Title(lib),
				Version: m[2],
				Source:  "body:script-src=" + m[1],
			})
			continue // skip unversioned check since we found versioned
		}

		// versioned filenames in link href
		reCss := regexp.MustCompile(fmt.Sprintf(`(?i)<link[^>]+href=["']([^"']*%s[-.](\d+\.\d+(?:\.\d+)*)[^"']*)["']`, lib))
		if m := reCss.FindStringSubmatch(body); len(m) > 2 {
			software = append(software, models.SoftwareInfo{
				Name:    strings.Title(lib),
				Version: m[2],
				Source:  "body:link-href=" + m[1],
			})
			continue // skip unversioned check since we found versioned
		}

		// unversioned script src with full path capture
		reScriptSrc := regexp.MustCompile(fmt.Sprintf(`(?i)<script[^>]+src=["']([^"']*%s[^"']*)["']`, lib))
		if m := reScriptSrc.FindStringSubmatch(body); len(m) > 1 {
			// m[1] is the full src attribute value
			exists := false
			for _, s := range software {
				if strings.EqualFold(s.Name, lib) {
					exists = true
					break
				}
			}
			if !exists {
				software = append(software, models.SoftwareInfo{Name: strings.Title(lib), Source: "body:script-src=" + m[1]})
				continue
			}
		}

		// unversioned link href with full path capture
		reLinkHref := regexp.MustCompile(fmt.Sprintf(`(?i)<link[^>]+href=["']([^"']*%s[^"']*)["']`, lib))
		if m := reLinkHref.FindStringSubmatch(body); len(m) > 1 {
			// m[1] is the full href attribute value
			exists := false
			for _, s := range software {
				if strings.EqualFold(s.Name, lib) {
					exists = true
					break
				}
			}
			if !exists {
				software = append(software, models.SoftwareInfo{Name: strings.Title(lib), Source: "body:link-href=" + m[1]})
			}
		}
	}

	// generic platform patterns
	patterns := map[string]*regexp.Regexp{
		"PHP":     regexp.MustCompile(`(?i)php/(\d+\.\d+(?:\.\d+)?)`),
		"ASP.NET": regexp.MustCompile(`(?i)asp\.net`),
		"Ruby":    regexp.MustCompile(`(?i)ruby`),
		"Python":  regexp.MustCompile(`(?i)python`),
		// match "java" as a whole word to avoid matching "javascript"
		"Java": regexp.MustCompile(`(?i)\bjava\b`),
		"Go":   regexp.MustCompile(`(?i)\bgo\b`),
	}
	for name, re := range patterns {
		if m := re.FindStringSubmatch(body); len(m) > 0 {
			version := ""
			if len(m) > 1 {
				version = m[1]
			}
			software = append(software, models.SoftwareInfo{
				Name:    name,
				Version: version,
			})
		}
	}

	return software
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

// fetchPage fetches a web page and returns its body, headers, status code and any software information
func (s *Scanner) fetchPage(targetURL string) (string, http.Header, int, []models.SoftwareInfo, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return "", nil, 0, nil, err
	}
	req.Header.Set("User-Agent", s.config.UserAgent)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", nil, 0, nil, err
	}
	defer resp.Body.Close()

	body, err := readBody(resp)
	if err != nil {
		return "", nil, resp.StatusCode, nil, err
	}

	software := extractSoftwareInfo(resp)

	return string(body), resp.Header, resp.StatusCode, software, nil
}
