package scanner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BuildAndDestroy/owasp-scanner/pkg/config"
)

func TestScannerCrawlOnly(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><body><a href="/page1">Page 1</a><a href="/page2">Page 2</a></body></html>`))
		case "/page1":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><body>Page 1 content</body></html>`))
		case "/page2":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><body>Page 2 content</body></html>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create config for crawl-only mode
	cfg := &config.Config{
		TargetURL: server.URL,
		MaxDepth:  2,
		CrawlOnly: true,
		Threads:   2,
		Timeout:   5 * time.Second,
	}

	scanner, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	// Run crawl-only scan
	results := scanner.CrawlOnly()

	// Verify results
	if len(results) == 0 {
		t.Fatal("Should have found URLs")
	}

	// Should find at least the root URL and the two linked pages
	if len(results) < 3 {
		t.Errorf("Expected at least 3 results, got %d", len(results))
	}

	// Check that URLs contain expected paths
	foundRoot := false
	foundPage1 := false
	foundPage2 := false

	for _, result := range results {
		switch result.URL {
		case server.URL:
			foundRoot = true
		case server.URL + "/page1":
			foundPage1 = true
		case server.URL + "/page2":
			foundPage2 = true
		}
	}

	if !foundRoot {
		t.Error("Root URL should be found")
	}
	if !foundPage1 {
		t.Error("Page 1 URL should be found")
	}
	if !foundPage2 {
		t.Error("Page 2 URL should be found")
	}
}

func TestScannerThreading(t *testing.T) {
	// Create a test server with multiple pages
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond) // Simulate processing time
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>Content</body></html>`))
	}))
	defer server.Close()

	// Test with different thread counts
	for _, threads := range []int{1, 2, 4} {
		t.Run(fmt.Sprintf("threads_%d", threads), func(t *testing.T) {
			cfg := &config.Config{
				TargetURL: server.URL,
				MaxDepth:  1,
				CrawlOnly: true,
				Threads:   threads,
				Timeout:   5 * time.Second,
			}

			scanner, err := New(cfg)
			if err != nil {
				t.Fatalf("Failed to create scanner: %v", err)
			}

			start := time.Now()
			results := scanner.CrawlOnly()
			duration := time.Since(start)

			if len(results) == 0 {
				t.Fatalf("Should have results for %d threads", threads)
			}

			// With threading, it should complete reasonably quickly
			if duration > 1*time.Second {
				t.Errorf("Scan with %d threads took too long: %v", threads, duration)
			}
		})
	}
}

func TestScannerURLLimit(t *testing.T) {
	// Create a test server that generates many links
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Generate many links to test URL limit
		html := `<html><body>`
		for i := 0; i < 50; i++ {
			html += fmt.Sprintf(`<a href="/page%d">Page %d</a>`, i, i)
		}
		html += `</body></html>`
		w.Write([]byte(html))
	}))
	defer server.Close()

	cfg := &config.Config{
		TargetURL: server.URL,
		MaxDepth:  1,
		CrawlOnly: true,
		Threads:   2,
		Timeout:   5 * time.Second,
	}

	scanner, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	results := scanner.CrawlOnly()

	// Should be limited to prevent runaway collection
	if len(results) > 10000 {
		t.Errorf("URL count should be limited, got %d", len(results))
	}
}
func TestSoftwareEnumeration(t *testing.T) {
	// create an HTTPS test server so we can also check TLS details
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "TestServer/1.2")
		w.Header().Set("X-Powered-By", "GoUnit")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><head>
			<meta name="generator" content="UnitCMS 2.3" />
			<link rel="stylesheet" href="/css/bootstrap-5.1.3.min.css" />
			<script src="/js/jquery-3.6.0.min.js"></script>
		</head><body>ok powered by UnitCMS</body></html>`))
	}))
	defer server.Close()

	cfg := &config.Config{
		TargetURL: server.URL,
		MaxDepth:  0,
		CrawlOnly: true,
		Threads:   1,
		Timeout:   5 * time.Second,
	}

	scanner, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	// trust the test server's self-signed certificate
	scanner.httpClient = server.Client()

	results := scanner.CrawlOnly()
	if len(results) == 0 {
		t.Fatal("Expected at least one result from crawl")
	}

	info := results[0].Software
	if len(info) == 0 {
		t.Error("Expected software information to be populated")
	}

	foundServer := false
	foundTLS := false
	foundGen := false
	foundJquery := false
	foundCMS := false
	for _, s := range info {
		if s.Source == "" {
			t.Errorf("software entry %+v missing source", s)
		}
		switch s.Name {
		case "Server":
			if strings.Contains(s.Details, "TestServer") {
				foundServer = true
			}
		case "TLS":
			foundTLS = true
		case "Generator":
			if strings.Contains(s.Details, "UnitCMS") {
				foundGen = true
			}
		case "Jquery":
			if s.Version == "3.6.0" {
				foundJquery = true
			}
		case "Powered":
			// ignore
		case "Bootstrap":
			// ignore
		}
		if s.Name == "UnitCMS" || strings.Contains(strings.ToLower(s.Name), "unitcms") {
			foundCMS = true
		}
	}
	if !foundServer {
		t.Error("Server header not recorded in software info")
	}
	if !foundTLS {
		t.Error("TLS version not recorded in software info")
	}
	if !foundGen {
		t.Error("Generator meta tag not detected")
	}
	if !foundJquery {
		t.Error("jQuery version not detected from script src")
	}
	if !foundCMS {
		t.Error("CMS (UnitCMS) not identified via body heuristics")
	}
}

func TestAnalyzeURLSoftware(t *testing.T) {
	url := "http://example.com/assets/jquery-3.3.1.min.js"
	software := analyzeURLSoftware(url)
	found := false
	for _, s := range software {
		if s.Source == "" {
			t.Errorf("entry %+v has no source", s)
		}
		if s.Name == "Jquery" && s.Version == "3.3.1" {
			found = true
		}
		if s.Name == "Java" {
			t.Error("unexpected Java detection from URL")
		}
	}
	if !found {
		t.Error("expected jquery version from URL path")
	}
}

func TestLicenseCommentDetection(t *testing.T) {
	body := `/*!
	 * jQuery JavaScript Library v3.5.1
	 * https://jquery.com/
	 * Includes Sizzle.js
	 */
	` + "console.log('hello');"
	detected := analyzeBodySoftware(body)
	found := false
	for _, s := range detected {
		t.Logf("detected software: %+v", s)
		if strings.EqualFold(s.Name, "jquery") && s.Version == "3.5.1" {
			found = true
		}
	}
	if !found {
		t.Error("license comment pattern should detect jquery version 3.5.1")
	}
}

func TestBodyLibraryNamesNoVersion(t *testing.T) {
	body := `<script src="lib/jquery/jquery.min.js"></script>
<script src="lib/bootstrap/js/bootstrap.bundle.min.js"></script>
<script src="lib/easing/easing.min.js"></script>`
	detected := analyzeBodySoftware(body)
	libs := map[string]bool{}
	for _, s := range detected {
		if s.Source == "" {
			t.Errorf("entry %+v missing source", s)
		}
		libs[strings.ToLower(s.Name)] = true
	}
	for _, lib := range []string{"jquery", "bootstrap", "easing"} {
		if !libs[lib] {
			t.Errorf("expected library %s to be recorded even without version", lib)
		}
	}
}
