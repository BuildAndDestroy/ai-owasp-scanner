package scanner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
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
