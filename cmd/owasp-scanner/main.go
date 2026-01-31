package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/BuildAndDestroy/owasp-scanner/pkg/config"
	"github.com/BuildAndDestroy/owasp-scanner/pkg/models"
	"github.com/BuildAndDestroy/owasp-scanner/pkg/report"
	"github.com/BuildAndDestroy/owasp-scanner/pkg/scanner"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

func main() {
	cfg := parseFlags()

	if cfg.ShowVersion {
		fmt.Printf("OWASP Scanner %s\n", Version)
		fmt.Printf("Build Time: %s\n", BuildTime)
		fmt.Printf("Git Commit: %s\n", GitCommit)
		os.Exit(0)
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		flag.Usage()
		os.Exit(1)
	}

	printBanner(cfg)

	// Create scanner
	s, err := scanner.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create scanner: %v\n", err)
		os.Exit(1)
	}

	// Run scan or crawl
	scanStart := time.Now()
	var results []models.ScanResult
	if cfg.CrawlOnly {
		results = s.CrawlOnly()
	} else {
		results = s.Scan()
	}
	scanEnd := time.Now()

	// Generate report
	rep := report.Generate(cfg.TargetURL, scanStart, scanEnd, results, len(s.Visited()), cfg.PayloadCount())

	// Output results
	if cfg.OutputJSON {
		if err := report.SaveJSON(rep); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving JSON report: %v\n", err)
			os.Exit(1)
		}
	} else {
		report.PrintConsole(rep)
	}
}

func parseFlags() *config.Config {
	cfg := &config.Config{}

	flag.StringVar(&cfg.TargetURL, "url", "", "Target URL to scan (required)")
	flag.StringVar(&cfg.OllamaURL, "ollama", "http://localhost:11434", "Ollama API URL")
	flag.StringVar(&cfg.OllamaModel, "model", "llama2", "Ollama model to use")
	flag.IntVar(&cfg.MaxDepth, "depth", 3, "Maximum crawl depth")
	flag.StringVar(&cfg.PayloadFile, "payloads", "", "Path to file containing payloads (one per line)")
	flag.BoolVar(&cfg.OutputJSON, "json", false, "Output results in JSON format with timestamped filename")
	flag.StringVar(&cfg.UserAgent, "user-agent", "OWASP-Scanner/1.0", "Custom User-Agent header")
	flag.BoolVar(&cfg.ShowVersion, "version", false, "Show version information")
	flag.DurationVar(&cfg.Timeout, "timeout", 30*time.Second, "HTTP request timeout")
	flag.BoolVar(&cfg.CrawlOnly, "crawl-only", false, "Only crawl the website and save URLs to JSON file (no OWASP scanning)")
	flag.IntVar(&cfg.Threads, "threads", 1, "Number of concurrent threads to use for scanning/crawling (default: 1)")

	flag.Parse()

	return cfg
}

func printBanner(cfg *config.Config) {
	if cfg.CrawlOnly {
		fmt.Printf("Starting website crawl for: %s\n", cfg.TargetURL)
		fmt.Printf("Crawl depth: %d, Threads: %d\n", cfg.MaxDepth, cfg.Threads)
	} else {
		fmt.Printf("Starting OWASP Top 10 security scan for: %s\n", cfg.TargetURL)
		fmt.Printf("Using Ollama at: %s with model: %s\n", cfg.OllamaURL, cfg.OllamaModel)
		if cfg.PayloadFile != "" {
			fmt.Printf("Loaded %d payloads from %s\n", cfg.PayloadCount(), cfg.PayloadFile)
		}
	}
	fmt.Println("----------------------------------------")
}
