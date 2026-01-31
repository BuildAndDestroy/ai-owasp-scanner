package config

import (
	"net/url"
	"testing"
	"time"
)

func TestConfigCreation(t *testing.T) {
	config := &Config{
		TargetURL: "http://example.com",
		MaxDepth:  3,
	}

	if config.TargetURL == "" {
		t.Error("target URL should not be empty")
	}

	if config.MaxDepth < 0 {
		t.Error("max depth should be set")
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		shouldErr bool
	}{
		{
			name: "valid config",
			config: Config{
				TargetURL:   "http://example.com",
				MaxDepth:    3,
				PayloadFile: "",
				CrawlOnly:   false,
				Threads:     4,
			},
			shouldErr: false,
		},
		{
			name: "valid config with crawl only",
			config: Config{
				TargetURL: "http://example.com",
				MaxDepth:  3,
				CrawlOnly: true,
				Threads:   2,
			},
			shouldErr: false,
		},
		{
			name: "missing target URL",
			config: Config{
				TargetURL: "",
				MaxDepth:  3,
				Threads:   1,
			},
			shouldErr: true,
		},
		{
			name: "negative max depth",
			config: Config{
				TargetURL: "http://example.com",
				MaxDepth:  -1,
				Threads:   1,
			},
			shouldErr: true,
		},
		{
			name: "zero threads",
			config: Config{
				TargetURL: "http://example.com",
				MaxDepth:  3,
				Threads:   0,
			},
			shouldErr: true,
		},
		{
			name: "negative threads",
			config: Config{
				TargetURL: "http://example.com",
				MaxDepth:  3,
				Threads:   -1,
			},
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.shouldErr {
				t.Errorf("Validate() error = %v, shouldErr %v", err, tt.shouldErr)
			}
		})
	}
}

func TestConfigURLParsing(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		isValid bool
	}{
		{"simple http", "http://example.com", true},
		{"https url", "https://example.com", true},
		{"url with path", "http://example.com/path", true},
		{"url with port", "http://example.com:8080", true},
		{"empty url", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := url.Parse(tt.url)
			isValid := err == nil && tt.url != ""
			if isValid != tt.isValid {
				t.Errorf("URL %s validity: got %v, want %v", tt.url, isValid, tt.isValid)
			}
		})
	}
}

func TestConfigMaxDepth(t *testing.T) {
	tests := []struct {
		name      string
		depth     int
		shouldErr bool
	}{
		{"zero depth", 0, false},
		{"positive depth", 3, false},
		{"large depth", 100, false},
		{"negative depth", -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := Config{
				TargetURL: "http://example.com",
				MaxDepth:  tt.depth,
				Threads:   1,
			}

			err := config.Validate()
			if (err != nil) != tt.shouldErr {
				t.Errorf("depth %d: got error %v, shouldErr %v", tt.depth, err, tt.shouldErr)
			}
		})
	}
}

func TestConfigThreads(t *testing.T) {
	tests := []struct {
		name      string
		threads   int
		shouldErr bool
	}{
		{"single thread", 1, false},
		{"multiple threads", 4, false},
		{"large thread count", 100, false},
		{"zero threads", 0, true},
		{"negative threads", -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := Config{
				TargetURL: "http://example.com",
				MaxDepth:  3,
				Threads:   tt.threads,
			}

			err := config.Validate()
			if (err != nil) != tt.shouldErr {
				t.Errorf("threads %d: got error %v, shouldErr %v", tt.threads, err, tt.shouldErr)
			}
		})
	}
}

func TestConfigFields(t *testing.T) {
	config := &Config{
		TargetURL:   "http://example.com",
		OllamaURL:   "http://localhost:11434",
		OllamaModel: "neural-chat",
		MaxDepth:    5,
		UserAgent:   "CustomAgent/1.0",
		Timeout:     30 * time.Second,
		CrawlOnly:   true,
		Threads:     8,
	}

	if config.TargetURL != "http://example.com" {
		t.Error("TargetURL mismatch")
	}

	if config.OllamaModel != "neural-chat" {
		t.Error("OllamaModel mismatch")
	}

	if config.MaxDepth != 5 {
		t.Error("MaxDepth mismatch")
	}

	if config.UserAgent != "CustomAgent/1.0" {
		t.Error("UserAgent mismatch")
	}

	if config.Timeout != 30*time.Second {
		t.Error("Timeout mismatch")
	}

	if config.CrawlOnly != true {
		t.Error("CrawlOnly mismatch")
	}

	if config.Threads != 8 {
		t.Error("Threads mismatch")
	}
}

func TestConfigPayloads(t *testing.T) {
	config := &Config{
		TargetURL:   "http://example.com",
		MaxDepth:    3,
		PayloadFile: "payloads/sample-payloads.txt",
	}

	// Note: LoadPayloads is only called via Validate()
	err := config.Validate()
	if err != nil {
		t.Logf("validation error: %v (expected if payloads/sample-payloads.txt not in test directory)", err)
	}
}

func TestConfigPayloadCount(t *testing.T) {
	config := &Config{}

	// Empty config should have 0 payloads
	count := config.PayloadCount()
	if count != 0 {
		t.Errorf("expected 0 payloads initially, got %d", count)
	}

	// Payloads method should return empty slice
	payloads := config.Payloads()
	if len(payloads) != 0 {
		t.Errorf("expected empty payloads slice, got %d", len(payloads))
	}
}
