package config

import (
	"errors"
	"net/url"
	"os"
	"strings"
	"time"
)

// Config holds all configuration for the scanner
type Config struct {
	TargetURL   string
	OllamaURL   string
	OllamaModel string
	MaxDepth    int
	PayloadFile string
	OutputJSON  bool
	UserAgent   string
	ShowVersion bool
	Timeout     time.Duration

	payloads []string
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.TargetURL == "" {
		return errors.New("target URL is required")
	}

	if _, err := url.Parse(c.TargetURL); err != nil {
		return errors.New("invalid target URL")
	}

	if c.MaxDepth < 0 {
		return errors.New("max depth must be >= 0")
	}

	if c.PayloadFile != "" {
		if err := c.loadPayloads(); err != nil {
			return err
		}
	}

	return nil
}

// Payloads returns the loaded payloads
func (c *Config) Payloads() []string {
	return c.payloads
}

// PayloadCount returns the number of loaded payloads
func (c *Config) PayloadCount() int {
	return len(c.payloads)
}

// loadPayloads reads payloads from the configured file
func (c *Config) loadPayloads() error {
	data, err := os.ReadFile(c.PayloadFile)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	c.payloads = make([]string, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			c.payloads = append(c.payloads, line)
		}
	}

	return nil
}
