package scanner

import (
	"net/url"
	"regexp"
	"strings"
)

// Crawler handles extracting and normalizing URLs from HTML
type Crawler struct {
	linkRegex *regexp.Regexp
}

// NewCrawler creates a new Crawler instance
func NewCrawler() *Crawler {
	return &Crawler{
		linkRegex: regexp.MustCompile(`href=["']([^"']+)["']`),
	}
}

// ExtractLinks extracts all links from HTML content
func (c *Crawler) ExtractLinks(html string, baseURL *url.URL) []string {
	var links []string
	matches := c.linkRegex.FindAllStringSubmatch(html, -1)

	for _, match := range matches {
		if len(match) > 1 {
			link := match[1]
			absoluteURL := c.makeAbsoluteURL(link, baseURL)
			if absoluteURL != "" {
				links = append(links, absoluteURL)
			}
		}
	}

	return links
}

// makeAbsoluteURL converts a relative URL to absolute
func (c *Crawler) makeAbsoluteURL(link string, baseURL *url.URL) string {
	// Already absolute
	if strings.HasPrefix(link, "http://") || strings.HasPrefix(link, "https://") {
		return link
	}

	// Protocol-relative
	if strings.HasPrefix(link, "//") {
		return baseURL.Scheme + ":" + link
	}

	// Absolute path
	if strings.HasPrefix(link, "/") {
		return baseURL.Scheme + "://" + baseURL.Host + link
	}

	// Skip special protocols
	if strings.HasPrefix(link, "#") ||
		strings.HasPrefix(link, "javascript:") ||
		strings.HasPrefix(link, "mailto:") {
		return ""
	}

	// Relative path
	basePath := baseURL.Path
	if !strings.HasSuffix(basePath, "/") {
		lastSlash := strings.LastIndex(basePath, "/")
		if lastSlash != -1 {
			basePath = basePath[:lastSlash+1]
		}
	}

	return baseURL.Scheme + "://" + baseURL.Host + basePath + link
}
