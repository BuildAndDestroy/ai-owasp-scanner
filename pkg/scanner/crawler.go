package scanner

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/BuildAndDestroy/owasp-scanner/pkg/models"
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

// ExtractForms extracts all forms from HTML content
func (c *Crawler) ExtractForms(html string, pageURL *url.URL) []models.FormData {
	var forms []models.FormData

	// Find form opening tags
	formOpenRegex := regexp.MustCompile(`(?i)<form\s+[^>]*>`)
	formMatches := formOpenRegex.FindAllStringIndex(html, -1)

	if len(formMatches) == 0 {
		return forms
	}

	// For each form opening tag, find its closing tag
	for _, openMatch := range formMatches {
		formStart := openMatch[0]

		// Find corresponding closing tag
		closeTagIndex := strings.Index(html[formStart:], "</form>")
		if closeTagIndex == -1 {
			continue
		}

		formEnd := formStart + closeTagIndex + len("</form>")
		formHTML := html[formStart:formEnd]

		form := models.FormData{
			URL:    pageURL.String(),
			Method: "GET",
		}

		// Extract form method
		methodRegex := regexp.MustCompile(`(?i)method\s*=\s*["']?([^"'\s>]+)["']?`)
		if methodMatch := methodRegex.FindStringSubmatch(formHTML); len(methodMatch) > 1 {
			form.Method = strings.ToUpper(methodMatch[1])
		}

		// Extract form action
		actionRegex := regexp.MustCompile(`(?i)action\s*=\s*["']([^"']+)["']`)
		if actionMatch := actionRegex.FindStringSubmatch(formHTML); len(actionMatch) > 1 {
			action := actionMatch[1]
			form.Action = c.makeAbsoluteURL(action, pageURL)
		} else {
			// Check for empty action attribute (submits to same page)
			actionEmptyRegex := regexp.MustCompile(`(?i)action\s*=\s*["']["']`)
			if actionEmptyRegex.MatchString(formHTML) {
				form.Action = pageURL.String()
			}
		}

		// Extract form ID and name
		idRegex := regexp.MustCompile(`(?i)id\s*=\s*["']?([^"'\s>]+)["']?`)
		if idMatch := idRegex.FindStringSubmatch(formHTML); len(idMatch) > 1 {
			form.ID = idMatch[1]
		}

		nameRegex := regexp.MustCompile(`(?i)name\s*=\s*["']?([^"'\s>]+)["']?`)
		if nameMatch := nameRegex.FindStringSubmatch(formHTML); len(nameMatch) > 1 {
			form.Name = nameMatch[1]
		}

		// Extract all input, textarea, and select elements with names
		inputRegex := regexp.MustCompile(`(?i)<input[^>]+name\s*=\s*["']?([^"'\s>]+)["']?`)
		inputMatches := inputRegex.FindAllStringSubmatch(formHTML, -1)
		for _, inputMatch := range inputMatches {
			if len(inputMatch) > 1 {
				inputName := strings.TrimSpace(inputMatch[1])
				if inputName != "" && !contains(form.Inputs, inputName) {
					form.Inputs = append(form.Inputs, inputName)
				}
			}
		}

		// Look for textarea
		textareaRegex := regexp.MustCompile(`(?i)<textarea[^>]+name\s*=\s*["']?([^"'\s>]+)["']?`)
		textareaMatches := textareaRegex.FindAllStringSubmatch(formHTML, -1)
		for _, taMatch := range textareaMatches {
			if len(taMatch) > 1 {
				inputName := strings.TrimSpace(taMatch[1])
				if !contains(form.Inputs, inputName) {
					form.Inputs = append(form.Inputs, inputName)
				}
			}
		}

		// Look for select
		selectRegex := regexp.MustCompile(`(?i)<select[^>]+name\s*=\s*["']?([^"'\s>]+)["']?`)
		selectMatches := selectRegex.FindAllStringSubmatch(formHTML, -1)
		for _, selMatch := range selectMatches {
			if len(selMatch) > 1 {
				inputName := strings.TrimSpace(selMatch[1])
				if !contains(form.Inputs, inputName) {
					form.Inputs = append(form.Inputs, inputName)
				}
			}
		}

		if len(form.Inputs) > 0 {
			forms = append(forms, form)
		}
	}

	return forms
}

// Helper function to check if slice contains string
func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}
