package scanner

import (
	"net/url"
	"testing"
)

func TestExtractLinks(t *testing.T) {
	crawler := NewCrawler()
	baseURL, _ := url.Parse("http://example.com/path/")

	tests := []struct {
		name     string
		html     string
		expected int
	}{
		{
			name:     "single absolute link",
			html:     `<a href="http://example.com/page">Link</a>`,
			expected: 1,
		},
		{
			name:     "single relative link",
			html:     `<a href="/other">Link</a>`,
			expected: 1,
		},
		{
			name:     "multiple links",
			html:     `<a href="/page1">L1</a><a href="/page2">L2</a>`,
			expected: 2,
		},
		{
			name:     "javascript link ignored",
			html:     `<a href="javascript:void(0)">Link</a>`,
			expected: 0,
		},
		{
			name:     "mailto link ignored",
			html:     `<a href="mailto:test@example.com">Link</a>`,
			expected: 0,
		},
		{
			name:     "anchor link ignored",
			html:     `<a href="#section">Link</a>`,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			links := crawler.ExtractLinks(tt.html, baseURL)
			if len(links) != tt.expected {
				t.Errorf("got %d links, expected %d", len(links), tt.expected)
			}
		})
	}
}

func TestExtractForms(t *testing.T) {
	crawler := NewCrawler()
	baseURL, _ := url.Parse("http://example.com/")

	tests := []struct {
		name           string
		html           string
		expectedCount  int
		expectedMethod string
		expectedInputs int
	}{
		{
			name: "simple form",
			html: `<form method="post" action="/submit">
				<input type="text" name="username" />
				<input type="password" name="password" />
			</form>`,
			expectedCount:  1,
			expectedMethod: "POST",
			expectedInputs: 2,
		},
		{
			name: "form with GET method",
			html: `<form method="get" action="/search">
				<input type="text" name="q" />
			</form>`,
			expectedCount:  1,
			expectedMethod: "GET",
			expectedInputs: 1,
		},
		{
			name: "form with textarea",
			html: `<form method="post">
				<textarea name="message"></textarea>
				<input type="text" name="email" />
			</form>`,
			expectedCount:  1,
			expectedMethod: "POST",
			expectedInputs: 2,
		},
		{
			name: "form with select",
			html: `<form method="post">
				<select name="country">
					<option>USA</option>
				</select>
				<input type="text" name="name" />
			</form>`,
			expectedCount:  1,
			expectedMethod: "POST",
			expectedInputs: 2,
		},
		{
			name:           "no forms",
			html:           `<div>No forms here</div>`,
			expectedCount:  0,
			expectedMethod: "",
			expectedInputs: 0,
		},
		{
			name: "multiple forms",
			html: `<form method="post"><input name="a" /></form>
				<form method="get"><input name="b" /></form>`,
			expectedCount:  2,
			expectedMethod: "",
			expectedInputs: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			forms := crawler.ExtractForms(tt.html, baseURL)
			if len(forms) != tt.expectedCount {
				t.Errorf("got %d forms, expected %d", len(forms), tt.expectedCount)
			}

			// Only check method/inputs if we specified expectations and have forms
			if tt.expectedMethod != "" && tt.expectedCount > 0 && len(forms) > 0 {
				if forms[0].Method != tt.expectedMethod {
					t.Errorf("got method %s, expected %s", forms[0].Method, tt.expectedMethod)
				}
				if len(forms[0].Inputs) != tt.expectedInputs {
					t.Errorf("got %d inputs, expected %d", len(forms[0].Inputs), tt.expectedInputs)
				}
			}
		})
	}
}

func TestMakeAbsoluteURL(t *testing.T) {
	crawler := NewCrawler()
	baseURL, _ := url.Parse("http://example.com/path/page.html")

	tests := []struct {
		name     string
		link     string
		expected string
	}{
		{
			name:     "absolute URL",
			link:     "http://other.com/page",
			expected: "http://other.com/page",
		},
		{
			name:     "root path",
			link:     "/root",
			expected: "http://example.com/root",
		},
		{
			name:     "relative path",
			link:     "page2.html",
			expected: "http://example.com/path/page2.html",
		},
		{
			name:     "parent directory",
			link:     "../other.html",
			expected: "http://example.com/path/../other.html",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := crawler.makeAbsoluteURL(tt.link, baseURL)
			if result != tt.expected {
				t.Errorf("got %s, expected %s", result, tt.expected)
			}
		})
	}
}

func TestFormDataStructure(t *testing.T) {
	crawler := NewCrawler()
	baseURL, _ := url.Parse("http://example.com/contact")

	html := `<form id="contactForm" name="contact" method="post" action="/submit">
		<input type="text" name="name" required />
		<input type="email" name="email" />
		<textarea name="message"></textarea>
		<button type="submit">Send</button>
	</form>`

	forms := crawler.ExtractForms(html, baseURL)

	if len(forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(forms))
	}

	form := forms[0]

	if form.ID != "contactForm" {
		t.Errorf("form ID: got %s, expected contactForm", form.ID)
	}

	if form.Name != "contact" {
		t.Errorf("form name: got %s, expected contact", form.Name)
	}

	if form.Method != "POST" {
		t.Errorf("form method: got %s, expected POST", form.Method)
	}

	if form.Action != "http://example.com/submit" {
		t.Errorf("form action: got %s, expected http://example.com/submit", form.Action)
	}

	expectedInputs := []string{"name", "email", "message"}
	for _, input := range expectedInputs {
		if !contains(form.Inputs, input) {
			t.Errorf("expected input %s not found", input)
		}
	}
}
