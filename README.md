# AI OWASP Scanner

## Overview
The AI OWASP Scanner is a tool designed to automate the process of scanning applications for vulnerabilities using AI techniques. It aims to enhance the security of applications by identifying potential weaknesses before they can be exploited.

## Features
- **Automated Vulnerability Scanning**: Crawls websites and tests payloads against query parameters and form inputs
- **Software Enumeration**: When crawling or scanning, request headers and TLS/SSL metadata are recorded (server, frameworks, certificate info). The scanner also inspects HTML bodies for generator tags, JS/CSS library versions, CMS/framework indicators, and common platform strings, **and analyzes resource URLs (like `/js/jquery-3.3.1.min.js`) or directory paths (e.g. `lib/jquery/jquery.min.js`) to inventory libraries even when no version is specified**.
- **Crawl-Only Mode**: Option to crawl websites and collect URLs without performing vulnerability scanning
- **Multi-Threaded Processing**: Configurable thread count for parallel processing to speed up scans
- **Form Discovery & Testing**: Automatically discovers HTML forms and tests all input fields with POST requests
- **Parameter Tracking**: Tracks which parameters were tested and with which HTTP method (GET/POST)
- **Comprehensive Payloads**: Tests for SQL injection, XSS, path traversal, SSRF, and command injection vulnerabilities
- **JSON Reporting**: Generates detailed JSON reports with all findings, forms discovered, and payload test results
- **Multi-Platform Support**: Builds for Linux, macOS, and Windows on both amd64 and arm64 architectures
- **Docker Support**: Fully containerized with multi-stage builds for minimal image size
- **Unit Tests**: Comprehensive test suite with 30+ tests covering form discovery, POST testing, payload analysis, and new threading features

## Installation
To install the AI OWASP Scanner, clone the repository and build the Docker image:

```bash
git clone https://github.com/BuildAndDestroy/ai-owasp-scanner.git
cd ai-owasp-scanner
docker build -t ai-owasp-scanner .
```

## Usage

### Command Line Options
```
-url string          Target URL to scan (required)
-payloads string     Path to payload file (optional, uses built-in if not specified)
-json                Output results in JSON format
-depth int           Maximum crawl depth (default 3)
-timeout duration    Request timeout (default 30s)
-user-agent string   Custom user agent string
-crawl-only          Only crawl and collect URLs, skip vulnerability scanning
-threads int         Number of threads for parallel processing (default 4)
-version             Show version information
```

### Quick Start (Docker)
```bash
# Build the image
docker build -t owasp-scanner .

# Run a full vulnerability scan
docker run --rm \
  -v $(pwd)/payloads:/app/payloads \
  -v $(pwd)/reports:/app/reports \
  owasp-scanner \
  -url http://example.com \
  -payloads /app/payloads/sample-payloads.txt \
  -json

# Run crawl-only mode to collect URLs
docker run --rm \
  -v $(pwd)/reports:/app/reports \
  owasp-scanner \
  -url http://example.com \
  -crawl-only \
  -threads 8 \
  -json

# Run with custom threading for faster scanning
docker run --rm \
  -v $(pwd)/payloads:/app/payloads \
  -v $(pwd)/reports:/app/reports \
  owasp-scanner \
  -url http://example.com \
  -payloads /app/payloads/sample-payloads.txt \
  -threads 8 \
  -json
```

Reports are saved to `reports/` directory with timestamps.

> **Note:** output JSON now includes a `software` array for each page.  Each entry now includes a `source` field indicating where the software string was observed (header name, `url`, `body:script-src`, `tls`, etc.).
> Detected items come from headers, TLS info, HTML content analysis and even the request URL itself.  Example entry:
>
> ```json
> {
>   "url": "http://example.com/",
>   "software": [
>     {"name":"Server","version":"nginx","details":"nginx/1.18.0","source":"header:Server"},
>     {"name":"TLS","version":"TLS1.2","source":"tls"},
>     {"name":"Generator","details":"WordPress 5.8","source":"body:meta-generator"},
>     {"name":"Jquery","version":"3.6.0","source":"url"}
>   ],
>   ...
> }
> ```


### Build from Source
```bash
make build          # Build for current platform
make test           # Run test suite
make build-all      # Build for all platforms
```

## Supported Architectures
- **Linux**: amd64, arm64
- **macOS**: amd64 (Intel), arm64 (Apple Silicon)
- **Windows**: amd64, arm64

## Testing

Run the comprehensive test suite:
```bash
go test ./pkg/... -v          # Run all tests
go test ./pkg/... -v -cover   # Run with coverage
```

Test files:
- `pkg/scanner/scanner_test.go` - Threading, crawl-only, and software enumeration tests
- `pkg/scanner/crawler_test.go` - Form/link extraction tests
- `pkg/scanner/payload_test.go` - Payload injection and analysis tests
- `pkg/models/types_test.go` - Data structure validation tests
- `pkg/config/config_test.go` - Configuration validation tests

## Contributing
Contributions are welcome! Please submit a pull request or open an issue for any suggestions or improvements.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
