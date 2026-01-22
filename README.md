# AI OWASP Scanner

## Overview
The AI OWASP Scanner is a tool designed to automate the process of scanning applications for vulnerabilities using AI techniques. It aims to enhance the security of applications by identifying potential weaknesses before they can be exploited.

## Features
- **Automated Vulnerability Scanning**: Crawls websites and tests payloads against query parameters and form inputs
- **Form Discovery & Testing**: Automatically discovers HTML forms and tests all input fields with POST requests
- **Parameter Tracking**: Tracks which parameters were tested and with which HTTP method (GET/POST)
- **Comprehensive Payloads**: Tests for SQL injection, XSS, path traversal, SSRF, and command injection vulnerabilities
- **JSON Reporting**: Generates detailed JSON reports with all findings, forms discovered, and payload test results
- **Multi-Platform Support**: Builds for Linux, macOS, and Windows on both amd64 and arm64 architectures
- **Docker Support**: Fully containerized with multi-stage builds for minimal image size
- **Unit Tests**: Comprehensive test suite with 27+ tests covering form discovery, POST testing, and payload analysis

## Installation
To install the AI OWASP Scanner, clone the repository and build the Docker image:

```bash
git clone https://github.com/BuildAndDestroy/ai-owasp-scanner.git
cd ai-owasp-scanner
docker build -t ai-owasp-scanner .
```

## Usage

### Quick Start (Docker)
```bash
# Build the image
docker build -t owasp-scanner .

# Run a scan
docker run --rm \
  -v $(pwd)/payloads:/app/payloads \
  -v $(pwd)/reports:/app/reports \
  owasp-scanner \
  -url http://example.com \
  -payloads /app/payloads/sample-payloads.txt \
  -json
```

Reports are saved to `reports/` directory with timestamps.

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
- `pkg/scanner/crawler_test.go` - Form/link extraction tests
- `pkg/scanner/payload_test.go` - Payload injection and analysis tests
- `pkg/models/types_test.go` - Data structure validation tests
- `pkg/config/config_test.go` - Configuration validation tests

## Contributing
Contributions are welcome! Please submit a pull request or open an issue for any suggestions or improvements.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
