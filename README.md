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
- **Report dashboard**: Web UI that ingests `scan_report_*.json` files into MongoDB and visualizes detected technologies (headers, TLS, HTML, URL hints) with charts and tables. Ships with Docker, Docker Compose, and Kubernetes manifests.

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
-threads int         Number of threads for parallel processing (default 1)
-socks5-proxy string SOCKS5 proxy in host:port format (e.g. 127.0.0.1:9050)
-test-socks5-proxy   Test SOCKS5 proxy connectivity against -url and exit
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

# Validate that SOCKS5 proxy routing works
docker run --rm \
  owasp-scanner \
  -url http://example.com \
  -socks5-proxy 127.0.0.1:9050 \
  -test-socks5-proxy
```

Reports are saved to `reports/` directory with timestamps.

## Scan report dashboard (MongoDB)

The dashboard stores full scan report JSON in MongoDB and aggregates `software` entries per page into charts and a sortable table.

### Run locally

Requires MongoDB listening on `127.0.0.1:27017`, or set **`MONGO_ROOT_USERNAME`** / **`MONGO_ROOT_PASSWORD`** (and optional **`MONGO_HOST`**, default `127.0.0.1:27017`) so the dashboard builds a URI with `authSource=admin`. You can still set a full **`MONGODB_URI`** to override.

```bash
go run ./cmd/dashboard -listen :8080
```

Open http://127.0.0.1:8080 and upload a file matching `reports/scan_report_*.json`, or POST JSON:

```bash
curl -sS -X POST http://127.0.0.1:8080/api/reports \
  -H 'Content-Type: application/json' \
  --data-binary @reports/scan_report_2026-04-07_15-34-29.json
```

API:

- `GET /health` — liveness
- `GET /api/reports` — list stored reports (id, target URL, created time)
- `POST /api/reports` — body = full scan report JSON
- `GET /api/reports/{id}` — raw report JSON
- `GET /api/reports/{id}/technologies` — summary + aggregated technologies

Environment variables: **`MONGODB_DATABASE`** (default `owasp_dashboard`). Connection string: optional **`MONGODB_URI`**; if unset, the binary builds one from **`MONGO_ROOT_USERNAME`**, **`MONGO_ROOT_PASSWORD`**, and **`MONGO_HOST`** (default `127.0.0.1:27017`) using `net/url` so special characters in passwords are encoded. If neither `MONGODB_URI` nor both root vars are set, it falls back to `mongodb://127.0.0.1:27017`.

Optional: create a `.env` file next to the binary (see `.env.example`). Values are loaded automatically via `godotenv` when you run the dashboard locally.

### Docker

```bash
docker build -f Dockerfile.dashboard -t owasp-dashboard:latest .
docker run --rm -p 8080:8080 \
  -e MONGODB_URI='mongodb://user:pass@host.docker.internal:27017/?authSource=admin' \
  owasp-dashboard:latest
```

On Linux, add `--add-host=host.docker.internal:host-gateway` if needed so the container can reach MongoDB on the host.

### Docker Compose (MongoDB + dashboard)

MongoDB is configured with **authentication** (root user). Copy `.env.example` to `.env` and set **`MONGO_ROOT_USERNAME`** and **`MONGO_ROOT_PASSWORD`**. Compose builds **`MONGODB_URI`** for the dashboard as `mongodb://USER:PASS@mongo:27017/?authSource=admin` (you do not put `$VAR` placeholders inside `MONGODB_URI` in `.env`). If you need a hand-crafted URI (e.g. password characters that confuse Compose), set **`MONGODB_URI`** in `.env` explicitly; it overrides the default.

```bash
cp .env.example .env
# edit .env — set MONGO_ROOT_USERNAME and MONGO_ROOT_PASSWORD
docker compose -f docker-compose.dashboard.yml up --build
```

If you previously ran this stack **without** auth, drop the old volume so MongoDB can re-initialize with credentials: `docker compose -f docker-compose.dashboard.yml down -v`.

Then open http://127.0.0.1:8080 (MongoDB is exposed on `27017` for debugging).

### Kubernetes

Edit `k8s/mongodb-secret.yaml` (or create your own Secret) with `MONGO_INITDB_ROOT_USERNAME`, `MONGO_INITDB_ROOT_PASSWORD`, and a matching `MONGODB_URI` for the dashboard. Build and load the image into your cluster (name must match the manifest or retag):

```bash
docker build -f Dockerfile.dashboard -t owasp-dashboard:latest .
kind load docker-image owasp-dashboard:latest   # example for kind
kubectl apply -f k8s/mongodb-secret.yaml
kubectl apply -f k8s/dashboard-mongodb.yaml
kubectl port-forward svc/owasp-dashboard 8080:8080
```

The sample manifest uses `emptyDir` for MongoDB data for simplicity; swap in a persistent volume for production.

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
