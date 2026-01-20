# Build Instructions for OWASP Scanner

## Quick Start

### Using Make (Recommended)

```bash
# Build for current platform
make build

# Build for all platforms
make build-all

# Run tests
make test

# Install to /usr/local/bin
make install
```

### Manual Build

```bash
# Build for current platform
go build -o owasp-scanner .

# Build for specific platform
GOOS=linux GOARCH=amd64 go build -o owasp-scanner-linux-amd64 .
GOOS=darwin GOARCH=arm64 go build -o owasp-scanner-darwin-arm64 .
GOOS=windows GOARCH=amd64 go build -o owasp-scanner-windows-amd64.exe .
```

## Supported Platforms

- **Linux**: amd64, arm64
- **macOS (Darwin)**: amd64 (Intel), arm64 (Apple Silicon)
- **Windows**: amd64, arm64

## Docker Build

### Build Docker Image

```bash
# Multi-platform build
make docker-build

# Local platform only
make docker-build-local

# Or using docker directly
docker build -t owasp-scanner:latest .
```

### Run with Docker

```bash
# Using make
make docker-run

# Or manually
docker run --rm -it \
  -v $(pwd)/payloads:/app/payloads \
  -v $(pwd)/reports:/app/reports \
  owasp-scanner:latest \
  -url https://example.com \
  -payloads /app/payloads/payloads.txt \
  -json
```

## GitHub Actions

The project includes automated CI/CD that:

- ✅ Builds binaries for all platforms on every push to `main`
- ✅ Builds binaries for all platforms on every pull request
- ✅ Runs tests and linting
- ✅ Builds Docker images for linux/amd64 and linux/arm64
- ❌ Does NOT store/upload binaries (build verification only)

### Workflow Files

- `.github/workflows/build.yml` - Main CI/CD workflow

## Usage Examples

### Basic Scan
```bash
./owasp-scanner -url https://example.com
```

### With Custom User Agent
```bash
./owasp-scanner \
  -url https://example.com \
  -user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

### Full Scan with Payloads and JSON Output
```bash
./owasp-scanner \
  -url https://example.com \
  -payloads payloads.txt \
  -json \
  -depth 5 \
  -model llama3.1 \
  -user-agent "CustomBot/1.0"
```

### Docker Usage
```bash
# Create payloads file
cat > payloads/test-payloads.txt <<EOF
' OR '1'='1
<script>alert('XSS')</script>
../../../etc/passwd
EOF

# Run scan
docker run --rm \
  -v $(pwd)/payloads:/app/payloads \
  -v $(pwd)/reports:/app/reports \
  owasp-scanner:latest \
  -url https://example.com \
  -payloads /app/payloads/test-payloads.txt \
  -json
```

## Development

### Prerequisites
- Go 1.21 or higher
- Make (optional, for using Makefile)
- Docker (optional, for containerized builds)

### Code Quality
```bash
# Format code
make fmt

# Run vet
make vet

# Run linter (requires golangci-lint)
make lint
```

## Creating Releases

```bash
# Build all platforms and create archives
make release

# Archives will be in build/releases/:
# - owasp-scanner-linux-amd64-1.0.0.tar.gz
# - owasp-scanner-darwin-arm64-1.0.0.tar.gz
# - owasp-scanner-windows-amd64-1.0.0.zip
# etc.
```

## Troubleshooting

### Build Fails on macOS
If you get CGO errors:
```bash
CGO_ENABLED=0 go build -o owasp-scanner .
```

### Docker Build Fails
Ensure Docker Buildx is enabled:
```bash
docker buildx create --use
```

### Cross-compilation Issues
Make sure you have Go 1.21+ which supports all target platforms:
```bash
go version
```

## File Structure

```
.
├── main.go                    # Main scanner code
├── go.mod                     # Go module definition
├── Dockerfile                 # Multi-platform Docker build
├── Makefile                   # Build automation
├── .github/
│   └── workflows/
│       └── build.yml         # GitHub Actions CI/CD
├── payloads/                 # Sample payload files
│   └── payloads.txt
└── reports/                  # Output directory for JSON reports
```

## Command-line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-url` | (required) | Target URL to scan |
| `-ollama` | `http://localhost:11434` | Ollama API URL |
| `-model` | `llama2` | Ollama model to use |
| `-depth` | `3` | Maximum crawl depth |
| `-payloads` | `""` | Path to payloads file |
| `-json` | `false` | Output JSON with timestamp |
| `-user-agent` | `OWASP-Scanner/1.0` | Custom User-Agent header |